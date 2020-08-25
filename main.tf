resource "aws_s3_bucket" "bucket" {
  bucket = var.bucket_name
  acl    = "bucket-owner-full-control"

  force_destroy = var.bucket_force_destroy

  versioning {
    enabled = var.bucket_versioning
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm     = "AES256"
      }
    }
  }

  lifecycle_rule {
    id      = "log"
    enabled = var.log_auto_clean

    prefix = "logs/"

    tags = {
      "rule"      = "log"
      "autoclean" = var.log_auto_clean
    }

    transition {
      days          = var.log_standard_ia_days
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = var.log_glacier_days
      storage_class = "GLACIER"
    }

    expiration {
      days = var.log_expiry_days
    }
  }

  tags = merge(var.tags)
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket = aws_s3_bucket.bucket.id

  block_public_acls   = true
  block_public_policy = true
  ignore_public_acls  = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object" "bucket_public_keys_readme" {
  bucket  = aws_s3_bucket.bucket.id
  key     = "public-keys/README.txt"
  content = "Drop here the ssh public keys of the instances you want to control"
}

resource "aws_security_group" "bastion_host_security_group" {
  description = "Enable SSH access to the bastion host from external via SSH port"
  name_prefix = var.resource_name_prefix
  vpc_id      = var.vpc_id

  tags = merge(var.tags)
}

resource "aws_security_group_rule" "ingress_bastion" {
  description = "Incoming traffic to bastion"
  type        = "ingress"
  from_port   = var.public_ssh_port
  to_port     = var.public_ssh_port
  protocol    = "TCP"
  cidr_blocks = concat(data.aws_subnet.subnets.*.cidr_block, var.cidrs)

  security_group_id = aws_security_group.bastion_host_security_group.id
}

resource "aws_security_group_rule" "egress_bastion" {
  description = "Outgoing traffic from bastion to instances"
  count       = var.bastion_open_egress == true ? 1 : 0
  type        = "egress"
  from_port   = "0"
  to_port     = "65535"
  protocol    = "-1"
  cidr_blocks = ["0.0.0.0/0"]

  security_group_id = aws_security_group.bastion_host_security_group.id
}

resource "aws_security_group" "private_instances_security_group" {
  description = "Enable SSH access to the Private instances from the bastion via SSH port"
  name_prefix = "${var.resource_name_prefix}private-instances"
  vpc_id      = var.vpc_id

  tags = merge(var.tags)
}

resource "aws_security_group_rule" "ingress_instances" {
  description = "Incoming traffic from bastion"
  type        = "ingress"
  from_port   = var.public_ssh_port
  to_port     = var.public_ssh_port
  protocol    = "TCP"

  source_security_group_id = aws_security_group.bastion_host_security_group.id

  security_group_id = aws_security_group.private_instances_security_group.id
}

resource "aws_iam_role" "bastion_host_role" {
  path = "/"
  name_prefix = var.resource_name_prefix

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": [
          "ec2.amazonaws.com"
        ]
      },
      "Action": [
        "sts:AssumeRole"
      ]
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "bastion_host_role_policy" {
  role = aws_iam_role.bastion_host_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:PutObjectAcl"
      ],
      "Resource": "arn:aws:s3:::${var.bucket_name}/logs/*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::${var.bucket_name}/public-keys/*"
    },
    {
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::${var.bucket_name}",
      "Condition": {
        "StringEquals": {
          "s3:prefix": "public-keys/"
        }
      }
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "read_onelogin_keys" {
  role = aws_iam_role.bastion_host_role.id

  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ssm:DescribeParameters"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ssm:GetParameter"
            ],
            "Resource": "arn:aws:ssm:${var.region}:*:parameter/bastion/*"
        }
    ]
}
EOF
}

resource "aws_route53_record" "bastion_record_name" {
  name    = var.bastion_record_name
  zone_id = var.hosted_zone_name != "" ? var.hosted_zone_name : "empty"
  type    = "A"
  count   = var.create_dns_record == true ? 1 : 0

  alias {
    evaluate_target_health = true
    name                   = aws_lb.bastion_lb.dns_name
    zone_id                = aws_lb.bastion_lb.zone_id
  }
}

resource "aws_lb" "bastion_lb" {
  internal = var.is_lb_private
  name_prefix     = substr(var.resource_name_prefix, 0, 6)

  subnets = var.elb_subnets

  load_balancer_type = "network"
  tags               = merge(var.tags)
}

resource "aws_lb_target_group" "bastion_lb_target_group" {
  port        = var.public_ssh_port
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  target_type = "instance"
  deregistration_delay = 120

  health_check {
    port     = "traffic-port"
    protocol = "TCP"
  }

  tags = merge(var.tags)
}

resource "aws_lb_listener" "bastion_lb_listener_22" {
  default_action {
    target_group_arn = aws_lb_target_group.bastion_lb_target_group.arn
    type             = "forward"
  }

  load_balancer_arn = aws_lb.bastion_lb.arn
  port              = var.public_ssh_port
  protocol          = "TCP"
}

resource "aws_lb" "share_keys_web_server_lb" {
  count = var.share_keys_web_server == true ? 1 : 0
  internal = true
  name = "${var.resource_name_prefix}authorized-keys"
  subnets = var.share_keys_elb_subnets
  load_balancer_type = "network"
}

resource "aws_lb_target_group" "share_keys_web_server_lb_target_group" {
  port        = 443
  protocol    = "TCP"
  vpc_id      = var.vpc_id
  deregistration_delay = 120
  tags = merge(var.tags)
  stickiness {
    type = "lb_cookie"
    enabled = false
  }
}

resource "aws_lb_listener" "share_keys_web_server_lb_listener" {
  count = var.share_keys_web_server == true ? 1 : 0
  default_action {
    target_group_arn = aws_lb_target_group.share_keys_web_server_lb_target_group.arn
    type             = "forward"
  }

  load_balancer_arn = aws_lb.share_keys_web_server_lb[0].arn
  port              = "443"
  protocol          = "TCP"
}

resource "aws_security_group_rule" "ingress_share_keys_web_server_cidrs" {
  count = length(var.share_keys_allowed_cidrs)
  description = "Incoming traffic to share keys"
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "TCP"
  cidr_blocks = [var.share_keys_allowed_cidrs[count.index]]
  security_group_id = aws_security_group.bastion_host_security_group.id
}

resource "aws_security_group_rule" "ingress_share_keys_web_server_sec_groups" {
  count = length(var.share_keys_allowed_sec_groups)
  description = "Incoming traffic to share keys"
  type        = "ingress"
  from_port   = 443
  to_port     = 443
  protocol    = "TCP"
  source_security_group_id = var.share_keys_allowed_sec_groups[count.index]
  security_group_id = aws_security_group.bastion_host_security_group
}

resource "aws_iam_instance_profile" "bastion_host_profile" {
  role = aws_iam_role.bastion_host_role.name
  path = "/"
  name_prefix = var.resource_name_prefix
}

resource "aws_launch_configuration" "bastion_launch_configuration" {
  name_prefix                 = var.resource_name_prefix
  image_id                    = var.bastion_ami_id == "" ? data.aws_ami.amazon-linux-2.id : var.bastion_ami_id
  instance_type               = "t2.nano"
  associate_public_ip_address = var.associate_public_ip_address
  enable_monitoring           = true
  iam_instance_profile        = aws_iam_instance_profile.bastion_host_profile.name
  key_name                    = var.bastion_host_key_pair

  security_groups = [
    aws_security_group.bastion_host_security_group.id,
  ]

  user_data = templatefile("${path.module}/user_data.sh", {
    static_ssh_users = var.static_ssh_users,
    aws_region  = var.region
    bucket_name = var.bucket_name
    ssh_tunnel_only_users = var.ssh_tunnel_only_users
    onelogin_sync = var.onelogin_sync
    onelogin_sync_role_ids = var.onelogin_sync_role_ids
    onelogin_sync_script = file("${path.module}/onelogin_sync/onelogin_sync.py")
    onelogin_sync_requirements = file("${path.module}/onelogin_sync/requirements.txt")
    share_keys_web_server = var.share_keys_web_server
  })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_autoscaling_group" "bastion_auto_scaling_group" {
  name                 = "ASG-${aws_launch_configuration.bastion_launch_configuration.name}"
  launch_configuration = aws_launch_configuration.bastion_launch_configuration.name
  max_size             = var.bastion_instance_count
  min_size             = var.bastion_instance_count
  desired_capacity     = var.bastion_instance_count

  vpc_zone_identifier = var.auto_scaling_group_subnets

  default_cooldown          = 180
  health_check_grace_period = 180
  health_check_type         = "EC2"

  target_group_arns = [
    aws_lb_target_group.bastion_lb_target_group.arn,
    aws_lb_target_group.share_keys_web_server_lb_target_group.arn
  ]

  termination_policies = [
    "OldestLaunchConfiguration",
  ]

  tag {
    key = "Name"
    value = "ASG-${aws_launch_configuration.bastion_launch_configuration.name}"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}
