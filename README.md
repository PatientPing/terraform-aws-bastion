AWS Bastion Terraform module
===========================================

[![Open Source Helpers](https://www.codetriage.com/guimove/terraform-aws-bastion/badges/users.svg)](https://www.codetriage.com/guimove/terraform-aws-bastion)

Terraform module which creates a secure SSH bastion on AWS.

Mainly inspired by [Securely Connect to Linux Instances Running in a Private Amazon VPC](https://aws.amazon.com/blogs/security/securely-connect-to-linux-instances-running-in-a-private-amazon-vpc/)

Features
--------

This module will create an SSH bastion to securely connect in SSH  to your private instances.
![Bastion Infrastrucutre](https://raw.githubusercontent.com/Guimove/terraform-aws-bastion/master/_docs/terraformawsbastion.png)
All SSH  commands are logged on an S3 bucket for security compliance, in the /logs path.

SSH  users are managed by their public key, simply drop the SSH key of the user in  the /public-keys path of the bucket.
Keys should be named like 'username.pub', this will create the user 'username' on the bastion server.

Then after you'll be able to connect to the server with : 

```
ssh [-i path_to_the_private_key] username@bastion-dns-name
```

From this bastion server, you'll able to connect to all instances on the private subnet. 

If there is a missing feature or a bug - [open an issue](https://github.com/Guimove/terraform-aws-bastion/issues/new).

Usage
-----

```hcl
module "bastion" {
  "source" = "terraform-aws-modules/bastion/aws"
  "bucket_name" = "my_famous_bucket_name"
  "region" = "eu-west-1"
  "vpc_id" = "my_vpc_id"
  "is_lb_private" = "true|false"
  "bastion_host_key_pair" = "my_key_pair"
  "hosted_zone_name" = "my.hosted.zone.name."
  "bastion_record_name" = "bastion.my.hosted.zone.name."
  "elb_subnets" = [
    "subnet-id1a",
    "subnet-id1b"
  ]
  "auto_scaling_group_subnets" = [
    "subnet-id1a",
    "subnet-id1b"
  ]
  tags = {
    "name" = "my_bastion_name",
    "description" = "my_bastion_description"
  }
}
```
## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|:----:|:-----:|:-----:|
| auto_scaling_group_subnets | List of subnet were the Auto Scalling Group will deploy the instances | list | - | yes |
| bastion_ami_id | Machine Image ID of bastion instances | string | `` | no |
| bastion_host_key_pair | Select the key pair to use to launch the bastion host | string | - | yes |
| bastion_instance_count | Count of bastion instance created on VPC | string | `1` | no |
| bastion_open_egress | Allow open egress from bastion hosts | bool | true | no |
| bastion_record_name | DNS record name to use for the bastion | string | `` | no |
| bucket_name | Bucket name were the bastion will store the logs | string | - | yes |
| bucket_force_destroy | On destroy, bucket and all objects should be destroyed when using true | string | false | no |
| bucket_versioning | Enable bucket versioning or not | string | true | no |
| cidrs | List of CIDRs than can access to the bastion. Default : 0.0.0.0/0 | list | `<list>` | no |
| create_dns_record | Choose if you want to create a record name for the bastion (LB). If true 'hosted_zone_name' and 'bastion_record_name' are mandatory | bool | - | yes |
| elb_subnets | List of subnet were the ELB will be deployed | list | - | yes |
| hosted_zone_name | Name of the hosted zone were we'll register the bastion DNS name | string | `` | no |
| is_lb_private | If TRUE the load balancer scheme will be "internal" else "internet-facing" | string | - | yes |
| log_auto_clean | Enable or not the lifecycle | string | `false` | no |
| log_expiry_days | Number of days before logs expiration | string | `90` | no |
| log_glacier_days | Number of days before moving logs to Glacier | string | `60` | no |
| log_standard_ia_days | Number of days before moving logs to IA Storage | string | `30` | no |
| onelogin_sync | Enable syncing of ssh keys from OneLogin | bool | false | no |
| onelogin_sync_role_ids | When using OneLogin sync, optionally limit to a list of role IDs.  If empty, all active users will be synced. | list(int) | [] | no |
| private_ssh_port | Set the SSH port to use between the bastion and private instance | string | `22` | no |
| public_ssh_port | Set the SSH port to use from desktop to the bastion | string | `22` | no |
| region |  | string | - | yes |
| resource_name_prefix | Prefix for AWS resource names including LC/ASG/SGs | string | `bastion-` | no |
| share_keys_web_server | make public keys available through a web server on the bastion | bool | false | no |
| share_keys_elb_subnets | ELB subnet IDs for sharing keys | list(string) | [] | no |
| share_keys_allowed_cidrs | CIDRs allowed to get shared public keys | list(string) | [] | no |
| share_keys_allowed_sec_groups | SecGroups allowed to get shared public keys over https | list(string) | [] | no |
| ssh_tunnel_only_users | comma separated list of users who can use the bastion only for port-forwarding | string | `nobody` | no |
| static_ssh_users | ssh users that we want to create statically in userdata rather than use s3 sync e.g. [ {name = "someone", public_key "id_rsa..." }]  | list(map) | [] no |
| tags | A mapping of tags to assign | map | `<map>` | no |
| vpc_id | VPC id were we'll deploy the bastion | string | - | yes |

## Outputs

| Name | Description |
|------|-------------|
| bucket_name |  |
| elb_ip |  |

## OneLogin Sync

Syncing users from OneLogin supported with onelogin_sync=true with the following requirements:
1.  SSH Keys stored in a user custom attribute called 'sshPublickey'.
2.  OneLogin credentials with Read perms stored in SSM Parameter Store parameters /bastion/onelogin_id and /bastion/onelogin_secret.

You can optionally limit syncing to users that have a role matching one or more role IDs.

## Sharing SSH Public Keys

Once a user is SSHed to the bastion, they may want to ssh to a next-hop/target instance.  This option allows those
other instances to use the same keys that are in use on the bastion by sharing those keys via HTTPS.

Notes: 
1.  Key sharing currently only supports HTTPS using a self-signed key.
2.  All keys for all bastion users are shared in one concatenated response.  So this is appropriate for next-hop/targets
with a shared user account (e.g. "ec2-user" or "ubuntu") rather than instances with multiple users with distinct access
control policies.

Example bastion Terraform configuration:
```
module "bastion" {
...
  share_keys_web_server = true
  share_keys_elb_subnets = module.vpc.private_subnets
  share_keys_allowed_cidrs = [ "10.0.0.0/8" ]
}
```

Example target instance Terraform configuration:
```
data "aws_lb" "authorized_keys" {
  name = "ssh-bastion-authorized-keys"
}

resource "aws_instance" "test" {
  ...
  user_data = <<EOF
#!/bin/bash -xe
echo AuthorizedKeysCommand /usr/bin/timeout 5 /usr/bin/curl --insecure https://${data.aws_lb.authorized_keys.dns_name}/authorized_keys >> /etc/ssh/sshd_config
echo AuthorizedKeysCommandUser nobody >> /etc/ssh/sshd_config
systemctl restart sshd.service
EOF
}
```

Note - You may want to consider supplying an emergency backup public key for use if the web server times-out.
You could do this by adding ```|| echo <emergency-key>``` after the curl command above.


To make use of key sharing, use ssh agent forwarding:
```
workstation $ ssh -A <bastion-username>@bastion-lb.example.com
...
<bastion-username>@bastion $ ssh <target-username>@target.example.com
...
<target--username>@target $

```


Known issues
------------

Tags are not applied to the instances generated by the auto scaling group do to known terraform issue : 
terraform-providers/terraform-provider-aws#290

Authors
-------

Module managed by [Guimove](https://github.com/Guimove).

License
-------

Apache 2 Licensed. See LICENSE for full details.
