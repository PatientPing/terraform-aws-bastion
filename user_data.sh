#!/bin/bash -x
yum -y update --security

##########################
## ENABLE SSH RECORDING ##
##########################

# Create a new folder for the log files
mkdir /var/log/bastion

# Allow ec2-user only to access this folder and its content
chown ec2-user:ec2-user /var/log/bastion
chmod -R 770 /var/log/bastion
setfacl -Rdm other:0 /var/log/bastion

# Make OpenSSH execute a custom script on logins
echo -e "\\nForceCommand /usr/bin/bastion/shell" >> /etc/ssh/sshd_config

sed -i 's/MaxAuthTries\ [0-9]/MaxAuthTries 5/' /etc/ssh/sshd_config

# Deny interactive shell to some users (tunnel-only)
cat >> /etc/ssh/sshd_config << 'EOF'

Match User ${ssh_tunnel_only_users}
  AllowTcpForwarding yes
  X11Forwarding no
  AllowAgentForwarding no
  ForceCommand /bin/false

EOF

# Block some SSH features that bastion host users could use to circumvent the solution
awk '!/X11Forwarding/' /etc/ssh/sshd_config > temp && mv temp /etc/ssh/sshd_config
echo "X11Forwarding no" >> /etc/ssh/sshd_config

mkdir /usr/bin/bastion

cat > /usr/bin/bastion/shell << 'EOF'

# Check that the SSH client did not supply a command
if [ -z $SSH_ORIGINAL_COMMAND ]; then

  # The format of log files is /var/log/bastion/YYYY-MM-DD_HH-MM-SS_user
  LOG_FILE="`date --date="today" "+%Y-%m-%d_%H-%M-%S"`_`whoami`"
  LOG_DIR="/var/log/bastion/"

  # Print a welcome message
  echo ""
  echo "NOTE: This SSH session will be recorded"
  echo "AUDIT KEY: $LOG_FILE"
  echo ""

  # I suffix the log file name with a random string. I explain why later on.
  SUFFIX=`mktemp -u _XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`

  # Wrap an interactive shell into "script" to record the SSH session
  script -qf --timing=$LOG_DIR$LOG_FILE$SUFFIX.time $LOG_DIR$LOG_FILE$SUFFIX.data --command=/bin/bash

else

  # The "script" program could be circumvented with some commands (e.g. bash, nc).
  # Therefore, I intentionally prevent users from supplying commands.

  echo "This bastion supports interactive sessions only. Do not supply a command"
  exit 1

fi

EOF

# Make the custom script executable
chmod a+x /usr/bin/bastion/shell

# Bastion host users could overwrite and tamper with an existing log file using "script" if
# they knew the exact file name. I take several measures to obfuscate the file name:
# 1. Add a random suffix to the log file name.
# 2. Prevent bastion host users from listing the folder containing log files. This is done
#    by changing the group owner of "script" and setting GID.
chown root:ec2-user /usr/bin/script
chmod g+s /usr/bin/script

# 3. Prevent bastion host users from viewing processes owned by other users, because the log
#    file name is one of the "script" execution parameters.
mount -o remount,rw,hidepid=2 /proc
awk '!/proc/' /etc/fstab > temp && mv temp /etc/fstab
echo "proc /proc proc defaults,hidepid=2 0 0" >> /etc/fstab

# Restart the SSH service to apply /etc/ssh/sshd_config modifications.
service sshd restart

############################
## EXPORT LOG FILES TO S3 ##
############################

cat > /usr/bin/bastion/sync_s3 << 'EOF'
#!/usr/bin/env bash

# Copy log files to S3 with server-side encryption enabled.
# Then, if successful, delete log files that are older than a day.
LOG_DIR="/var/log/bastion/"
aws s3 cp $LOG_DIR s3://${bucket_name}/logs/ --sse --region ${aws_region} --recursive && find $LOG_DIR* -mtime +1 -exec rm {} \;

EOF

chmod 700 /usr/bin/bastion/sync_s3

#######################################
## SYNCHRONIZE USERS AND PUBLIC KEYS ##
#######################################

# Bastion host users should log in to the bastion host with their personal SSH key pair.
# The public keys are stored on S3 with the following naming convention: "username.pub".
# This script retrieves the public keys, creates or deletes local user accounts as needed,
# and copies the public key to /home/username/.ssh/authorized_keys

cat > /usr/bin/bastion/sync_users << 'EOF'
#!/usr/bin/env bash

# The file will log user changes
LOG_FILE="/var/log/bastion/users_changelog.txt"

# The function returns the user name from the public key file name.
# Example: public-keys/sshuser.pub => sshuser
get_user_name () {
  echo "$1" | sed -e "s/.*\///g" | sed -e "s/\.pub//g"
}

# For each public key available in the S3 bucket
aws s3api list-objects --bucket ${bucket_name} --prefix public-keys/ --region ${aws_region} --output text --query 'Contents[?Size>`0`].Key' | tr '\t' '\n' > ~/keys_retrieved_from_s3
while read line; do
  USER_NAME="`get_user_name "$line"`"

  # Make sure the user name is alphanumeric
  if [[ "$USER_NAME" =~ ^[a-z][-a-z0-9]*$ ]]; then

    # Create a user account if it does not already exist
    cut -d: -f1 /etc/passwd | grep -qx $USER_NAME
    if [ $? -eq 1 ]; then
      /usr/sbin/adduser $USER_NAME && \
      mkdir -m 700 /home/$USER_NAME/.ssh && \
      chown $USER_NAME:$USER_NAME /home/$USER_NAME/.ssh && \
      echo "$line" >> ~/keys_installed && \
      echo "`date --date="today" "+%Y-%m-%d %H-%M-%S"`: Creating user account for $USER_NAME ($line)" >> $LOG_FILE
    fi

    # Copy the public key from S3, if an user account was created from this key
    if [ -f ~/keys_installed ]; then
      grep -qx "$line" ~/keys_installed
      if [ $? -eq 0 ]; then
        aws s3 cp s3://${bucket_name}/$line /home/$USER_NAME/.ssh/authorized_keys --region ${aws_region}
        chmod 600 /home/$USER_NAME/.ssh/authorized_keys
        chown $USER_NAME:$USER_NAME /home/$USER_NAME/.ssh/authorized_keys
      fi
    fi

  fi
done < ~/keys_retrieved_from_s3

# Remove user accounts whose public key was deleted from S3
if [ -f ~/keys_installed ]; then
  sort -uo ~/keys_installed ~/keys_installed
  sort -uo ~/keys_retrieved_from_s3 ~/keys_retrieved_from_s3
  comm -13 ~/keys_retrieved_from_s3 ~/keys_installed | sed "s/\t//g" > ~/keys_to_remove
  while read line; do
    USER_NAME="`get_user_name "$line"`"
    echo "`date --date="today" "+%Y-%m-%d %H-%M-%S"`: Removing user account for $USER_NAME ($line)" >> $LOG_FILE
    /usr/sbin/userdel -r -f $USER_NAME
  done < ~/keys_to_remove
  comm -3 ~/keys_installed ~/keys_to_remove | sed "s/\t//g" > ~/tmp && mv ~/tmp ~/keys_installed
fi

EOF

chmod 700 /usr/bin/bastion/sync_users

################################################
## Support creating users/keys from user_data ##
################################################

%{ for user in static_ssh_users ~}

/usr/sbin/adduser ${user.name}
mkdir -m 700 /home/${user.name}/.ssh
chown ${user.name}:${user.name} /home/${user.name}/.ssh
echo ${user.public_key} >> /home/${user.name}/.ssh/authorized_keys
passwd -d -u ${user.name}

%{ endfor }

###########################################
## SCHEDULE SCRIPTS AND SECURITY UPDATES ##
###########################################

cat > ~/mycron << EOF
*/5 * * * * /usr/bin/bastion/sync_s3
*/5 * * * * /usr/bin/bastion/sync_users
0 0 * * * yum -y update --security
EOF
crontab ~/mycron
rm ~/mycron


###########################################
## ONELOGIN SYNC                         ##
###########################################

%{ if onelogin_sync }

cat > /usr/bin/bastion/onelogin_sync.py << 'EOF'
${onelogin_sync_script}
EOF

cat > /usr/bin/bastion/onelogin_sync.requirements << 'EOF'
${onelogin_sync_requirements}
EOF

chmod 755 /usr/bin/bastion/onelogin_sync.py
yum -yq install python3 || (apt-get -q update && apt-get -yq install python3-pip)
pip3 install -r /usr/bin/bastion/onelogin_sync.requirements

crontab -l > ~/mycron
cat >> ~/mycron << EOF
*/5 * * * * AWS_DEFAULT_REGION=${aws_region} /usr/bin/bastion/onelogin_sync.py %{ for role in onelogin_sync_role_ids ~} --role_id ${role} %{ endfor }
EOF
crontab ~/mycron
rm ~/mycron
%{ endif ~}


###########################################
## SHARE AUTHORIZED KEYS VIA WEB SERVER  ##
###########################################

%{ if share_keys_web_server }

amazon-linux-extras install nginx1.12 -y || apt-get install -yq nginx
rm /usr/share/nginx/html/index.html
openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 \
    -subj "/C=US/ST=foo/L=foo/O=foo/CN=self-signed" \
    -keyout /etc/nginx/self-signed.key  -out /etc/nginx/self-signed.cert
chmod 600 /etc/nginx/self-signed.key

cat > /etc/nginx/tls.conf << 'EOF'
server {
  listen       443 ssl http2;
  root         /usr/share/nginx/html;
  ssl_certificate "/etc/nginx/self-signed.cert";
  ssl_certificate_key "/etc/nginx/self-signed.key";
}
EOF

mv /etc/nginx/tls.conf /etc/nginx/conf.d/tls.conf || mv /etc/nginx/tls.conf /etc/nginx/sites-enabled/tls.conf

systemctl restart nginx

cat > /usr/bin/bastion/share_keys_web_server << 'EOF'
#!/bin/bash
[ -f /tmp/authorized_keys ] && rm /tmp/authorized_keys
for home in $(getent passwd | grep -oP "/home/[^:]+"); do
  [ -s "$home/.ssh/authorized_keys" ] && cat $home/.ssh/authorized_keys >> /tmp/authorized_keys
done
[ -f /tmp/authorized_keys ] && mv /tmp/authorized_keys /usr/share/nginx/html/authorized_keys
EOF
chmod 700 /usr/bin/bastion/share_keys_web_server

crontab -l > ~/mycron
cat >> ~/mycron << EOF
*/5 * * * * /usr/bin/bastion/share_keys_web_server
EOF
crontab ~/mycron
rm ~/mycron

%{ endif ~}