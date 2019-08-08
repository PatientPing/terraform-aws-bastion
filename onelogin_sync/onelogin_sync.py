#! /usr/bin/python3

import os
import sys
import logging
import re
import configargparse
import boto3

from onelogin.api.client import OneLoginClient


def get_opts(log):
    parser = configargparse.ArgParser(default_config_files=['onelogin_lookup.ini'])
    parser.add_argument('-v', '--verbosity', help='Logging level. Default ERROR', default='error')
    parser.add_argument('-c', '--config', help='Config file')
    parser.add_argument('-r', '--role_id', action='append', type=int,
                        help="""
                        Allowed OneLogin role IDs.  Use multiple --role_id [role_id] if needed.
                        If no role IDs are specified, all active users will be synced.
                        """)

    opts = parser.parse_args()

    if opts.verbosity.lower() == 'debug':
        log.setLevel(logging.DEBUG)
    elif opts.verbosity.lower() == 'info':
        log.setLevel(logging.INFO)
    elif opts.verbosity.lower() == 'warning':
        log.setLevel(logging.WARNING)
    elif opts.verbosity.lower() == 'error':
        log.setLevel(logging.ERROR)
    elif opts.verbosity.lower() == 'critical':
        log.setLevel(logging.CRITICAL)
    return opts


def get_logger():
    logging.basicConfig(format = '%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')
    log = logging.getLogger('default')
    return log


def setup():
    log = get_logger()
    opts = get_opts(log)
    if opts.role_id:
        allowed_roles_set = set(opts.role_id)
    else:
        allowed_roles_set = set([])
    return opts, log, allowed_roles_set


def get_onelogin_credentials():
    ssm = boto3.client('ssm')
    parameter = ssm.get_parameter(Name='/bastion/onelogin_id', WithDecryption=True)
    key_id = parameter['Parameter']['Value']
    parameter = ssm.get_parameter(Name='/bastion/onelogin_secret', WithDecryption=True)
    key_secret = parameter['Parameter']['Value']
    return key_id, key_secret


def get_user_list(key_id, key_secret, log):
    try:
        onelogin_client = OneLoginClient(
            key_id,
            key_secret,
            "us"
        )
    except Exception as onelogin_exception:
        log.error(onelogin_exception)
        sys.exit(1)

    onelogin_users = onelogin_client.get_users()

    return onelogin_users


def create_delete_users(log, users=None, allowed_role_set=None):
    os.environ['PATH'] += os.pathsep + '/usr/sbin'

    for u in users:

        if allowed_role_set:
            if u.role_ids:
                user_roles_set = set(u.role_ids)
            else:
                user_roles_set = set([])
            has_allowed_role = user_roles_set.intersection(allowed_role_set)
        else:
            has_allowed_role = True

        if (u.status in [1, 3, 4]
                and re.match('^[a-z][-a-z0-9]*$', u.username)
                and u.state == 1
                and has_allowed_role):
            if 'sshPublickey' in u.custom_attributes and str(u.custom_attributes['sshPublickey'])[0:3] == 'ssh':
                ssh_public_key = u.custom_attributes['sshPublickey']
                os.system(f'id -u {u.username} > /dev/null 2>&1 || useradd -m {u.username}')
                os.system(f'[ -d "/home/{u.username}/.ssh" ] ||  mkdir "/home/{u.username}/.ssh"')
                os.system(f'echo {ssh_public_key} > "/home/{u.username}/.ssh/authorized_keys"')
                os.system(f'chown {u.username}:{u.username} "/home/{u.username}/.ssh"')
            else:
                os.system(
                    f'[ -f "/home/{u.username}/.ssh/authorized_keys" ] && rm "/home/{u.username}/.ssh/authorized_keys"')
        else:
            os.system(f'id -u {u.username} > /dev/null 2>&1 && userdel {u.username}')


if __name__ == '__main__':
    (opts, log, allowed_roles_set) = setup()
    (onelogin_id, onelogin_secret) = get_onelogin_credentials()
    user_list = get_user_list(key_id=onelogin_id, key_secret=onelogin_secret, log=log)
    create_delete_users(log=log, users=user_list, allowed_role_set=allowed_roles_set)
