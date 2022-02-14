import argparse
import configparser
import json
import logging
import os
import random
import shutil
import socket
import subprocess
import sys
import time


import requests
import texttable


def str2bool(v):
    return v.lower() in ("yes", "true", "1")


def list2newline_string(v):
    return '{0}'.format(os.linesep).join(v)


def main():
    parser = argparse.ArgumentParser(description="DLMEngine CLI")
    parser.add_argument('--raw', dest='raw', action='store_true', default=False)

    subparsers = parser.add_subparsers(help='commands', dest='method')
    subparsers.required = True

    locks = subparsers.add_parser('locks', help='manage locks')
    locks.set_defaults(method='locks')

    locks_subparsers = locks.add_subparsers(help='commands', dest='sub_method')
    locks_subparsers.required = True

    locks_add = locks_subparsers.add_parser('add', help='add lock')
    locks_add.add_argument('--id', dest='id', action='store', required=True)
    locks_add.add_argument('--by', dest='by', action='store', required=False, default=socket.getfqdn())
    locks_add.add_argument('--secret', dest='secret', action='store', required=False, default=None)

    locks_delete = locks_subparsers.add_parser('delete', help='delete lock')
    locks_delete.add_argument('--id', dest='id', action='store', required=True)
    locks_delete.add_argument('--by', dest='by', action='store', required=False, default=socket.getfqdn())
    locks_delete.add_argument('--secret', dest='secret', action='store', required=False, default=None)

    locks_get = locks_subparsers.add_parser('get', help='get lock')
    locks_get.add_argument('--id', dest='id', action='store', required=True)

    locks_list = locks_subparsers.add_parser('list', help='list locks')
    locks_list.add_argument('--id', dest='id', action='store', required=False, default=None)
    locks_list.add_argument('--by', dest='by', action='store', required=False, default=None)

    permissions = subparsers.add_parser('permissions', help='manage permissions')
    permissions.set_defaults(method='permissions')

    permissions_subparsers = permissions.add_subparsers(help='commands', dest='sub_method')
    permissions_subparsers.required = True

    permissions_add = permissions_subparsers.add_parser('add', help='add permission')
    permissions_add.add_argument('--id', dest='id', action='store', required=True)
    permissions_add.add_argument(
        '--permissions', dest='permissions', action='store', required=False, default=[], nargs='+'
    )
    permissions_add.add_argument('--users', dest='users', action='store', required=False, default=[], nargs='+')

    permissions_delete = permissions_subparsers.add_parser('delete', help='delete permission')
    permissions_delete.add_argument('--id', dest='id', action='store', required=True)

    permissions_get = permissions_subparsers.add_parser('get', help='get permission')
    permissions_get.add_argument('--id', dest='id', action='store', required=True)

    permissions_update = permissions_subparsers.add_parser('update', help='update permission')
    permissions_update.add_argument('--id', dest='id', action='store', required=True)
    permissions_update.add_argument(
        '--permissions', dest='permissions', action='store', required=False, default=None, nargs='+'
    )
    permissions_update.add_argument('--users', dest='users', action='store', required=False, default=None, nargs='+')

    permissions_list = permissions_subparsers.add_parser('list', help='list permissions')
    permissions_list.add_argument('--permission', dest='id', action='store', required=False)
    permissions_list.add_argument('--permissions', dest='permissions', action='store', required=False)
    permissions_list.add_argument('--users', dest='users', action='store', required=False)

    shield = subparsers.add_parser('shield', help='run command using a lock')
    shield.set_defaults(method='shield')

    shield.add_argument('--lock', dest='lock', action='store', required=True, help="name of the lock")
    shield.add_argument(
        '--wait', dest='wait', action='store_true', default=False,
        required=False, help="wait for the lock to become available"
    )
    shield.add_argument(
        '--wait_max', dest='wait_max', action='store', type=int, default=3600,
        required=False, help="maximum time in seconds to wait, before giving up"
    )
    shield.add_argument(
        '--cmd', dest='cmd', action='store', nargs='*', required=True,
        help="command, including arguments, to execute"
    )
    shield.add_argument('--by', dest='by', action='store', required=False, default=socket.getfqdn())

    users = subparsers.add_parser('users', help='manage users')
    users.set_defaults(method='users')

    users_subparsers = users.add_subparsers(help='commands', dest='sub_method')
    users_subparsers.required = True

    users_add = users_subparsers.add_parser('add', help='add user')
    users_add.add_argument('--id', dest='id', action='store', required=True, default='_self')
    users_add.add_argument('--admin', dest='admin', action='store', required=False, default=False, type=str2bool)
    users_add.add_argument('--email', dest='email', action='store', required=True)
    users_add.add_argument('--name', dest='name', action='store', required=True)
    users_add.add_argument('--password', dest='password', action='store', required=True)

    users_delete = users_subparsers.add_parser('delete', help='delete user')
    users_delete.add_argument('--id', dest='id', action='store', required=True)

    users_get = users_subparsers.add_parser('get', help='get user')
    users_get.add_argument('--id', dest='id', action='store', required=False, default='_self')

    users_update = users_subparsers.add_parser('update', help='update user')
    users_update.add_argument('--id', dest='id', action='store', required=False, default='_self')
    users_update.add_argument('--admin', dest='admin', action='store', required=False, default=None, type=str2bool)
    users_update.add_argument('--email', dest='email', action='store', required=False, default=None)
    users_update.add_argument('--name', dest='name', action='store', required=False, default=None)
    users_update.add_argument('--password', dest='password', action='store', required=False, default=None)

    users_list = users_subparsers.add_parser('list', help='list users')
    users_list.add_argument('--id', dest='id', action='store', required=False, default=None)

    user_credentials = subparsers.add_parser('user_credentials', help='manage user_credentials')
    user_credentials.set_defaults(method='user_credentials')

    user_credentials_subparsers = user_credentials.add_subparsers(help='commands', dest='sub_method')
    user_credentials_subparsers.required = True

    user_credentials_add = user_credentials_subparsers.add_parser('add', help='add user_credential')
    user_credentials_add.add_argument('--user', dest='user', action='store', required=False, default='_self')
    user_credentials_add.add_argument('--description', dest='description', action='store', required=True)

    user_credentials_delete = user_credentials_subparsers.add_parser('delete', help='delete user_credential')
    user_credentials_delete.add_argument('--id', dest='id', action='store', required=True)
    user_credentials_delete.add_argument('--user', dest='user', action='store', required=False, default='_self')

    user_credentials_get = user_credentials_subparsers.add_parser('get', help='get user_credential')
    user_credentials_get.add_argument('--id', dest='id', action='store', required=True)
    user_credentials_get.add_argument('--user', dest='user', action='store', required=False, default='_self')

    user_credentials_update = user_credentials_subparsers.add_parser('update', help='update user_credential')
    user_credentials_update.add_argument('--id', dest='id', action='store', required=True)
    user_credentials_update.add_argument('--user', dest='user', action='store', required=False, default='_self')
    user_credentials_update.add_argument('--description', dest='description', action='store', required=True)

    user_credentials_list = user_credentials_subparsers.add_parser('list', help='list user_credential')
    user_credentials_list.add_argument('--user', dest='user', action='store', required=False, default='_self')

    parsed_args = parser.parse_args()

    dlm_engine_cli = DLMEngineCLI(raw=parsed_args.raw)

    if parsed_args.method == 'locks':
        if parsed_args.sub_method == 'add':
            dlm_engine_cli.locks_add(
                lock=parsed_args.id,
                by=parsed_args.by,
                secret=parsed_args.secret
            )
        elif parsed_args.sub_method == 'delete':
            dlm_engine_cli.locks_delete(
                lock=parsed_args.id,
                by=parsed_args.by,
                secret=parsed_args.secret
            )
        elif parsed_args.sub_method == 'get':
            dlm_engine_cli.locks_get(
                lock=parsed_args.id,
            )
        elif parsed_args.sub_method == 'list':
            dlm_engine_cli.locks_list(
                locks=parsed_args.id,
                acquired_by=parsed_args.by
            )
    elif parsed_args.method == 'permissions':
        if parsed_args.sub_method == 'add':
            dlm_engine_cli.permissions_add(
                permission=parsed_args.id,
                permissions=parsed_args.permissions,
                users=parsed_args.users
            )
        elif parsed_args.sub_method == 'delete':
            dlm_engine_cli.permissions_delete(
                permission=parsed_args.id
            )
        elif parsed_args.sub_method == 'get':
            dlm_engine_cli.permissions_get(
                permission=parsed_args.id
            )
        elif parsed_args.sub_method == 'update':
            dlm_engine_cli.permissions_add(
                permission=parsed_args.id,
                permissions=parsed_args.permissions,
                users=parsed_args.users,
                method='put'
            )
        elif parsed_args.sub_method == 'list':
            dlm_engine_cli.permissions_list(
                permission=parsed_args.id,
                permissions=parsed_args.permissions,
                users=parsed_args.permissions
            )
    elif parsed_args.method == 'shield':
        dlm_engine_cli.shield(
            lock=parsed_args.lock,
            wait=parsed_args.wait,
            wait_max=parsed_args.wait_max,
            cmd=parsed_args.cmd,
            by=parsed_args.by
        )
    elif parsed_args.method == 'users':
        if parsed_args.sub_method == 'add':
            dlm_engine_cli.users_add(
                _id=parsed_args.id,
                admin=parsed_args.admin,
                email=parsed_args.email,
                name=parsed_args.name,
                password=parsed_args.password
            )
        elif parsed_args.sub_method == 'delete':
            dlm_engine_cli.users_delete(
                _id=parsed_args.id
            )
        elif parsed_args.sub_method == 'get':
            dlm_engine_cli.users_get(
                _id=parsed_args.id
            )
        elif parsed_args.sub_method == 'update':
            dlm_engine_cli.users_add(
                _id=parsed_args.id,
                admin=parsed_args.admin,
                email=parsed_args.email,
                name=parsed_args.name,
                password=parsed_args.password,
                method='put'
            )
        elif parsed_args.sub_method == 'list':
            dlm_engine_cli.users_list(
                _id=parsed_args.id
            )
    elif parsed_args.method == 'user_credentials':
        if parsed_args.sub_method == 'add':
            dlm_engine_cli.user_credentials_add(
                user_id=parsed_args.user,
                description=parsed_args.description
            )
        elif parsed_args.sub_method == 'delete':
            dlm_engine_cli.user_credentials_delete(
                _id=parsed_args.id,
                user_id=parsed_args.user
            )
        elif parsed_args.sub_method == 'get':
            dlm_engine_cli.user_credentials_get(
                _id=parsed_args.id,
                user_id=parsed_args.user
            )
        elif parsed_args.sub_method == 'update':
            dlm_engine_cli.user_credentials_update(
                _id=parsed_args.id,
                user_id=parsed_args.user,
                description=parsed_args.description
            )
        elif parsed_args.sub_method == 'list':
            dlm_engine_cli.user_credentials_list(
                user_id=parsed_args.user
            )


class DLMEngineCLI(object):
    def __init__(self, raw):
        self.raw = raw
        self.texttable = texttable.Texttable(max_width=shutil.get_terminal_size(fallback=(80, 24))[0])
        self.log = logging.getLogger('application')
        self.log.setLevel(logging.DEBUG)
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.log.addHandler(handler)

        self._config = configparser.ConfigParser()
        try:
            self._config.read_file(open(os.path.expanduser('~/.dlm_engine_cli.ini')))
        except FileNotFoundError:
            self.log.fatal('Could not read configfile, please create: ~/.dlm_engine_cli.ini')
            sys.exit(1)
        try:
            self.endpoint = self._config.get('main', 'endpoint')
        except (configparser.NoOptionError, configparser.NoSectionError):
            self.log.fatal('please configure the endpoint in the main section')
            sys.exit(1)
        try:
            self.secret_id = self._config.get('main', 'secret_id')
        except (configparser.NoOptionError, configparser.NoSectionError):
            self.log.fatal('please configure the secret_id in the main section')
            sys.exit(1)
        try:
            self.secret = self._config.get('main', 'secret')
        except (configparser.NoOptionError, configparser.NoSectionError):
            self.log.fatal('please configure the secret in the main section')
            sys.exit(1)
        self.ca = self._config.get('main', 'ca', fallback=True)

    def _api(self, url, method='get', params=None, body=None):
        _method = getattr(requests, method)
        result = _method(
            url=self.endpoint + url,
            headers={
                'x-id': self.secret_id,
                'x-secret': self.secret
            },
            params=params,
            json=body,
            verify=self.ca

        )
        if result.json() is None:
            return
        if 'errors' in result.json():
            print(json.dumps(result.json(), indent=4, sort_keys=True))
            sys.exit(1)
        if self.raw:
            print(json.dumps(result.json(), indent=4, sort_keys=True))
        else:
            return result.json()

    @staticmethod
    def _api_body(**kwargs):
        params = dict()
        for key, value in kwargs.items():
            if value is None:
                continue
            elif value == ['']:
                params[key] = list()
            else:
                params[key] = value
        return {"data": params}

    @staticmethod
    def _api_params(**kwargs):
        params = dict()
        for key, value in kwargs.items():
            if value is not None:
                params[key] = value
        return params

    def locks_print(self, data):
        table = self.texttable
        table.set_deco(texttable.Texttable.HEADER)
        table.add_rows(rows=[['ID', 'acquired_by', 'acquired_since']], header=True)
        for row in data['data']['results']:
            table.add_row([
                row['data']['id'],
                row['data']['acquired_by'],
                row['data']['acquired_since'],
            ])
        print(table.draw())

    def locks_add(self, lock, by, secret):
        body = self._api_body(acquired_by=by, secret=secret)
        result = self._api(url='locks/{0}'.format(lock), body=body, method='post')
        self.locks_print({'data': {'results': [result]}})

    def locks_delete(self, lock, by, secret):
        body = self._api_body(acquired_by=by, secret=secret)
        self._api(url='locks/{0}'.format(lock), body=body, method='delete')
        print("OK")

    def locks_get(self, lock):
        result = self._api(url='locks/{0}'.format(lock))
        self.locks_print({'data': {'results': [result]}})

    def locks_list(self, locks, acquired_by):
        params = self._api_params(
            locks=locks,
            acquired_by=acquired_by
        )
        result = self._api(url='locks/_search', params=params)
        self.locks_print(result)

    def permissions_print(self, data):
        table = self.texttable
        table.set_deco(texttable.Texttable.HEADER)
        table.add_rows(rows=[['ID', 'permissions', 'users']], header=True)
        for row in data['data']['results']:
            table.add_row([
                row['data']['id'],
                list2newline_string(row['data']['permissions']),
                list2newline_string(row['data']['users'])
            ])
        print(table.draw())

    def permissions_add(self, permission, permissions, users, method='post'):
        body = self._api_body(
            permissions=permissions,
            users=users
        )
        result = self._api(url='permissions/{0}'.format(permission), body=body, method=method)
        self.permissions_print({'data': {'results': [result]}})

    def permissions_delete(self, permission):
        self._api(url='permissions/{0}'.format(permission), method='delete')
        print("OK")

    def permissions_get(self, permission):
        result = self._api(url='permissions/{0}'.format(permission))
        self.permissions_print({'data': {'results': [result]}})

    def permissions_list(self, permission, permissions, users):
        params = self._api_params(
            permission=permission,
            permissions=permissions,
            users=users
        )
        result = self._api(url='permissions/_search', params=params)
        self.permissions_print(result)

    def shield(self, lock, wait, wait_max, cmd, by):
        self.log.debug("waiting is set to {0}".format(wait))
        self.log.debug("max wait time is set to {0}".format(wait_max))
        if wait:
            _waited = 0
            while True:
                if self._shield_acquire(lock, by):
                    result = self._shield_cmd(cmd)
                    self._shield_release(lock, by)
                    sys.exit(result)
                else:
                    if _waited > wait_max:
                        self.log.error("exceeded max wait time, quiting")
                        sys.exit(1)
                    _sleep = random.randint(10, 60)
                    _waited += _sleep + 2
                    self.log.error("sleeping {0} seconds".format(_sleep))
                    time.sleep(_sleep)
        else:
            if not self._shield_acquire(lock, by):
                self.log.error("quiting")
                sys.exit(1)
            else:
                result = self._shield_cmd(cmd)
                self._shield_release(lock, by)
                sys.exit(result)

    def _shield_acquire(self, lock, by):
        self.log.info("trying to acquire: {0}".format(lock))
        resp = requests.post(
            json={
                "data": {
                    "acquired_by": by
                }
            },
            headers={
                'x-id': self.secret_id,
                'x-secret': self.secret
            },
            timeout=2.0,
            url="{0}locks/{1}".format(self.endpoint, lock),
            verify=self.ca
        )
        self.log.debug("http status_code is: {0}".format(resp.status_code))
        self.log.debug("http_response is {0}".format(resp.json()))
        if resp.status_code == 201:
            self.log.info("success acquiring lock")
            return True
        else:
            self.log.error("could not acquire lock: {0}".format(resp.json()))
            return False

    def _shield_release(self, lock, by):
        self.log.info("trying to release: {0}".format(lock))
        resp = requests.delete(
            json={
                "data": {
                    "acquired_by": by
                }
            },
            headers={
                'x-id': self.secret_id,
                'x-secret': self.secret
            },
            timeout=2.0,
            url="{0}locks/{1}".format(self.endpoint, lock),
            verify=self.ca
        )
        self.log.debug("http status_code is: {0}".format(resp.status_code))
        self.log.debug("http_response is {0}".format(resp.json()))
        if resp.status_code == 200:
            self.log.info("success releasing lock")
            return
        else:
            self.log.error("could not release lock: {0}".format(resp.json()))
            sys.exit(1)

    def _shield_cmd(self, args):
        self.log.info("running command: {0}".format(args))
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        for line in p.stdout:
            self.log.info(line.rstrip())
        p.stdout.close()
        self.log.info("finished running command: {0}".format(args))
        return p.wait()

    def users_print(self, data):
        table = self.texttable
        table.set_deco(texttable.Texttable.HEADER)
        table.add_rows(rows=[['ID', 'admin', 'name', 'email']], header=True)
        for row in data['data']['results']:
            table.add_row([
                row['data']['id'],
                row['data']['admin'],
                row['data']['name'],
                row['data']['email'],
            ])
        print(table.draw())

    def users_add(self, _id, admin, email, name, password, method='post'):
        body = self._api_body(
            admin=admin,
            email=email,
            name=name,
            password=password
        )
        result = self._api(url='users/{0}'.format(_id), body=body, method=method)
        self.users_print({'data': {'results': [result]}})

    def users_delete(self, _id):
        self._api(url='users/{0}'.format(_id), method='delete')
        print("OK")

    def users_get(self, _id):
        result = self._api(url='users/{0}'.format(_id))
        self.users_print({'data': {'results': [result]}})

    def users_list(self, _id):
        params = self._api_params(
            id=_id
        )
        result = self._api(url='users/_search', params=params)
        self.users_print(result)

    def user_credentials_print(self, data):
        table = self.texttable
        table.set_deco(texttable.Texttable.HEADER)
        table.add_rows(rows=[['ID', 'created', 'description']], header=True)
        for row in data['data']['results']:
            table.add_row([
                row['data']['id'],
                row['data']['created'],
                row['data']['description']
            ])
        print(table.draw())

    def user_credentials_add(self, user_id, description):
        body = self._api_body(
            description=description
        )
        result = self._api(url='users/{0}/credentials'.format(user_id), body=body, method='post')
        self.user_credentials_print({'data': {'results': [result]}})

    def user_credentials_delete(self, _id, user_id):
        self._api(url='users/{0}/credentials/{1}'.format(user_id, _id), method='delete')
        print("OK")

    def user_credentials_get(self, _id, user_id):
        result = self._api(url='users/{0}/credentials/{1}'.format(user_id, _id))
        self.user_credentials_print({'data': {'results': [result]}})

    def user_credentials_list(self, user_id):
        result = self._api(url='users/{0}/credentials'.format(user_id))
        self.user_credentials_print(result)

    def user_credentials_update(self, _id, user_id, description):
        body = self._api_body(
            description=description
        )
        result = self._api(url='users/{0}/credentials/{1}'.format(user_id, _id), body=body, method='put')
        self.user_credentials_print({'data': {'results': [result]}})
