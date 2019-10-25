#!/usr/bin/python
# -*- coding: utf-8 -*-
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
# Copyright: (c) 2019, Hong Viet Lê (@pomverte), Julien Alexandre (@jual), Marc Cyprien (@LeFameux)

from __future__ import absolute_import, division, print_function

ANSIBLE_METADATA = {
    'status': ['preview'],
    'supported_by': 'community',
    'metadata_version': '1.1'
}

DOCUMENTATION = '''
'''

EXAMPLES = '''
---
- name: Create a user
  grafana_user:
    url: "https://grafana.example.com"
    url_username: admin
    url_password: changeme
    name: "Bruce Wayne"
    email: batman@gotham.city
    login: batman
    password: robin
    state: present

- name: Delete a user
  grafana_user:
    url: "https://grafana.example.com"
    url_username: admin
    url_password: changeme
    login: batman
    state: absent
'''

RETURN = '''
---
'''

import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, url_argument_spec, basic_auth_header

__metaclass__ = type


class GrafanaUserInterface(object):

    def __init__(self, module):
        self._module = module
        # {{{ Authentication header
        self.headers = {"Content-Type": "application/json"}
        self.headers["Authorization"] = basic_auth_header(module.params['url_username'], module.params['url_password'])
        # }}}
        self.grafana_url = module.params.get("url")

    def _send_request(self, url, data=None, headers=None, method="GET"):
        if data is not None:
            data = json.dumps(data, sort_keys=True)
        if not headers:
            headers = []

        full_url = "{grafana_url}{path}".format(grafana_url=self.grafana_url, path=url)
        resp, info = fetch_url(self._module, full_url, data=data, headers=headers, method=method)
        status_code = info["status"]
        if status_code == 404:
            return None
        elif status_code == 401:
            self._module.fail_json(failed=True, msg="Unauthorized to perform action '%s' on '%s' header: %s" % (method, full_url, self.headers))
        elif status_code == 403:
            self._module.fail_json(failed=True, msg="Permission Denied")
        elif status_code == 409:
            self._module.fail_json(failed=True, msg="Login name is taken")
        elif status_code == 200:
            return self._module.from_json(resp.read())
        self._module.fail_json(failed=True, msg="Grafana Users API answered with HTTP %d" % status_code)
    
    def create_user(self, name, email, login, password):
        # https://grafana.com/docs/http_api/admin/#global-users
        url = "/api/admin/users" 
        user = dict(name=name, email=email, login=login, password=password)
        response = self._send_request(url, data=user, headers=self.headers, method="POST")
        return response

    def get_user_from_login(self, login):
        # https://grafana.com/docs/http_api/user/#get-single-user-by-username-login-or-email
        url = "/api/users/lookup?loginOrEmail={login}".format(login=login)
        user = self._send_request(url, headers=self.headers, method="GET")
        if user is None:
            self._module.fail_json(failed=True, msg="User '%s' does not exists" % login)
        return user

    def update_user(self, user_id, email, name, login):
        # https://grafana.com/docs/http_api/user/#user-update
        url = "/api/users/{user_id}".format(user_id=user_id)
        user = dict(email=email, name=name, login=login)
        response = self._send_request(url, data=user, headers=self.headers, method="PUT")
        return response

    def update_user_password(self, user_id, password):
        # https://grafana.com/docs/http_api/admin/#password-for-user
        url = "/api/admin/users/{user_id}/password".format(user_id=user_id)
        password_dict = dict(password=password)
        response = self._send_request(url, data=password_dict, headers=self.headers, method="PUT")
        return response

    def update_user_permissions(self, user_id, is_admin):
        # https://grafana.com/docs/http_api/admin/#permissions
        url = "/api/admin/users/{user_id}/permissions".format(user_id=user_id)
        permissions = dict(isGrafanaAdmin=is_admin)
        response = self._send_request(url, data=permissions, headers=self.headers, method="PUT")
        return response

    def delete_user(self, user_id):
        # https://grafana.com/docs/http_api/admin/#delete-global-user
        url = "/api/admin/users/{user_id}".format(user_id=user_id)
        response = self._send_request(url, headers=self.headers, method="DELETE")
        return response

def setup_module_object():
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_if=[
            ['state', 'present', ['name', 'email', 'password']],
        ]
    )
    return module

argument_spec = url_argument_spec()
# remove unnecessary arguments
del argument_spec['force']
del argument_spec['http_agent']

argument_spec.update(
    url=dict(type='str', required=True),
    url_username=dict(type='str', required=True),
    url_password=dict(type='str', required=True, no_log=True),
    state=dict(choices=['present', 'absent'], default='present'),
    name=dict(type='str', required=False),
    email=dict(type='str', required=False),
    login=dict(type='str', required=True),
    password=dict(type='str', required=False, no_log=True),
)


def main():
    module = setup_module_object()
    state = module.params['state']
    name = module.params['name']
    email = module.params['email']
    login = module.params['login']
    password = module.params['password']

    grafana_iface = GrafanaUserInterface(module)

    # search user by login
    target_user = grafana_iface.get_user_from_login(login)
    if state == 'present':
        if target_user is None:
            # create new user
            result = grafana_iface.create_user(name, email, login, password)
            module.exit_json(failed=False, changed=True, message=result.get("message"))
        else:
            # compare value before making rest call
            target_user_dict = dict(
                email=target_user.get("email"),
                name=target_user.get("name"),
                login=target_user.get("login")
            )
            param_dict = dict(email=email, name=name, login=login)
            if target_user_dict == param_dict:
                module.exit_json(failed=False, changed=False, message="user up to date, nothing to do")
            else:
                # update found user
                result = grafana_iface.update_user(target_user, email, name, login)
                module.exit_json(failed=False, changed=True, message=result.get("message"))
    elif state == 'absent':
        if target_user is None:
            module.exit_json(failed=False, changed=False, message="No user found, nothing to do")
        else:
            result = grafana_iface.delete_user(target_user.get("id"))
            module.exit_json(failed=False, changed=True, message=result.get("message"))


if __name__ == '__main__':
    main()
