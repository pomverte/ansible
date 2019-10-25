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

# source hacking/env-setup
# ansible-test units grafana_user --docker

from __future__ import (absolute_import, division, print_function)

from units.compat import unittest
from units.compat.mock import patch, MagicMock
from ansible.modules.monitoring import grafana_user
from ansible.module_utils._text import to_bytes
from ansible.module_utils import basic
from ansible.module_utils.urls import basic_auth_header
import json

__metaclass__ = type

class MockedReponse(object):
    def __init__(self, data):
        self.data = data

    def read(self):
        return self.data

def exit_json(*args, **kwargs):
    """function to patch over exit_json; package return data into an exception"""
    if 'changed' not in kwargs:
        kwargs['changed'] = False
    raise AnsibleExitJson(kwargs)


def fail_json(*args, **kwargs):
    """function to patch over fail_json; package return data into an exception"""
    kwargs['failed'] = True
    raise AnsibleFailJson(kwargs)
class AnsibleExitJson(Exception):
    """Exception class to be raised by module.exit_json and caught by the test case"""
    pass


class AnsibleFailJson(Exception):
    """Exception class to be raised by module.fail_json and caught by the test case"""
    pass


def set_module_args(args):
    """prepare arguments so that they will be picked up during module creation"""
    args = json.dumps({'ANSIBLE_MODULE_ARGS': args})
    basic._ANSIBLE_ARGS = to_bytes(args)

def user_not_found_resp():
    server_response = json.dumps({"message": "User not found"})
    return (MockedReponse(server_response), {"status": 404})

def user_deleted_resp():
    server_response = json.dumps({"message": "User deleted"})
    return (MockedReponse(server_response), {"status": 200})

def user_exists_resp():
    server_response = json.dumps({
        "id": 1,
        "email": "user@mygraf.com",
        "name": "admin",
        "login": "admin",
        "theme": "light",
        "orgId": 1,
        "isGrafanaAdmin": True,
        "isDisabled": False,
        "isExternal": False,
        "authLabels": None,
        "updatedAt": "2019-0925T14:44:37+01:00",
        "createdAt": "2019-09-25T14:4:37+01:00"
    }, sort_keys=True)
    return (MockedReponse(server_response), {"status": 200})

class GrafanaUserTest(unittest.TestCase):

    def setUp(self):
        self.authorization = basic_auth_header("admin", "changeme")
        self.mock_module_helper = patch.multiple(basic.AnsibleModule,
                                                 exit_json=exit_json,
                                                 fail_json=fail_json)

        self.mock_module_helper.start()
        self.addCleanup(self.mock_module_helper.stop)

    @patch('ansible.modules.monitoring.grafana_user.fetch_url')
    def test_delete_user_by_user_id(self, mock_fetch_url):
        set_module_args({
            'url': 'https://grafana.example.com',
            'url_username': 'admin',
            'url_password': 'changeme',
            'login': 'batman',
            'state': 'absent'
        })
        module = grafana_user.setup_module_object()
        mock_fetch_url.return_value = user_deleted_resp()

        grafana_iface = grafana_user.GrafanaUserInterface(module)
        user_id = 42
        result = grafana_iface.delete_user(user_id)
        mock_fetch_url.assert_called_once_with(
            module,
            'https://grafana.example.com/api/admin/users/42',
            data=None,
            headers={'Content-Type': 'application/json', 'Authorization': self.authorization},
            method='DELETE')
        self.assertEquals(result, {"message": "User deleted"})


    def test_get_user_id_from_mail(self):
        # FIXME: What's needed for module initialization?
        set_module_args('url': 'http://grafana.example.com')
        module = grafana_user.setup_module_object()
        grafana_iface = grafana_user.GrafanaUserInteface(module)
        tests = (
            ('johndoe@example.com', 1),
            ('johndoe@example.com', 1234),
            ('johndoe@example.com', None),
        )
        for email, expected_id in tests:
            grafana_iface._sendrequest = MagicMock(return_value=expected_id)
            if expected_id is None:
                with self.assertRaises(AnsibleFailJson) as result:
                    grafana_iface.get_user_id_from_mail(email)
                self.assertTrue(result.exception.args[0]['msg'].startswith("User '{0}' does not exists".format(email))
                self.assertTrue(result.exception.args[0]['failed'])
            else:
                res = grafana_iface.get_user_id_from_mail(email)
                grafana_iface._send_request.assert_called_once_with(
                    module,
                    '/api/users/lookup?loginOrEmail={0}'.format(email),
                    data=None,
                    headers={'Content-Type': 'application/json', 'Authorization': self.authorization},
                    method='GET')
                self.assertEquals(res, expected_id)

    @patch('ansible.modules.monitoring.grafana_user.fetch_url')
    def test__send_request(self, mock_fetch_url):
        set_module_args({
            'url': 'http://grafana.example.com',
            'url_username': 'jdoe',
            'url_password': 'passwd'
        })
        module = grafana_user.setup_module_object()
        grafana_iface = grafana_user.GrafanaUserInterface(module)
        tests = (
            ({url: 'rst', data: 'rst', headers: 'rst', method: 'rst'}, user_exists_resp, True),
        )
        for args, resp_func, shouldFail in tests:
            mock_fetch_url.return_value = resp_func()
            res = grafana_iface._send_request(**args)
