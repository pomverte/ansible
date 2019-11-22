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
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
"""

EXAMPLES = """
---
- name: Create a Grafana user
  grafana_user:
    url: "https://grafana.example.com"
    url_username: admin
    url_password: changeme
    name: "Bruce Wayne"
    email: batman@gotham.city
    login: batman
    password: robin
    state: present

- name: Delete a Grafana user
  grafana_user:
    url: "https://grafana.example.com"
    url_username: admin
    url_password: changeme
    login: batman
    state: absent
"""

RETURN = """
---
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import url_argument_spec
from ansible.module_utils.grafana import GrafanaUserAdapter

__metaclass__ = type


def setup_module():
    argument_spec = url_argument_spec()
    del argument_spec["force"]
    del argument_spec["http_agent"]
    argument_spec.update(
        url={"type": "str", "required": True},
        url_username={"type": "str", "required": True},
        url_password={"type": "str", "required": True, "no_log": True},
        state={"choices": ["present", "absent"], "default": "present"},
        name={"type": "str", "required": False},
        email={"type": "str", "required": False},
        login={"type": "str", "required": True},
        password={"type": "str", "required": False, "no_log": True},
    )
    return AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_if=[["state", "present", ["name", "email", "password"]],],
    )


if __name__ == "__main__":
    module = setup_module()
    state = module.params["state"]
    name = module.params["name"]
    email = module.params["email"]
    login = module.params["login"]
    password = module.params["password"]

    adapter = GrafanaUserAdapter(module)

    user = adapter.get(login, ignore=(404,))

    if state == "present" and not user:
        adapter.create(name, email, login, password)
        module.exit_json(changed=True)
    if state == "present" and user:
        if {"email": email, "name": name, "login": login}.items() <= user.items():
            module.exit_json(changed=False)
        else:
            adapter.update(user["id"], email, name, login)
            module.exit_json(changed=True)
    elif state == "absent" and not user:
        module.exit_json(changed=False)
    elif state == "absent" and user:
        adapter.delete(user["id"])
        module.exit_json(changed=True)
