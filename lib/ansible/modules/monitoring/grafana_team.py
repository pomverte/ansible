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
# Copyright: (c) 2019, Rémi REY (@rrey)

from __future__ import absolute_import, division, print_function

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: grafana_team
author:
  - Rémi REY (@rrey)
version_added: "2.10"
short_description: Manage Grafana Teams
description:
  - Create/update/delete Grafana Teams through the Teams API.
  - Also allows to add members in the team (if members exists).
  - The Teams API is only available starting Grafana 5 and the module will fail if the server version is lower than version 5.
options:
  url:
    description:
      - The Grafana URL.
    required: true
    type: str
  name:
    description:
      - The name of the Grafana Team.
    required: true
    type: str
  email:
    description:
      - The mail address associated with the Team.
    required: true
    type: str
  url_username:
    description:
      - The Grafana user for API authentication.
    default: admin
    type: str
    aliases: [ grafana_user ]
  url_password:
    description:
      - The Grafana password for API authentication.
    default: admin
    type: str
    aliases: [ grafana_password ]
  grafana_api_key:
    description:
      - The Grafana API key.
      - If set, C(url_username) and C(url_password) will be ignored.
    type: str
  members:
    description:
      - List of team members (emails).
      - The list can be enforced with C(enforce_members) parameter.
    type: list
  state:
    description:
      - Delete the members not found in the C(members) parameters from the
      - list of members found on the Team.
    default: present
    type: str
    choices: ["present", "absent"]
  enforce_members:
    description:
      - Delete the members not found in the C(members) parameters from the
      - list of members found on the Team.
    default: False
    type: bool
  use_proxy:
    description:
      - If C(no), it will not use a proxy, even if one is defined in an environment variable on the target hosts.
    type: bool
    default: yes
  client_cert:
    description:
      - PEM formatted certificate chain file to be used for SSL client authentication.
      - This file can also include the key, in which case I(client_key) is not required
    type: path
  client_key:
    description:
      - PEM formatted file that contains your private key to be used for SSL client authentication.
      - If I(client_cert) contains both the certificate and key, this option is not required.
    type: path
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated.
      - This should only be set to C(no) when used on personally controlled sites using self-signed certificates.
      - Prior to 1.9.2 the code defaulted to C(no).
    type: bool
    default: yes
"""

EXAMPLES = """
---
- name: Create a team
  grafana_team:
      url: "https://grafana.example.com"
      grafana_api_key: "{{ some_api_token_value }}"
      name: "grafana_working_group"
      email: "foo.bar@example.com"
      state: present

- name: Create a team with members
  grafana_team:
      url: "https://grafana.example.com"
      grafana_api_key: "{{ some_api_token_value }}"
      name: "grafana_working_group"
      email: "foo.bar@example.com"
      members:
          - john.doe@example.com
          - jane.doe@example.com
      state: present

- name: Create a team with members and enforce the list of members
  grafana_team:
      url: "https://grafana.example.com"
      grafana_api_key: "{{ some_api_token_value }}"
      name: "grafana_working_group"
      email: "foo.bar@example.com"
      members:
          - john.doe@example.com
          - jane.doe@example.com
      enforce_members: yes
      state: present

- name: Delete a team
  grafana_team:
      url: "https://grafana.example.com"
      grafana_api_key: "{{ some_api_token_value }}"
      name: "grafana_working_group"
      email: "foo.bar@example.com"
      state: absent
"""

RETURN = """
---
team:
    description: Information about the Team
    returned: On success
    type: complex
    contains:
        avatarUrl:
            description: The url of the Team avatar on Grafana server
            returned: always
            type: str
            sample:
                - "/avatar/a7440323a684ea47406313a33156e5e9"
        email:
            description: The Team email address
            returned: always
            type: str
            sample:
                - "foo.bar@example.com"
        id:
            description: The Team email address
            returned: always
            type: int
            sample:
                - 42
        memberCount:
            description: The number of Team members
            returned: always
            type: int
            sample:
                - 42
        name:
            description: The name of the team.
            returned: always
            type: str
            sample:
                - "grafana_working_group"
        members:
            description: The list of Team members
            returned: always
            type: list
            sample:
                - ["john.doe@exemple.com"]
        orgId:
            description: The organization id that the team is part of.
            returned: always
            type: int
            sample:
                - 1
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import fetch_url, url_argument_spec, basic_auth_header
from ansible.module_utils.grafana import GrafanaTeamAdapter

__metaclass__ = type


def setup_module():
    argument_spec = url_argument_spec()
    del argument_spec["force"]
    del argument_spec["force_basic_auth"]
    del argument_spec["http_agent"]
    argument_spec.update(
        state=dict(choices=["present", "absent"], default="present"),
        name=dict(type="str", required=True),
        email=dict(type="str", required=True),
        members=dict(type="list", required=False),
        url=dict(type="str", required=True),
        grafana_api_key=dict(type="str", no_log=True),
        enforce_members=dict(type="bool", default=False),
        url_username=dict(aliases=["grafana_user"], default="admin"),
        url_password=dict(aliases=["grafana_password"], default="admin", no_log=True),
    )
    return AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False,
        required_together=[["url_username", "url_password"]],
        mutually_exclusive=[["url_username", "grafana_api_key"]],
    )


def diff_members(target, current):
    # TODO: return a tuple (or two values?)
    diff = {"to_del": [], "to_add": []}
    for member in target:
        if member not in current:
            diff["to_add"].append(member)
    for member in current:
        if member not in target:
            diff["to_del"].append(member)
    return diff


def reconcile_team():
    if state == "present" and not team:
        adapter.create(name, email)
        return True
    if state == "present" and team:
        if {"email": email, "name": name}.items() <= team.items():
            return False
        else:
            adapter.update(team["id"], name, email)
            return True
    if state == "absent" and not team:
        return False
    if state == "absent" and team:
        adapter.delete(team["id"])
        return True

def reconcile_members():
    if members is not None:
        cur_members = adapter.get_team_members(team.get("id"))
        plan = diff_members(members, cur_members)
        for member in plan.get("to_add"):
            user = adapter.get_user(member)
            if not user:
                module.fail_json(msg="")
            adapter.add_team_member(team.get("id"), user.get("id"))
            changed = True
        if enforce_members:
            for member in plan.get("to_del"):
                adapter.delete_team_member(
                    team.get("id"),
                    adapter.get_user(member, ignore=()).get("id"),
                )
                changed = True
        team = adapter.get_team_by_name(name)
    team["members"] = [
        member.get("email")
        for member in adapter.get_team_members(team.get("id"))
    ]
    module.exit_json(failed=False, changed=changed, team=team)


if __name__ == "__main__":
    module = setup_module()
    state = module.params["state"]
    name = module.params["name"]
    email = module.params["email"]
    members = module.params["members"]
    enforce_members = module.params["enforce_members"]

    adapter = GrafanaTeamAdapter(module)

    team = adapter.get(name, ignore=(404,))
