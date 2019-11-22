import json
from pkg_resources import parse_version
from ansible.module_utils.urls import fetch_url


class GrafanaAdapter(object):
    def __init__(self, module, min_version=None):
        self._module = module
        self.headers = {"Content-Type": "application/json"}
        self.base_url = module.params.get("url")

        health = self.health()
        version = health["version"]
        if min_version and parse_version(version) < min_version:
            self._module.fail_json(
                msg="This module requires Grafana >={}".format(min_version)
            )

    # TODO: No need to UT this method nor the constructor
    # TODO: This will be tested during IT by installing a older grafana version
    def health(self, **kwargs):
        return self.fetch_resource("/api/health", **kwargs)

    def handle_response(self, resp, info, ok=(200,), ignore=()):
        status = info["status"]
        if status in ok:
            return self._module.from_json(resp.read())
        if status in ignore:
            return None
        msg = (
            info["body"]
            if status >= 400
            else "Grafana API answered with HTTP {}".format(status)
        )
        self._module.fail_json(msg=msg)

    def fetch_resource(self, resource, data=None, method=None, **kwargs):
        data = self._module.jsonify(data)  # TODO: Ensure `if data:` test is not needed
        url = self.base_url + resource
        resp, info = fetch_url(
            self._module, url, data=data, headers=self.headers, method=method
        )
        return self.handle_response(resp, info, **kwargs)


class GrafanaUserAdapter(GrafanaAdapter):
    def __init__(self, module):
        super(GrafanaUserAdapter, self).__init__(module)

    def create(self, email, name, login, password, **kwargs):
        # https://grafana.com/docs/http_api/admin/#global-users
        data = {"email": email, "name": name, "login": login, "password": password}
        return self.fetch_resource("/api/admin/users", data=data, **kwargs)

    def get(self, login_or_email, **kwargs):
        # https://grafana.com/docs/http_api/user/#get-single-user-by-username-login-or-email
        resource = "/api/users/lookup?loginOrEmail={}".format(login_or_email)
        return self.fetch_resource(resource, **kwargs)

    # FIXME: naming implies it can't update email/login?
    def update(self, user_id, email, name, login, **kwargs):
        # https://grafana.com/docs/http_api/user/#user-update
        resource = "/api/users/{}".format(user_id)
        data = {"email": email, "name": name, "login": login}
        return self.fetch_resource(resource, data=data, method="PUT", **kwargs)

    def update_password(self, user_id, password, **kwargs):
        # https://grafana.com/docs/http_api/admin/#password-for-user
        resource = "/api/admin/users/{}/password".format(user_id)
        data = {"password": password}
        return self.fetch_resource(resource, data=data, method="PUT", **kwargs)

    def update_permissions(self, user_id, is_admin, **kwargs):
        # https://grafana.com/docs/http_api/admin/#permissions
        resource = "/api/admin/users/{}/permissions".format(user_id)
        data = {"isGrafanaAdmin": is_admin}
        return self.fetch_resource(resource, data=data, method="PUT", **kwargs)

    def delete(self, user_id, **kwargs):
        # https://grafana.com/docs/http_api/admin/#delete-global-user
        resource = "/api/admin/users/{}".format(user_id)
        return self.fetch_resource(resource, method="DELETE", **kwargs)


class GrafanaTeamAdapter(GrafanaAdapter):
    def __init__(self, module):
        super(GrafanaTeamAdapter, self).__init__(module, "5")

    def create(self, name, email, **kwargs):
        # https://grafana.com/docs/http_api/team/#add-team
        data = {"email": email, "name": name}
        return self.fetch_resource("/api/teams", data=data, **kwargs)

    def get(self, name, **kwargs):
        # https://grafana.com/docs/http_api/team/#using-the-name-parameter
        url = "/api/teams/search?name={}".format(name)
        return self.fetch_resource(url, **kwargs)

    def update(self, team_id, name, email, **kwargs):
        # https://grafana.com/docs/http_api/team/#update-team
        url = "/api/teams/{}".format(team_id)
        data = {"name": name, "email": email}
        return self.fetch_resource(url, data=data, method="PUT", **kwargs)

    def delete(self, team_id, **kwargs):
        # https://grafana.com/docs/http_api/team/#delete-team-by-id
        url = "/api/teams/{}".format(team_id)
        return self.fetch_resource(url, method="DELETE", **kwargs)

    def get_members(self, team_id, **kwargs):
        # https://grafana.com/docs/http_api/team/#get-team-members
        url = "/api/teams/{}/members".format(team_id)
        return self.fetch_resource(url, **kwargs)

    def add_member(self, team_id, user_id, **kwargs):
        # https://grafana.com/docs/http_api/team/#add-team-member
        url = "/api/teams/{}/members".format(team_id)
        data = {"userId": user_id}
        return self.fetch_resource(url, data=data, **kwargs)

    def remove_member(self, team_id, user_id, **kwargs):
        # https://grafana.com/docs/http_api/team/#remove-member-from-team
        url = "/api/teams/{}/members/{}".format(team_id, user_id)
        return self.fetch_resource(url, method="DELETE", **kwargs)
