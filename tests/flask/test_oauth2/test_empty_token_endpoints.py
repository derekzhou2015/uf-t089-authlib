"""Empty values at the token and other form-based endpoints.

RFC 6749 §3.1: parameters sent without a value MUST be treated as if they were
omitted. A required parameter given an empty value is therefore rejected as a
missing parameter, across every endpoint that reads the request form.
"""

import pytest
from flask import json

from authlib.integrations.sqla_oauth2 import create_query_token_func
from authlib.integrations.sqla_oauth2 import create_revocation_endpoint
from authlib.oauth2.rfc7662 import IntrospectionEndpoint

from .models import Token
from .models import User
from .models import db
from .oauth2_server import create_basic_header


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["https://client.test/authorized"],
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


@pytest.fixture(autouse=True)
def endpoints(server, app):
    RevocationEndpoint = create_revocation_endpoint(db.session, Token)
    server.register_endpoint(RevocationEndpoint)

    query_token = create_query_token_func(db.session, Token)

    class MyIntrospectionEndpoint(IntrospectionEndpoint):
        def check_permission(self, token, client, request):
            return True

        def query_token(self, token, token_type_hint):
            return query_token(token, token_type_hint)

        def introspect_token(self, token):
            user = db.session.get(User, token.user_id)
            return {"active": True, "username": user.username}

    server.register_endpoint(MyIntrospectionEndpoint)

    @app.route("/oauth/revoke", methods=["POST"])
    def revoke_token():
        return server.create_endpoint_response("revocation")

    @app.route("/oauth/introspect", methods=["POST"])
    def introspect_token():
        return server.create_endpoint_response("introspection")

    return server


@pytest.mark.parametrize("path", ["/oauth/revoke", "/oauth/introspect"])
def test_empty_token_is_rejected_as_missing(test_client, path):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(path, data={"token": ""}, headers=headers)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_request"


@pytest.mark.parametrize("path", ["/oauth/revoke", "/oauth/introspect"])
def test_missing_token_is_rejected(test_client, path):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(path, headers=headers)
    assert rv.status_code == 400
    assert json.loads(rv.data)["error"] == "invalid_request"


def test_empty_and_missing_token_behave_identically(test_client):
    """The empty value and the omitted parameter must give the same response."""
    headers = create_basic_header("client-id", "client-secret")
    empty = test_client.post("/oauth/revoke", data={"token": ""}, headers=headers)
    missing = test_client.post("/oauth/revoke", headers=headers)
    assert empty.status_code == missing.status_code
    assert json.loads(empty.data) == json.loads(missing.data)
