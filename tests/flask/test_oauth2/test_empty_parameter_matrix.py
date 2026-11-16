"""Behavior matrix for empty-valued authorization parameters.

RFC 6749 §3.1: parameters sent without a value MUST be treated as if they were
omitted. These tests pin the three outcomes of an empty value across the
transport forms (query string, form body and RFC 9101 request object):

* a required parameter is rejected as a missing parameter,
* an optional parameter falls back to its default / omitted behavior,
* an echoed parameter (``state``) is not echoed, because it is treated as
  omitted and the echo obligation no longer applies.
"""

import pytest
from joserfc import jwk
from joserfc import jwt

from authlib.common.urls import add_params_to_uri
from authlib.common.urls import url_decode
from authlib.common.urls import urlparse
from authlib.oauth2 import rfc9101
from authlib.oauth2.rfc6749.grants import (
    AuthorizationCodeGrant as _AuthorizationCodeGrant,
)
from tests.util import read_file_path

from .models import CodeGrantMixin
from .models import save_authorization_code
from .oauth2_server import create_basic_header

authorize_url = "/oauth/authorize"


@pytest.fixture(autouse=True)
def client(client, db):
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test"],
            "scope": "profile address",
            "token_endpoint_auth_method": "client_secret_basic",
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "jwks": read_file_path("jwks_public.json"),
            "require_signed_request_object": False,
        }
    )
    db.session.add(client)
    db.session.commit()
    return client


class AuthorizationCodeGrant(CodeGrantMixin, _AuthorizationCodeGrant):
    TOKEN_ENDPOINT_AUTH_METHODS = ["client_secret_basic", "client_secret_post", "none"]

    def save_authorization_code(self, code, request):
        return save_authorization_code(code, request)


@pytest.fixture(autouse=True)
def jar_server(server):
    server.register_grant(AuthorizationCodeGrant)

    class JWTAuthenticationRequest(rfc9101.JWTAuthenticationRequest):
        def resolve_client_public_key(self, client):
            return read_file_path("jwk_public.json")

        def get_server_metadata(self):
            return {}

    server.register_extension(JWTAuthenticationRequest())
    return server


def _query(rv):
    return dict(url_decode(urlparse.urlparse(rv.location).query))


def _jar_url(claims):
    request_obj = jwt.encode(
        {"alg": "RS256"},
        claims,
        jwk.import_key(read_file_path("jwk_private.json")),
    )
    return add_params_to_uri(
        authorize_url, {"client_id": "client-id", "request": request_obj}
    )


BASE_FORM = {"response_type": "code", "client_id": "client-id", "user_id": "1"}


def _send(test_client, transport, empty_param):
    """Send an authorization request where ``empty_param`` has an empty value,
    through one of the three transport forms.

    * query: the parameters are in the URL query string, the consent in the body,
    * form: the parameters are in the form body,
    * jar: the parameters are the claims of a signed request object.
    """
    if transport == "form":
        return test_client.post(authorize_url, data={**BASE_FORM, empty_param: ""})

    if transport == "query":
        return test_client.post(
            f"{authorize_url}?response_type=code&client_id=client-id&{empty_param}=",
            data={"user_id": "1"},
        )

    claims = {"response_type": "code", "client_id": "client-id", empty_param: ""}
    return test_client.post(_jar_url(claims), data={"user_id": "1"})


# ---------------------------------------------------------------------------
# Optional parameters: an empty value is treated as omitted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("transport", ["query", "form", "jar"])
def test_empty_state_is_not_echoed(test_client, transport):
    """state is an echoed parameter; an empty value is omitted, so it must not
    come back, identically across every transport."""
    rv = _send(test_client, transport, "state")

    assert rv.status_code == 303
    params = _query(rv)
    assert "code" in params
    assert "state" not in params


@pytest.mark.parametrize("transport", ["query", "form", "jar"])
def test_empty_scope_is_treated_as_omitted(test_client, transport):
    """An empty scope must not raise invalid_scope: it is the omitted scope."""
    rv = _send(test_client, transport, "scope")

    assert rv.status_code == 303
    assert "code" in _query(rv)


@pytest.mark.parametrize("transport", ["query", "form", "jar"])
def test_empty_redirect_uri_uses_default(test_client, transport):
    """An empty redirect_uri is omitted, so the registered default is used."""
    rv = _send(test_client, transport, "redirect_uri")

    assert rv.status_code == 303
    assert rv.location.startswith("https://client.test?")


def test_non_empty_state_is_still_echoed(test_client):
    """The normalization must not drop a real, non-empty state."""
    rv = test_client.post(authorize_url, data={**BASE_FORM, "state": "bar"})
    assert _query(rv)["state"] == "bar"


# ---------------------------------------------------------------------------
# Required parameters: an empty value is rejected as a missing parameter
# ---------------------------------------------------------------------------


def test_empty_client_id_is_rejected(test_client):
    # On the authorization endpoint an empty client_id is normalized to a
    # missing one and reported as invalid_client (without a redirect).
    rv = test_client.get(authorize_url + "?response_type=code&client_id=")
    assert b"invalid_client" in rv.data
    assert b"Missing 'client_id'" in rv.data


def test_empty_response_type_is_unsupported(test_client):
    # An empty response_type matches no registered grant; the error is
    # redirected to the client when its redirect URI can be validated.
    rv = test_client.post(
        authorize_url,
        data={**BASE_FORM, "response_type": ""},
    )
    assert rv.status_code == 303
    assert _query(rv)["error"] == "unsupported_response_type"


def test_empty_code_at_token_endpoint_is_rejected(test_client):
    headers = create_basic_header("client-id", "client-secret")
    rv = test_client.post(
        "/oauth/token",
        data={"grant_type": "authorization_code", "code": ""},
        headers=headers,
    )
    # An empty code is treated as an omitted, required parameter.
    assert rv.status_code == 400
    assert rv.json["error"] == "invalid_request"


def test_form_and_request_object_share_authorization_key(test_client):
    """The same empty-valued parameters must hash to the same authorization
    key for the form and request object transports, so the two integration
    styles do not split."""
    form_request = test_client.post(
        authorize_url,
        data={**BASE_FORM, "scope": "", "state": ""},
    )
    assert form_request.status_code == 303

    jar_request = test_client.post(
        _jar_url(
            {
                "response_type": "code",
                "client_id": "client-id",
                "scope": "",
                "state": "",
            }
        ),
        data={"user_id": "1"},
    )
    assert jar_request.status_code == 303
    # Both requests are accepted and neither echoes the empty state.
    assert "state" not in _query(form_request)
    assert "state" not in _query(jar_request)
