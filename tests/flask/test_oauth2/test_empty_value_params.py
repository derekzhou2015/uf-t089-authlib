"""Behavior matrix for parameters sent without a value: Flask form.

Per RFC 6749 §3.1 and §3.2, parameters sent without a value MUST be treated
as if they were omitted from the request. This file pins that ruling for the
Flask server integration, for the query string (authorization endpoint) and
the form body (token endpoint) entry points.
"""

from flask import request as flask_request

from authlib.integrations.flask_oauth2.requests import FlaskOAuth2Request


def _payload(app, *args, **kwargs):
    with app.test_request_context(*args, **kwargs):
        payload = FlaskOAuth2Request(flask_request).payload
        # Evaluate the cached properties within the request context.
        assert payload.data is not None
        assert payload.datalist is not None
        return payload


def test_query_empty_params_are_omitted(app):
    payload = _payload(
        app, "/authorize?client_id=c&response_type=code&redirect_uri=&scope=&state="
    )
    assert payload.data == {"client_id": "c", "response_type": "code"}
    assert payload.datalist == {"client_id": ["c"], "response_type": ["code"]}
    assert payload.client_id == "c"
    assert payload.redirect_uri is None
    assert payload.scope is None
    assert payload.state is None


def test_query_bare_parameter_name_is_omitted(app):
    """A bare "state" (without "=") is omitted too."""
    payload = _payload(app, "/authorize?client_id=c&state")
    assert payload.data == {"client_id": "c"}
    assert payload.state is None


def test_form_empty_params_are_omitted(app):
    payload = _payload(
        app,
        "/token",
        method="POST",
        data="grant_type=authorization_code&code=abc&client_secret=&redirect_uri=",
        content_type="application/x-www-form-urlencoded",
    )
    assert payload.data == {"grant_type": "authorization_code", "code": "abc"}
    assert payload.datalist == {
        "grant_type": ["authorization_code"],
        "code": ["abc"],
    }
    assert payload.grant_type == "authorization_code"


def test_empty_repeat_does_not_count_as_repetition(app):
    """ "state=&state=x" holds one effective state: the empty one is omitted."""
    payload = _payload(app, "/authorize?client_id=c&state=&state=x")
    assert payload.datalist["state"] == ["x"]
    assert payload.state == "x"


def test_first_non_empty_value_wins(app):
    """ "scope=&scope=profile" holds one effective scope."""
    payload = _payload(app, "/authorize?client_id=c&scope=&scope=profile")
    assert payload.scope == "profile"
    assert payload.datalist["scope"] == ["profile"]


def test_non_empty_params_are_untouched(app):
    payload = _payload(
        app,
        "/authorize?client_id=c&response_type=code&scope=profile&state=s&max_age=0",
    )
    assert payload.data == {
        "client_id": "c",
        "response_type": "code",
        "scope": "profile",
        "state": "s",
        "max_age": "0",
    }
