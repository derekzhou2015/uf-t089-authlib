"""Behavior matrix for parameters sent without a value: Django form.

Per RFC 6749 §3.1 and §3.2, parameters sent without a value MUST be treated
as if they were omitted from the request. This file pins that ruling for the
Django server integration, for the query string (authorization endpoint) and
the form body (token endpoint) entry points.
"""

from authlib.integrations.django_oauth2.requests import DjangoOAuth2Request


def _payload(request):
    return DjangoOAuth2Request(request).payload


def test_query_empty_params_are_omitted(factory):
    request = factory.get(
        "/authorize?client_id=c&response_type=code&redirect_uri=&scope=&state="
    )
    payload = _payload(request)
    assert payload.data == {"client_id": "c", "response_type": "code"}
    assert payload.datalist == {"client_id": ["c"], "response_type": ["code"]}
    assert payload.client_id == "c"
    assert payload.redirect_uri is None
    assert payload.scope is None
    assert payload.state is None


def test_query_bare_parameter_name_is_omitted(factory):
    """A bare "state" (without "=") is omitted too."""
    payload = _payload(factory.get("/authorize?client_id=c&state"))
    assert payload.data == {"client_id": "c"}
    assert payload.state is None


def test_form_empty_params_are_omitted(factory):
    request = factory.post(
        "/token",
        data="grant_type=authorization_code&code=abc&client_secret=&redirect_uri=",
        content_type="application/x-www-form-urlencoded",
    )
    payload = _payload(request)
    assert payload.data == {"grant_type": "authorization_code", "code": "abc"}
    assert payload.datalist == {
        "grant_type": ["authorization_code"],
        "code": ["abc"],
    }
    assert payload.grant_type == "authorization_code"


def test_empty_repeat_does_not_count_as_repetition(factory):
    """ "state=&state=x" holds one effective state: the empty one is omitted."""
    payload = _payload(factory.get("/authorize?client_id=c&state=&state=x"))
    assert payload.datalist["state"] == ["x"]
    assert payload.state == "x"


def test_non_empty_params_are_untouched(factory):
    payload = _payload(
        factory.get(
            "/authorize?client_id=c&response_type=code&scope=profile&state=s&max_age=0"
        )
    )
    assert payload.data == {
        "client_id": "c",
        "response_type": "code",
        "scope": "profile",
        "state": "s",
        "max_age": "0",
    }
