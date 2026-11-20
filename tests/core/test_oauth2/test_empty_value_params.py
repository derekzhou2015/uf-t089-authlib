"""Behavior matrix for parameters sent without a value.

Per RFC 6749 §3.1 and §3.2, parameters sent without a value MUST be treated
as if they were omitted from the request. This file pins that ruling for the
framework-agnostic entry points: the callback parsers (query and fragment),
the request builders, and the basic server payload. The Flask and Django
integration forms have their own matrix files.
"""

import pytest

from authlib.oauth2.rfc6749 import errors
from authlib.oauth2.rfc6749 import parameters
from authlib.oauth2.rfc6749 import util
from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload


@pytest.mark.parametrize(
    "uri,expected",
    [
        # An empty "state" or a bare "scope" is omitted.
        (
            "https://client.test/cb?code=a&state=&scope",
            {"code": "a"},
        ),
        # A bare "state" (no "=") is omitted too.
        (
            "https://client.test/cb?code=a&state",
            {"code": "a"},
        ),
        # Non-empty parameters are untouched.
        (
            "https://client.test/cb?code=a&state=s&session_state=0",
            {"code": "a", "state": "s", "session_state": "0"},
        ),
    ],
    ids=["empty-values-omitted", "bare-name-omitted", "non-empty-kept"],
)
def test_parse_authorization_code_response_empty_params(uri, expected):
    assert parameters.parse_authorization_code_response(uri) == expected


def test_parse_authorization_code_response_empty_code_is_missing():
    """An empty "code=" is a missing code, not an empty one."""
    with pytest.raises(errors.MissingCodeException):
        parameters.parse_authorization_code_response(
            "https://client.test/cb?code=&state=s"
        )


def test_parse_authorization_code_response_empty_state_mismatches_real_state():
    """The client sent a state, the response carries an empty one: mismatch."""
    with pytest.raises(errors.MismatchingStateException):
        parameters.parse_authorization_code_response(
            "https://client.test/cb?code=a&state=", "xyz"
        )


@pytest.mark.parametrize(
    "uri,expected",
    [
        (
            "https://client.test/cb#access_token=a&token_type=bearer&state=",
            {"access_token": "a", "token_type": "bearer"},
        ),
        (
            "https://client.test/cb#access_token=a&token_type=bearer&state=s",
            {"access_token": "a", "token_type": "bearer", "state": "s"},
        ),
    ],
    ids=["empty-state-omitted", "non-empty-state-kept"],
)
def test_parse_implicit_response_empty_params(uri, expected):
    assert parameters.parse_implicit_response(uri) == expected


def test_parse_implicit_response_empty_access_token_is_missing():
    with pytest.raises(errors.MissingTokenException):
        parameters.parse_implicit_response(
            "https://client.test/cb#access_token=&token_type=bearer"
        )


def test_parse_implicit_response_empty_token_type_is_missing():
    with pytest.raises(errors.MissingTokenTypeException):
        parameters.parse_implicit_response(
            "https://client.test/cb#access_token=a&token_type="
        )


def test_basic_payload_omits_empty_params():
    """The server-side payload sees empty-valued parameters as omitted."""
    payload = BasicOAuth2Payload(
        {
            "client_id": "c",
            "response_type": "code",
            "redirect_uri": "",
            "scope": "",
            "state": "",
        }
    )
    assert payload.data == {"client_id": "c", "response_type": "code"}
    assert payload.datalist == {"client_id": ["c"], "response_type": ["code"]}
    assert payload.client_id == "c"
    assert payload.redirect_uri is None
    assert payload.scope is None
    assert payload.state is None


def test_basic_payload_keeps_falsy_non_empty_values():
    """Only the empty string is omitted; 0 and False are values."""
    payload = BasicOAuth2Payload({"max_age": 0, "claims": False})
    assert payload.data == {"max_age": 0, "claims": False}


def test_prepare_grant_uri_omits_empty_kwargs():
    """The client does not emit bare "key=" parameters."""
    uri = parameters.prepare_grant_uri(
        "https://server.test/authorize",
        "c",
        "code",
        prompt="",
        max_age=0,
        resource=["a", ""],
    )
    assert uri == (
        "https://server.test/authorize"
        "?response_type=code&client_id=c&max_age=0&resource=a"
    )


def test_prepare_token_request_empty_code_is_missing():
    """An empty "code" kwarg is a missing code."""
    with pytest.raises(errors.MissingCodeException):
        parameters.prepare_token_request("authorization_code", code="")


def test_omit_empty_params():
    assert util.omit_empty_params(
        {"a": "", "b": "x", "c": 0, "d": None, "e": False}
    ) == {"b": "x", "c": 0, "d": None, "e": False}
