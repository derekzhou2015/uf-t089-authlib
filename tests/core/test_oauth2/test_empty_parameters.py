"""Normalization of empty request parameter values.

Per RFC 6749 §3.1, parameters sent without a value MUST be treated as if they
were omitted from the request. The payload wrappers and the request object
payload therefore normalize an empty string to ``None`` before any grant or
extension reads the request.
"""

import pytest

from authlib.oauth2.rfc6749.requests import BasicOAuth2Payload
from authlib.oauth2.rfc6749.requests import normalize_empty_value_lists
from authlib.oauth2.rfc6749.requests import normalize_empty_values


def test_empty_string_is_normalized_to_none():
    assert normalize_empty_values({"state": "", "code": "abc"}) == {
        "state": None,
        "code": "abc",
    }


def test_missing_parameter_stays_absent():
    assert normalize_empty_values({"code": "abc"}) == {"code": "abc"}


def test_non_empty_values_are_untouched():
    data = {"scope": "profile", "max_age": "60", "client_id": "client-id"}
    assert normalize_empty_values(data) == data


def test_non_string_empty_values_are_not_normalized():
    # JSON types keep their value so the request object type checks reject them.
    data = {"max_age": 0, "claims": {}, "ui_locales": [], "missing": None}
    assert normalize_empty_values(data) == data


def test_normalized_dict_is_a_copy():
    original = {"state": ""}
    normalized = normalize_empty_values(original)
    assert normalized is not original
    assert original == {"state": ""}


def test_empty_value_lists_become_none_but_keep_their_length():
    datalist = {"state": [""], "code": ["a", "b"], "scope": ["", ""]}
    assert normalize_empty_value_lists(datalist) == {
        "state": [None],
        "code": ["a", "b"],
        "scope": [None, None],
    }


def test_basic_payload_normalizes_request_object_empty_strings():
    # The request object path (RFC 9101) must match the form path.
    payload = BasicOAuth2Payload(
        {"response_type": "code", "client_id": "client-id", "state": ""}
    )
    assert payload.data["state"] is None
    assert payload.state is None
    assert payload.datalist["state"] == [None]
    assert payload.data["response_type"] == "code"


def test_basic_payload_keeps_non_string_types():
    payload = BasicOAuth2Payload({"max_age": 0, "claims": {}})
    assert payload.data["max_age"] == 0
    assert payload.data["claims"] == {}


@pytest.mark.parametrize(
    "name",
    ["client_id", "response_type", "grant_type", "redirect_uri", "scope", "state"],
)
def test_basic_payload_exposes_optional_empty_value_as_none(name):
    payload = BasicOAuth2Payload({name: ""})
    assert getattr(payload, name) is None
