from collections import defaultdict
from functools import cached_property

from flask.wrappers import Request

from authlib.oauth2.rfc6749 import JsonPayload
from authlib.oauth2.rfc6749 import JsonRequest
from authlib.oauth2.rfc6749 import OAuth2Payload
from authlib.oauth2.rfc6749 import OAuth2Request
from authlib.oauth2.rfc6749.requests import normalize_empty_value_lists
from authlib.oauth2.rfc6749.requests import normalize_empty_values


class FlaskOAuth2Payload(OAuth2Payload):
    def __init__(self, request: Request):
        self._request = request

    @cached_property
    def data(self):
        # RFC 6749 §3.1: a parameter sent without a value is treated as if it
        # were omitted, so normalize its empty string to None.
        return normalize_empty_values(self._request.values)

    @cached_property
    def datalist(self):
        values = defaultdict(list)
        for k in self._request.values:
            values[k].extend(self._request.values.getlist(k))
        return normalize_empty_value_lists(values)


class FlaskOAuth2Request(OAuth2Request):
    def __init__(self, request: Request):
        super().__init__(
            method=request.method, uri=request.url, headers=request.headers
        )
        self._request = request
        self.payload = FlaskOAuth2Payload(request)

    @property
    def framework_request(self):
        """The Flask request of this OAuth 2.0 request."""
        return self._request

    @property
    def args(self):
        return self._request.args

    @property
    def form(self):
        return self._request.form


class FlaskJsonPayload(JsonPayload):
    def __init__(self, request: Request):
        self._request = request

    @cached_property
    def data(self):
        try:
            return self._request.get_json(force=True, silent=True)
        except RecursionError:
            return None


class FlaskJsonRequest(JsonRequest):
    def __init__(self, request: Request):
        super().__init__(request.method, request.url, request.headers)
        self._request = request
        self.payload = FlaskJsonPayload(request)

    @property
    def form(self):
        return self._request.form
