from collections import defaultdict
from functools import cached_property

from flask.wrappers import Request

from authlib.oauth2.rfc6749 import JsonPayload
from authlib.oauth2.rfc6749 import JsonRequest
from authlib.oauth2.rfc6749 import OAuth2Payload
from authlib.oauth2.rfc6749 import OAuth2Request


class FlaskOAuth2Payload(OAuth2Payload):
    def __init__(self, request: Request):
        self._request = request

    @cached_property
    def data(self):
        return {k: values[0] for k, values in self.datalist.items()}

    @cached_property
    def datalist(self):
        # Per RFC 6749 §3.1 and §3.2, a parameter sent without a value is
        # treated as if it were omitted from the request.
        values = defaultdict(list)
        for k in self._request.values:
            non_empty = [v for v in self._request.values.getlist(k) if v != ""]
            if non_empty:
                values[k].extend(non_empty)
        return values


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
