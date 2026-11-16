from collections import defaultdict

from .errors import InsecureTransportError
from .util import normalize_response_type


def normalize_empty_values(data):
    """Return a copy of a request parameter mapping where an empty string is
    replaced with ``None``.

    Per RFC 6749 §3.1, parameters sent without a value MUST be treated as if
    they were omitted from the request. A framework parses ``state=`` as an
    empty string rather than as a missing parameter; normalizing it to ``None``
    gives every grant and extension a single "omitted" representation,
    independently of the transport (query string, form body, request object).

    Only strings are normalized. A JSON ``null`` is already ``None``, and the
    other JSON types keep their value so that the request object type checks
    keep rejecting them.
    """
    return {
        key: (None if isinstance(value, str) and value == "" else value)
        for key, value in data.items()
    }


def normalize_empty_value_lists(datalist):
    """Apply the RFC 6749 §3.1 empty-value rule to the repeated values of a
    request: each empty string becomes ``None``. The keys and the number of
    values are preserved, so a repeated parameter is still detected.
    """
    return {
        key: [None if isinstance(value, str) and value == "" else value for value in values]
        for key, values in datalist.items()
    }


class OAuth2Payload:
    @property
    def data(self):
        raise NotImplementedError()

    @property
    def datalist(self) -> defaultdict[str, list]:
        raise NotImplementedError()

    @property
    def client_id(self) -> str:
        """The authorization server issues the registered client a client
        identifier -- a unique string representing the registration
        information provided by the client. The value is extracted from
        request.

        :return: string
        """
        return self.data.get("client_id")

    @property
    def response_type(self) -> str:
        return normalize_response_type(self.data.get("response_type"))

    @property
    def grant_type(self) -> str:
        return self.data.get("grant_type")

    @property
    def redirect_uri(self):
        return self.data.get("redirect_uri")

    @property
    def scope(self) -> str:
        return self.data.get("scope")

    @property
    def state(self):
        return self.data.get("state")


class BasicOAuth2Payload(OAuth2Payload):
    def __init__(self, payload):
        # RFC 6749 §3.1: an empty value is treated as an omitted parameter, in
        # the request object path as in the query and form paths.
        self._data = normalize_empty_values(payload)
        self._datalist = {key: [value] for key, value in self._data.items()}

    @property
    def data(self):
        return self._data

    @property
    def datalist(self) -> defaultdict[str, list]:
        return self._datalist


class OAuth2Request:
    def __init__(self, method: str, uri: str, *, headers=None):
        InsecureTransportError.check(uri)
        #: HTTP method
        self.method = method
        self.uri = uri
        #: HTTP headers
        self.headers = headers or {}

        self.payload = None

        #: A hash of the authorization request parameters. It is the same for
        #: all the HTTP requests of one authorization request.
        self.authorization_key = None

        self._request_time = None
        self._request_time_loader = None

        self.client = None
        self.auth_method = None
        self.user = None
        self.authorization_code = None
        self.refresh_token = None
        self.credential = None
        self._scope = None

    @property
    def request_time(self):
        """The time the authorization request started, or ``None``. The
        authorization session gives it on first use."""
        if self._request_time_loader is not None:
            self._request_time = self._request_time_loader(self)
            self._request_time_loader = None

        return self._request_time

    @request_time.setter
    def request_time(self, value):
        self._request_time_loader = None
        self._request_time = value

    @property
    def args(self):
        raise NotImplementedError()

    @property
    def form(self):
        raise NotImplementedError()

    @property
    def scope(self) -> str:
        if self._scope is not None:
            return self._scope
        return self.payload.scope

    @scope.setter
    def scope(self, value: str):
        self._scope = value


class JsonPayload:
    @property
    def data(self):
        """The decoded JSON body, or ``None`` if the body is not valid JSON."""
        raise NotImplementedError()


class JsonRequest:
    def __init__(self, method, uri, headers=None):
        self.method = method
        self.uri = uri
        self.headers = headers or {}
        self.payload = None
