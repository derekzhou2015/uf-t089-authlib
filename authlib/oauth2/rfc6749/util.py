import base64
import binascii
from urllib.parse import unquote

from authlib.common.encoding import to_unicode


def list_to_scope(scope):
    """Convert a list of scopes to a space separated string."""
    if isinstance(scope, (set, tuple, list)):
        return " ".join([to_unicode(s) for s in scope])
    if scope is None:
        return scope
    return to_unicode(scope)


def scope_to_list(scope):
    """Convert a space separated string to a list of scopes."""
    if isinstance(scope, (tuple, list, set)):
        return [to_unicode(s) for s in scope]
    elif scope is None:
        return None
    return scope.strip().split()


def omit_empty_params(params):
    """Return the mapping without the parameters whose value is empty.

    Per :rfc:`6749#section-3.1` and :rfc:`6749#section-3.2`, parameters sent
    without a value MUST be treated as if they were omitted from the request.
    A parameter that appears with no value (``key=`` or a bare ``key`` in an
    ``application/x-www-form-urlencoded`` message) is therefore dropped here,
    so that every OAuth 2.0 entry point sees it exactly as if it had never
    been sent. Only the empty string is dropped: ``0``, ``False`` and other
    falsy but meaningful values are kept.

    :param params: a mapping of parameter names to values
    :return: a dict without the empty-valued parameters
    """
    return {k: v for k, v in params.items() if v != ""}


def normalize_response_type(response_type):
    """Sort the values of a response type, so it can be compared as a string.

    Per RFC 6749 §3.1.1, the values are separated by spaces and their order
    does not matter. Repeated values are kept, so ``code code`` does not match
    ``code``.

    :param response_type: a space separated ``response_type`` value
    :return: the sorted values, or the input unchanged if it is empty
    """
    if not response_type:
        return response_type
    return " ".join(sorted(value for value in response_type.split(" ") if value))


def extract_basic_authorization(headers):
    auth = headers.get("Authorization")
    if not auth or " " not in auth:
        return None, None

    auth_type, auth_token = auth.split(None, 1)
    if auth_type.lower() != "basic":
        return None, None

    try:
        query = to_unicode(base64.b64decode(auth_token))
    except (binascii.Error, TypeError, UnicodeDecodeError):
        return None, None
    if ":" in query:
        username, password = query.split(":", 1)
        return unquote(username), unquote(password)
    return query, None
