Changed
~~~~~~~

- Parameters sent without a value (``key=`` or a bare ``key``) are now
  treated as if they were omitted from the request, uniformly across the
  OAuth 2.0 implementation, per :rfc:`6749#section-3.1` and
  :rfc:`6749#section-3.2`. This resolves the collision between those
  sections and :rfc:`6749#section-4.1.2`, which requires ``state`` to be
  returned "if present": an empty ``state=`` is not present, so it is
  neither echoed nor matched.

  The rule applies to every entry point and integration form:

  - the Flask and Django server payloads (``data`` and ``datalist``), for
    both the query string and the form body;
  - ``BasicOAuth2Payload``;
  - the client-side parsers ``parse_authorization_code_response`` and
    ``parse_implicit_response`` (the latter used to keep blank values, so an
    empty ``access_token=`` passed the presence check);
  - the request builders ``prepare_grant_uri`` and
    ``prepare_token_request``, which no longer emit bare ``key=``
    parameters, and an empty ``code`` now raises ``MissingCodeException``.

  Only the empty string is dropped; ``0``, ``False`` and ``None`` remain
  meaningful values. Two boundaries apply:

  - RFC 9101 ``request`` and ``request_uri`` select the JWT secured
    authorization request mechanism. Treating an empty one as omitted would
    silently downgrade the request to a plain OAuth 2.0 request, so their
    presence without a value is rejected with ``invalid_request_object`` or
    ``invalid_request_uri`` instead.
  - ``authlib.common.urls.url_decode`` and ``extract_params`` remain
    faithful codecs that keep blank values: OAuth 1.0a signature base
    strings must include empty-valued parameters per
    :rfc:`5849#section-3.4.1`.
