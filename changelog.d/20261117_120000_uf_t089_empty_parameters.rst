Fixed
~~~~~

- Empty-valued request parameters (``name=``) are now handled with a single
  semantics across every transport: the query string, the form body and the
  :rfc:`9101` request object. Per :rfc:`6749#section-3.1`, a parameter sent
  without a value is treated as if it were omitted. An empty optional
  parameter (``scope``, ``redirect_uri``, ``max_age``, ``prompt``,
  ``code_challenge`` and the other authorization parameters) falls back to its
  default behavior, an empty required parameter is rejected as missing, and an
  empty ``state`` is no longer echoed. The request object used to reject an
  empty string as an invalid type, while the form accepted it; both now behave
  the same way, and an authorization request hashes to the same
  ``authorization_key`` in both paths.
