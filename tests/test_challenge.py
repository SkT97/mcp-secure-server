"""Rewriting of Bearer challenges: required scopes, and no error without credentials."""

from __future__ import annotations

from mcp_secure_server.challenge import challenge_with_scopes

SDK_401 = (
    'Bearer error="invalid_token", error_description="Authentication required", '
    'resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource"'
)
SDK_403 = (
    'Bearer error="insufficient_scope", error_description="Required scope: a", '
    'resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource"'
)


def test_without_credentials_the_error_is_dropped_and_scopes_added() -> None:
    value = challenge_with_scopes(SDK_401, ("records:read", "records:list"), had_credentials=False)
    assert value == (
        'Bearer scope="records:read records:list", '
        'resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource"'
    )


def test_with_credentials_the_error_is_kept() -> None:
    value = challenge_with_scopes(SDK_403, ("records:read",), had_credentials=True)
    assert value.startswith('Bearer error="insufficient_scope", error_description=')
    assert 'scope="records:read"' in value
    assert value.endswith('oauth-protected-resource"')


def test_other_schemes_are_left_alone() -> None:
    assert challenge_with_scopes('Basic realm="x"', ("a",), had_credentials=True) == (
        'Basic realm="x"'
    )


def test_a_header_that_is_not_in_the_form_the_sdk_emits_is_left_untouched() -> None:
    odd = [
        'Bearer error="bad \\"x\\" tok", resource_metadata="https://m/x"',
        "Bearer error=invalid_token",
        'Bearer error="a", Basic realm="b"',
        'Bearer error="a",resource_metadata="https://m/x"',
        "Bearer",
        "",
    ]
    for value in odd:
        assert challenge_with_scopes(value, ("a",), had_credentials=True) == value, value


def test_the_scheme_is_matched_case_insensitively() -> None:
    value = challenge_with_scopes('bearer error="x"', ("a",), had_credentials=True)
    assert value == 'Bearer error="x", scope="a"'
