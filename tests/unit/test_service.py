# CMN-C1-708 — Unit tests: service helpers (hash, event flags, SSRF allowlist)

from src.services.service import (
    hash_endpoint,
    is_endpoint_allowed,
    resolve_event_flags,
)


class TestHashEndpoint:
    def test_sha256_hex_length(self):
        h = hash_endpoint("https://ci.example.com/trigger")
        assert len(h) == 64
        assert h == hash_endpoint("https://ci.example.com/trigger")  # deterministic

    def test_different_urls_differ(self):
        assert hash_endpoint("https://a/x") != hash_endpoint("https://a/y")


class TestResolveEventFlags:
    def test_maps_known_phrases(self):
        flags = resolve_event_flags("on push and merge request", ["push_events", "merge_requests_events"])
        assert flags == {"push_events": True, "merge_requests_events": True}

    def test_never_emits_disallowed_flag(self):
        # "issue" maps to issues_events, but it's not in the allowed set -> dropped
        flags = resolve_event_flags("on issue events", ["push_events"])
        assert flags == {}

    def test_no_match_returns_empty(self):
        assert resolve_event_flags("hello world", ["push_events"]) == {}


class TestIsEndpointAllowed:
    ALLOW = ["https://ci.example.com/trigger", "https://hooks.example.org/"]

    def test_exact_match(self):
        assert is_endpoint_allowed("https://ci.example.com/trigger", self.ALLOW) is True

    def test_prefix_match(self):
        assert is_endpoint_allowed("https://hooks.example.org/repo/x", self.ALLOW) is True

    def test_http_scheme_blocked(self):
        assert is_endpoint_allowed("http://ci.example.com/trigger", self.ALLOW) is False

    def test_unlisted_blocked(self):
        assert is_endpoint_allowed("https://evil.example/steal", self.ALLOW) is False

    def test_empty_allowlist_fail_fast(self):
        assert is_endpoint_allowed("https://ci.example.com/trigger", []) is False
