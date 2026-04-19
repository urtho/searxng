# SPDX-License-Identifier: AGPL-3.0-or-later
# pylint: disable=missing-module-docstring,disable=missing-class-docstring,invalid-name

from unittest.mock import patch, Mock

from parameterized.parameterized import parameterized

import searx
import searx.plugins
import searx.preferences

from searx.extended_types import sxng_request
from searx.result_types import Answer

from tests import SearxTestCase
from .test_plugins import do_post_search


VALID_DIDS = [
    "did:web:example.com",
    "did:web:example.com:alice",
    "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "did:sov:WRfXPg8dantKVubE3HX8pw",
    "did:indy:sovrin:WRfXPg8dantKVubE3HX8pw",
    "did:web:example.com#key-1",
    "did:web:example.com/path/to/resource",
    "did:web:example.com?service=agent",
]

INVALID_DIDS = [
    "",
    "hello world",
    "not a did",
    "did:",
    "did:web",
    "did:WEB:example.com",  # method must be lowercase
    "http://example.com",
    "did:web:example.com more text",
]


FAKE_RESOLUTION = {
    "@context": "https://w3id.org/did-resolution/v1",
    "didDocument": {
        "id": "did:web:example.com",
        "controller": "did:web:example.com",
        "verificationMethod": [
            {"id": "did:web:example.com#key-1", "type": "Ed25519VerificationKey2018"},
        ],
        "authentication": ["did:web:example.com#key-1"],
        "service": [
            {
                "id": "did:web:example.com#agent",
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://example.com/agent",
            }
        ],
    },
    "didResolutionMetadata": {
        "contentType": "application/did+ld+json",
        "driverId": "did-web",
        "duration": 42,
    },
    "didDocumentMetadata": {"created": "2024-01-01T00:00:00Z"},
}

UNIRESOLVER_URL = "https://uniresolver.test"


def _inject_cfg(test_case):
    searx.settings["did_resolve"] = {
        "uniresolver_url": UNIRESOLVER_URL,
        "api_key": "secret",
        "timeout": 5,
    }
    test_case.addCleanup(searx.settings.pop, "did_resolve", None)


class PluginDIDResolveTest(SearxTestCase):

    def setUp(self):
        super().setUp()
        _inject_cfg(self)

        self.storage = searx.plugins.PluginStorage()
        self.storage.load_settings({"searx.plugins.did_resolve.SXNGPlugin": {"active": True}})
        self.storage.init(self.app)
        self.pref = searx.preferences.Preferences(["simple"], ["general"], {}, self.storage)
        self.pref.parse_dict({"locale": "en"})

    def test_plugin_registered_when_configured(self):
        self.assertEqual(1, len(self.storage))

    def test_plugin_skipped_without_config(self):
        searx.settings.pop("did_resolve", None)
        storage = searx.plugins.PluginStorage()
        storage.load_settings({"searx.plugins.did_resolve.SXNGPlugin": {"active": True}})
        storage.init(self.app)
        self.assertEqual(0, len(storage))

    @parameterized.expand(VALID_DIDS)
    def test_did_regex_matches(self, did: str):
        from searx.plugins.did_resolve import DID_REGEX  # pylint: disable=import-outside-toplevel
        self.assertIsNotNone(DID_REGEX.match(did), f"expected match for {did!r}")

    @parameterized.expand(INVALID_DIDS)
    def test_did_regex_rejects(self, query: str):
        from searx.plugins.did_resolve import DID_REGEX  # pylint: disable=import-outside-toplevel
        self.assertIsNone(DID_REGEX.match(query), f"expected no match for {query!r}")

    def test_non_did_query_noop(self):
        with self.app.test_request_context():
            sxng_request.preferences = self.pref
            with patch("searx.plugins.did_resolve.http_get") as mock_get:
                search = do_post_search("hello world", self.storage)
                mock_get.assert_not_called()
            self.assertEqual(list(search.result_container.answers), [])

    def test_resolve_success(self):
        with self.app.test_request_context():
            sxng_request.preferences = self.pref

            response = Mock()
            response.raise_for_status = Mock()
            response.json = Mock(return_value=FAKE_RESOLUTION)

            with patch("searx.plugins.did_resolve.http_get", return_value=response) as mock_get:
                search = do_post_search("did:web:example.com", self.storage)

            mock_get.assert_called_once()
            url = mock_get.call_args[0][0]
            self.assertEqual(url, f"{UNIRESOLVER_URL}/1.0/identifiers/did:web:example.com")
            headers = mock_get.call_args[1]["headers"]
            self.assertEqual(headers["X-API-Key"], "secret")

            expected = Answer(
                answer="Resolved did:web:example.com — 1 verification method(s), 1 service(s)"
            )
            self.assertIn(expected, search.result_container.answers)

    def test_pageno_two_is_noop(self):
        with self.app.test_request_context():
            sxng_request.preferences = self.pref
            with patch("searx.plugins.did_resolve.http_get") as mock_get:
                do_post_search("did:web:example.com", self.storage, pageno=2)
                mock_get.assert_not_called()

    def test_http_error_adds_answer_and_does_not_raise(self):
        from httpx import HTTPError  # pylint: disable=import-outside-toplevel

        with self.app.test_request_context():
            sxng_request.preferences = self.pref
            with patch(
                "searx.plugins.did_resolve.http_get",
                side_effect=HTTPError("boom"),
            ):
                search = do_post_search("did:web:example.com", self.storage)

            expected = Answer(
                answer="Could not resolve DID did:web:example.com via Universal Resolver."
            )
            self.assertIn(expected, search.result_container.answers)

    def test_unwrapped_did_document_response(self):
        # Some drivers answer ``Accept: application/did+ld+json`` by returning
        # the DID Document directly (no didDocument wrapper).  The plugin must
        # still pull verificationMethod / service counts from the top level.
        unwrapped = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:nfd:urtho.algo",
            "verificationMethod": [
                {"id": "did:nfd:urtho.algo#k1", "type": "Ed25519VerificationKey2018"},
                {"id": "did:nfd:urtho.algo#k2", "type": "Ed25519VerificationKey2018"},
            ],
            "service": [
                {"id": "did:nfd:urtho.algo#s1", "type": "LinkedDomains",
                 "serviceEndpoint": "https://urtho.algo.xyz"},
                {"id": "did:nfd:urtho.algo#s2", "type": "LinkedDomains",
                 "serviceEndpoint": "https://example.com"},
                {"id": "did:nfd:urtho.algo#s3", "type": "DIDCommMessaging",
                 "serviceEndpoint": "https://example.com/dcomm"},
            ],
        }
        with self.app.test_request_context():
            sxng_request.preferences = self.pref

            response = Mock()
            response.raise_for_status = Mock()
            response.json = Mock(return_value=unwrapped)

            with patch("searx.plugins.did_resolve.http_get", return_value=response):
                search = do_post_search("did:nfd:urtho.algo", self.storage)

            expected = Answer(
                answer="Resolved did:nfd:urtho.algo — 2 verification method(s), 3 service(s)"
            )
            self.assertIn(expected, search.result_container.answers)

    def test_overview_is_scored_high_enough_to_sort_first(self):
        # After post_search the plugin should have (a) registered a stub
        # engine in ``searx.engines.engines`` and (b) produced an overview
        # result whose score >> any single-engine weight-1 result (=1.0).
        import searx.engines

        with self.app.test_request_context():
            sxng_request.preferences = self.pref

            response = Mock()
            response.raise_for_status = Mock()
            response.json = Mock(return_value={
                "didDocument": {"id": "did:web:example.com",
                                "service": [{"type": "LinkedDomains",
                                             "serviceEndpoint": "https://example.com"}]}
            })

            with patch("searx.plugins.did_resolve.http_get", return_value=response):
                search = do_post_search("did:web:example.com", self.storage)

            stub = searx.engines.engines.get("plugin: did_resolve")
            self.assertIsNotNone(stub, "plugin must register a stub engine")
            self.assertGreaterEqual(getattr(stub, "weight", 0), 100.0)

            ordered = search.result_container.get_ordered_results()
            self.assertEqual(len(ordered), 1)
            # Score is weight (from stub) * len(positions)=1 / position=1.
            self.assertGreaterEqual(ordered[0].score, 100.0)

    def test_overview_folds_services_into_title_and_content(self):
        # URL-like, whitespace-containing, and object values are skipped when
        # picking title/content pairs.  The test fixture mixes all four:
        # - serviceEndpoint (URL)       -> skipped
        # - description (has spaces)    -> skipped
        # - nested object (dict)        -> skipped
        # - handle / tokenId (clean str)-> eligible
        doc = {
            "@context": ["https://www.w3.org/ns/did/v1"],
            "id": "did:nfd:urtho.algo",
            "verificationMethod": [
                {"id": "did:nfd:urtho.algo#k1", "type": "Ed25519VerificationKey2018"},
                {"id": "did:nfd:urtho.algo#k2", "type": "Ed25519VerificationKey2018"},
            ],
            "service": [
                # Pure URL, whitespace-free value — still skipped because of ``://``.
                {"id": "did:nfd:urtho.algo#s1", "type": "LinkedDomains",
                 "serviceEndpoint": "https://a-very-long-subdomain.example.org/"},
                # Clean token — wins title (longest eligible value).
                {"id": "did:nfd:urtho.algo#s2", "type": "NFDToken",
                 "tokenId": "NFD-1234567890ABCDEFGHIJKL"},
                # Clean handle — second-longest eligible value, goes to content.
                {"id": "did:nfd:urtho.algo#s3", "type": "SocialProfile",
                 "handle": "@urthoalgo",
                 # plus fields that must be skipped:
                 "serviceEndpoint": "https://twitter.com/urtho",
                 "description": "A long descriptive sentence with spaces",
                 "routingKeys": ["did:key:z6MkAAAA"]},
            ],
        }
        wrapped = {
            "didDocument": doc,
            "didResolutionMetadata": {"driverId": "did-nfd"},
            "didDocumentMetadata": {
                "created": "2024-01-02T03:04:05Z",
                "updated": "2024-06-07T08:09:10Z",
            },
        }

        with self.app.test_request_context():
            sxng_request.preferences = self.pref

            response = Mock()
            response.raise_for_status = Mock()
            response.json = Mock(return_value=wrapped)

            with patch("searx.plugins.did_resolve.http_get", return_value=response):
                search = do_post_search("did:nfd:urtho.algo", self.storage)

            main = list(search.result_container.main_results_map.values())
            # Overview only — no VM or service cards.
            self.assertEqual(len(main), 1)
            ov = main[0]

            self.assertEqual(ov.url, "https://dev.uniresolver.io/#did:nfd:urtho.algo")
            # Title is the longest *eligible* value (NFDToken.tokenId, 24 chars).
            # URL, whitespace, and nested-object values are excluded.
            self.assertEqual(ov.title, "NFD-1234567890ABCDEFGHIJKL")

            # content == date-only timestamps + "{service.type} :: {value}"
            # for the second-longest eligible pair (SocialProfile.handle).
            self.assertIn("Created: 2024-01-02", ov.content)
            self.assertIn("Updated: 2024-06-07", ov.content)
            self.assertNotIn("03:04:05", ov.content)
            self.assertIn("SocialProfile :: @urthoalgo", ov.content)

            # Excluded values must NOT leak into title/content.
            self.assertNotIn("://", ov.title)
            self.assertNotIn("://", ov.content)
            self.assertNotIn("long descriptive", ov.content)
            self.assertNotIn("routingKeys", ov.content)

            # No KeyValue results should be emitted at all.
            self.assertFalse(any(getattr(r, "caption", "") for r in main))

    def test_resolution_error_metadata_produces_answer(self):
        # 2xx response but didResolutionMetadata.error is set (e.g. notFound).
        with self.app.test_request_context():
            sxng_request.preferences = self.pref

            response = Mock()
            response.raise_for_status = Mock()
            response.json = Mock(return_value={
                "didDocument": None,
                "didResolutionMetadata": {
                    "error": "notFound",
                    "errorMessage": "DID not found on driver",
                },
                "didDocumentMetadata": {},
            })

            with patch("searx.plugins.did_resolve.http_get", return_value=response):
                search = do_post_search("did:web:missing.example", self.storage)

            expected = Answer(
                answer="Universal Resolver could not resolve did:web:missing.example: "
                "DID not found on driver"
            )
            self.assertIn(expected, search.result_container.answers)

    @parameterized.expand(
        [
            # (query, expected_did)
            ("nfdomains.algo", "did:nfd:nfdomains.algo"),
            ("bob-smith.algo", "did:nfd:bob-smith.algo"),
            # Ethereum account
            (
                "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B",
                "did:ethr:0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B",
            ),
            # ENS
            ("vitalik.eth", "did:ens:vitalik.eth"),
            # Unstoppable Domains
            ("brad.crypto", "did:ud:brad.crypto"),
            # CAIP-10 pkh
            (
                "eip155:1:0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B",
                "did:pkh:eip155:1:0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B",
            ),
        ]
    )
    def test_shortcut_rewrites(self, query: str, expected: str):
        with self.app.test_request_context():
            sxng_request.preferences = self.pref

            response = Mock()
            response.raise_for_status = Mock()
            response.json = Mock(return_value=FAKE_RESOLUTION)

            with patch("searx.plugins.did_resolve.http_get", return_value=response) as mock_get:
                do_post_search(query, self.storage)

            mock_get.assert_called_once()
            url = mock_get.call_args[0][0]
            self.assertEqual(url, f"{UNIRESOLVER_URL}/1.0/identifiers/{expected}")

    @parameterized.expand(
        [
            # Not a DID and no shortcut matches => no HTTP call
            "hello world",
            "alice",                      # no TLD
            "foo.com",                    # unsupported TLD
            "0x123",                      # too short for eth account
            "0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",  # non-hex
        ]
    )
    def test_shortcut_no_match_is_noop(self, query: str):
        with self.app.test_request_context():
            sxng_request.preferences = self.pref
            with patch("searx.plugins.did_resolve.http_get") as mock_get:
                do_post_search(query, self.storage)
                mock_get.assert_not_called()

    def test_custom_shortcut_overrides_defaults(self):
        # Replace the default shortcut table with a single custom entry that
        # rewrites ``*.example`` to ``did:demo:<name>``.
        searx.settings["did_resolve"]["shortcuts"] = [
            {"name": "demo", "pattern": r"^(?P<name>[a-z]+)\.example$", "rewrite": "did:demo:{name}"},
        ]

        storage = searx.plugins.PluginStorage()
        storage.load_settings({"searx.plugins.did_resolve.SXNGPlugin": {"active": True}})
        storage.init(self.app)

        with self.app.test_request_context():
            sxng_request.preferences = searx.preferences.Preferences(["simple"], ["general"], {}, storage)
            sxng_request.preferences.parse_dict({"locale": "en"})

            response = Mock()
            response.raise_for_status = Mock()
            response.json = Mock(return_value=FAKE_RESOLUTION)

            with patch("searx.plugins.did_resolve.http_get", return_value=response) as mock_get:
                do_post_search("alice.example", storage)
                # Default NFD shortcut should be gone
                do_post_search("nfdomains.algo", storage)

            self.assertEqual(mock_get.call_count, 1)
            self.assertEqual(
                mock_get.call_args[0][0],
                f"{UNIRESOLVER_URL}/1.0/identifiers/did:demo:alice",
            )

    def test_invalid_shortcut_is_skipped_not_fatal(self):
        searx.settings["did_resolve"]["shortcuts"] = [
            {"name": "bad-regex", "pattern": "(unclosed", "rewrite": "did:x:{0}"},
            {"name": "nfd", "pattern": r"^\S+\.algo$", "rewrite": "did:nfd:{0}"},
        ]

        storage = searx.plugins.PluginStorage()
        storage.load_settings({"searx.plugins.did_resolve.SXNGPlugin": {"active": True}})
        storage.init(self.app)

        with self.app.test_request_context():
            sxng_request.preferences = searx.preferences.Preferences(["simple"], ["general"], {}, storage)
            sxng_request.preferences.parse_dict({"locale": "en"})

            response = Mock()
            response.raise_for_status = Mock()
            response.json = Mock(return_value=FAKE_RESOLUTION)

            with patch("searx.plugins.did_resolve.http_get", return_value=response) as mock_get:
                do_post_search("nfdomains.algo", storage)

            mock_get.assert_called_once()
            self.assertEqual(
                mock_get.call_args[0][0],
                f"{UNIRESOLVER_URL}/1.0/identifiers/did:nfd:nfdomains.algo",
            )

    def test_named_network_is_activated_for_request(self):
        searx.settings["did_resolve"]["network"] = "did_resolver"

        storage = searx.plugins.PluginStorage()
        storage.load_settings({"searx.plugins.did_resolve.SXNGPlugin": {"active": True}})
        storage.init(self.app)

        with self.app.test_request_context():
            sxng_request.preferences = searx.preferences.Preferences(["simple"], ["general"], {}, storage)
            sxng_request.preferences.parse_dict({"locale": "en"})

            response = Mock()
            response.raise_for_status = Mock()
            response.json = Mock(return_value=FAKE_RESOLUTION)

            # Capture network-context calls in the exact order vs. http_get so
            # we can assert the switch happened BEFORE the HTTP call.
            call_log: list[str] = []
            with patch(
                "searx.plugins.did_resolve.set_context_network_name",
                side_effect=lambda name: call_log.append(f"set:{name}"),
            ), patch(
                "searx.plugins.did_resolve.http_get",
                side_effect=lambda *a, **kw: (call_log.append("http_get"), response)[1],
            ):
                do_post_search("did:web:example.com", storage)

            self.assertEqual(call_log, ["set:did_resolver", "http_get"])

    def test_no_network_configured_leaves_context_untouched(self):
        # Default fixture has no ``network`` key => set_context_network_name
        # should not be called.
        with self.app.test_request_context():
            sxng_request.preferences = self.pref

            response = Mock()
            response.raise_for_status = Mock()
            response.json = Mock(return_value=FAKE_RESOLUTION)

            with patch("searx.plugins.did_resolve.set_context_network_name") as mock_set, patch(
                "searx.plugins.did_resolve.http_get", return_value=response
            ):
                do_post_search("did:web:example.com", self.storage)

            mock_set.assert_not_called()

    def test_method_allowlist_skips_non_matching(self):
        searx.settings["did_resolve"]["methods"] = ["key"]

        storage = searx.plugins.PluginStorage()
        storage.load_settings({"searx.plugins.did_resolve.SXNGPlugin": {"active": True}})
        storage.init(self.app)

        with self.app.test_request_context():
            sxng_request.preferences = searx.preferences.Preferences(["simple"], ["general"], {}, storage)
            sxng_request.preferences.parse_dict({"locale": "en"})
            with patch("searx.plugins.did_resolve.http_get") as mock_get:
                do_post_search("did:web:example.com", storage)
                mock_get.assert_not_called()
