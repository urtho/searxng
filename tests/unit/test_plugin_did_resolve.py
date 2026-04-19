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


FAKE_DID_DOC = {
    "did_document": {
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
    "metadata": {"contentType": "application/did+ld+json", "driverId": "did-web"},
}


def _inject_cfg(test_case):
    searx.settings["did_resolve"] = {
        "base_url": "http://aca-py.test:8020",
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
            response.json = Mock(return_value=FAKE_DID_DOC)

            with patch("searx.plugins.did_resolve.http_get", return_value=response) as mock_get:
                search = do_post_search("did:web:example.com", self.storage)

            mock_get.assert_called_once()
            url = mock_get.call_args[0][0]
            self.assertEqual(url, "http://aca-py.test:8020/resolver/resolve/did:web:example.com")
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

            expected = Answer(answer="Could not resolve DID did:web:example.com via ACA-Py.")
            self.assertIn(expected, search.result_container.answers)

    def test_nfd_shortcut_rewrites_to_did_nfd(self):
        with self.app.test_request_context():
            sxng_request.preferences = self.pref

            response = Mock()
            response.raise_for_status = Mock()
            response.json = Mock(return_value=FAKE_DID_DOC)

            with patch("searx.plugins.did_resolve.http_get", return_value=response) as mock_get:
                do_post_search("nfdomains.algo", self.storage)

            mock_get.assert_called_once()
            url = mock_get.call_args[0][0]
            self.assertEqual(url, "http://aca-py.test:8020/resolver/resolve/did:nfd:nfdomains.algo")

    @parameterized.expand(
        [
            "nfdomains.algo",
            "bob-smith.algo",
            "sub.domain.algo",
            "a1.algo",
        ]
    )
    def test_nfd_regex_matches(self, query: str):
        from searx.plugins.did_resolve import NFD_REGEX  # pylint: disable=import-outside-toplevel
        self.assertIsNotNone(NFD_REGEX.match(query))

    @parameterized.expand(
        [
            ".algo",
            "-nfdomains.algo",
            "nfdomains-.algo",
            "NFDOMAINS.algo",
            "nfdomains.algo.foo",
            "nfdomains.com",
        ]
    )
    def test_nfd_regex_rejects(self, query: str):
        from searx.plugins.did_resolve import NFD_REGEX  # pylint: disable=import-outside-toplevel
        self.assertIsNone(NFD_REGEX.match(query))

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
