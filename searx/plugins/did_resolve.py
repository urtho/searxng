# SPDX-License-Identifier: AGPL-3.0-or-later
"""A plugin that detects Decentralized Identifiers (DIDs) in the search query
and resolves them through an `ACA-Py`_ instance that has the `DIDResolver`_
plugin loaded.

.. _ACA-Py: https://github.com/openwallet-foundation/acapy
.. _DIDResolver: https://github.com/openwallet-foundation/acapy-plugins/tree/main/did_resolver

The plugin is opt-in: it is only registered when a ``did_resolve:`` settings
block exists in ``settings.yml``.

.. code:: yaml

   did_resolve:
     # Base URL of the ACA-Py admin API (with the ``did_resolver`` plugin
     # exposed).  Required.
     base_url: 'http://localhost:8020'

     # Optional X-API-Key value (ACA-Py admin API key).
     api_key: null

     # HTTP timeout in seconds for the resolve call.
     timeout: 10

     # Optional allow-list of DID methods that are forwarded to the resolver.
     # If empty/absent every syntactically valid DID is forwarded.
     methods:
       - web
       - key
       - sov
       - indy

The query is treated as a DID when the whole (trimmed) query is a syntactically
valid DID or DID URL according to the `W3C DID Core`_ ABNF.  Two short
summaries are placed in the answer area: one plain-text headline and one
key/value table with the salient fields of the resolved DID Document.

.. _W3C DID Core: https://www.w3.org/TR/did-core/#did-syntax
"""
from __future__ import annotations

import re
import typing as t
from collections import OrderedDict

from flask_babel import gettext
from httpx import HTTPError

from searx import settings
from searx.network import get as http_get
from searx.plugins import Plugin, PluginInfo
from searx.result_types import EngineResults

if t.TYPE_CHECKING:
    import flask
    from searx.search import SearchWithPlugins
    from searx.extended_types import SXNG_Request
    from searx.plugins import PluginCfg


DID_REGEX = re.compile(
    r"""
    ^did:
    (?P<method>[a-z0-9]+)                         # method-name
    :
    (?P<msid>
        (?:[a-zA-Z0-9._%-]|:[a-zA-Z0-9._%-])+     # method-specific-id (colons allowed between segments)
    )
    (?P<path>/[^?#\s]*)?                          # optional DID-URL path
    (?P<query>\?[^#\s]*)?                         # optional query
    (?P<fragment>\#\S*)?                          # optional fragment
    $
    """,
    re.VERBOSE,
)

# NFD (Non-Fungible Domain, Algorand) shortcut: any bare ``*.algo`` query is
# rewritten to ``did:nfd:<name>.algo`` before resolution.  NFD names are
# lowercase alphanumeric labels (hyphens allowed inside) separated by dots and
# ending with the ``.algo`` TLD.
NFD_REGEX = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.algo$"
)


class SXNGPlugin(Plugin):
    """Resolve a DID via an ACA-Py instance with the ``did_resolver`` plugin."""

    id = "did_resolve"

    def __init__(self, plg_cfg: "PluginCfg") -> None:
        super().__init__(plg_cfg)
        self.base_url: str = ""
        self.api_key: str | None = None
        self.timeout: float = 10.0
        self.methods: set[str] = set()

        self.info = PluginInfo(
            id=self.id,
            name=gettext("DID resolver plugin"),
            description=gettext(
                "Detects Decentralized Identifiers (DIDs) in the query and resolves"
                " them through an ACA-Py instance with the DIDResolver plugin."
            ),
            examples=[
                "did:web:example.com",
                "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
                "alice.algo",
            ],
            preference_section="query",
        )

    def init(self, app: "flask.Flask") -> bool:  # pylint: disable=unused-argument
        cfg = settings.get(self.id) or {}
        base_url = cfg.get("base_url")
        if not base_url:
            # No configuration provided => plugin stays inactive.
            return False

        self.base_url = str(base_url).rstrip("/")
        self.api_key = cfg.get("api_key") or None
        self.timeout = float(cfg.get("timeout", 10))
        self.methods = {str(m).lower() for m in (cfg.get("methods") or [])}
        return True

    def post_search(self, request: "SXNG_Request", search: "SearchWithPlugins") -> EngineResults:
        results = EngineResults()

        if search.search_query.pageno > 1:
            return results

        query = search.search_query.query.strip()
        did = _to_did(query)
        if did is None:
            return results

        method = DID_REGEX.match(did).group("method")  # type: ignore[union-attr]
        if self.methods and method not in self.methods:
            return results

        try:
            payload = self._resolve(did)
        except HTTPError as exc:
            self.log.warning("ACA-Py resolve failed for %s: %s", did, exc)
            results.add(
                results.types.Answer(
                    answer=gettext("Could not resolve DID %(did)s via ACA-Py.") % {"did": did}
                )
            )
            return results

        if not payload:
            return results

        doc = payload.get("did_document") or payload.get("didDocument") or {}
        metadata = payload.get("metadata") or payload.get("didResolutionMetadata") or {}

        results.add(results.types.Answer(answer=_summary(did, doc)))
        results.add(
            results.types.KeyValue(
                kvmap=_kvmap(did, method, doc, metadata),
                caption=gettext("DID Document") + f" — {did}",
                key_title=gettext("Field"),
                value_title=gettext("Value"),
            )
        )
        return results

    def _resolve(self, did: str) -> dict[str, t.Any] | None:
        url = f"{self.base_url}/resolver/resolve/{did}"
        headers = {"Accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        resp = http_get(url, headers=headers, timeout=self.timeout)
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            self.log.warning("ACA-Py response for %s is not JSON", did)
            return None


def _to_did(query: str) -> str | None:
    """Return a DID string for ``query``, or ``None`` if the query isn't a DID.

    Shortcut: any bare ``*.algo`` query is rewritten to ``did:nfd:<query>``
    so that NFD names can be typed as-is in the search bar.
    """
    if DID_REGEX.match(query):
        return query
    if NFD_REGEX.match(query):
        return f"did:nfd:{query}"
    return None


def _summary(did: str, doc: dict[str, t.Any]) -> str:
    vm_count = len(doc.get("verificationMethod") or [])
    svc_count = len(doc.get("service") or [])
    return gettext(
        "Resolved %(did)s — %(vm)d verification method(s), %(svc)d service(s)"
    ) % {"did": did, "vm": vm_count, "svc": svc_count}


def _kvmap(
    did: str,
    method: str,
    doc: dict[str, t.Any],
    metadata: dict[str, t.Any],
) -> "OrderedDict[str, t.Any]":
    kv: "OrderedDict[str, t.Any]" = OrderedDict()
    kv[gettext("DID")] = did
    kv[gettext("Method")] = method

    controller = doc.get("controller")
    if controller:
        kv[gettext("Controller")] = ", ".join(controller) if isinstance(controller, list) else controller

    also_known_as = doc.get("alsoKnownAs")
    if also_known_as:
        kv[gettext("Also known as")] = ", ".join(also_known_as)

    verification_methods = doc.get("verificationMethod") or []
    if verification_methods:
        kv[gettext("Verification methods")] = "\n".join(
            f"{vm.get('id', '?')} ({vm.get('type', '?')})" for vm in verification_methods
        )

    for rel in ("authentication", "assertionMethod", "keyAgreement", "capabilityInvocation", "capabilityDelegation"):
        refs = doc.get(rel)
        if refs:
            kv[rel] = "\n".join(str(r) if isinstance(r, str) else r.get("id", "?") for r in refs)

    services = doc.get("service") or []
    if services:
        kv[gettext("Services")] = "\n".join(
            f"{s.get('id', '?')} [{s.get('type', '?')}] → {s.get('serviceEndpoint', '?')}" for s in services
        )

    if metadata:
        if metadata.get("contentType"):
            kv[gettext("Content type")] = metadata["contentType"]
        if metadata.get("retrieved"):
            kv[gettext("Retrieved")] = metadata["retrieved"]
        if metadata.get("driverId") or metadata.get("driver_id"):
            kv[gettext("Driver")] = metadata.get("driverId") or metadata.get("driver_id")

    return kv
