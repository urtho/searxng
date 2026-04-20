# SPDX-License-Identifier: AGPL-3.0-or-later
"""A plugin that detects Decentralized Identifiers (DIDs) in the search query
and resolves them through a `Universal Resolver`_ HTTP API.

.. _Universal Resolver: https://github.com/decentralized-identity/universal-resolver

The plugin is opt-in: it is only registered when a ``did_resolve:`` settings
block with a ``uniresolver_url`` is present in ``settings.yml``.

.. code:: yaml

   did_resolve:
     # Base URL of the Universal Resolver HTTP API (origin, without the
     # ``/1.0/identifiers`` path).  Required.
     uniresolver_url: 'https://dev.uniresolver.io'

     # Optional bearer/api token forwarded as ``X-API-Key`` — only needed
     # for self-hosted Universal Resolver instances that add auth.
     api_key: null

     # HTTP timeout in seconds for the resolve call.
     timeout: 10

     # Optional name of a network defined in ``outgoing.networks``.  This is
     # how you talk to a plain-HTTP resolver (e.g. a localhost instance)
     # without globally enabling ``enable_http`` on the default network.
     # See the ``outgoing.networks`` block in settings.yml for an example.
     network: 'did_resolver'

     # Optional allow-list of DID methods that are forwarded to the resolver.
     # If empty/absent every syntactically valid DID is forwarded.
     methods:
       - nfd
       - web
       - key
       - ethr
       - ens

     # Optional list of shortcut rewrites.  Each shortcut has a ``name``
     # (for logs/debug), a ``pattern`` (Python regex, matched against the
     # whole trimmed query) and a ``rewrite`` template where ``{0}`` is the
     # full match, ``{1}``, ``{2}`` ... are numbered capture groups and
     # ``{name}`` are named capture groups.  The first matching shortcut
     # wins.  When absent, :py:obj:`DEFAULT_SHORTCUTS` is used.
     shortcuts: []

The query is treated as a DID either directly (syntactically valid DID / DID
URL per `W3C DID Core`_) or after passing through a shortcut rewrite (e.g. a
bare Ethereum address becomes ``did:ethr:0x…``).  Two short summaries are
placed in the answer area: one plain-text headline and one key/value table
with the salient fields of the resolved DID Document together with the
resolution / document metadata blocks returned by the resolver.

.. _W3C DID Core: https://www.w3.org/TR/did-core/#did-syntax
"""
from __future__ import annotations

import re
import typing as t
from contextlib import contextmanager
from dataclasses import dataclass

from flask_babel import gettext
from httpx import HTTPError

import searx.engines

from searx import metrics, settings
from searx.network import THREADLOCAL, get as http_get, set_context_network_name
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


# Default shortcut table.  The first shortcut whose ``pattern`` matches the
# trimmed query is used; its ``rewrite`` template is expanded with ``{0}``
# (full match), ``{1}`` .. (numbered groups) and ``{name}`` (named groups).
DEFAULT_SHORTCUTS: list[dict[str, str]] = [
    # Non-Fungible Domains (Algorand NFDs)
    {
        "name": "nfd",
        "pattern": r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.algo$",
        "rewrite": "did:nfd:{0}",
    },
    # Ethereum account address
    {
        "name": "ethr",
        "pattern": r"^0x[a-fA-F0-9]{40}$",
        "rewrite": "did:ethr:{0}",
    },
    # Ethereum Name Service (*.eth)
    {
        "name": "ens",
        "pattern": r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.eth$",
        "rewrite": "did:ens:{0}",
    },
    # Unstoppable Domains
    {
        "name": "ud",
        "pattern": (
            r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
            r"\.(?:crypto|nft|wallet|x|dao|blockchain|bitcoin|polygon|888|zil)$"
        ),
        "rewrite": "did:ud:{0}",
    },
    # CAIP-10 chain account => did:pkh
    {
        "name": "pkh",
        "pattern": (
            r"^(?:eip155|bip122|solana|cosmos|polkadot|tezos|near|algorand)"
            r":[a-zA-Z0-9]+:[a-zA-Z0-9]+$"
        ),
        "rewrite": "did:pkh:{0}",
    },
]


@dataclass
class Shortcut:
    """Single entry of the shortcut rewrite table."""

    name: str
    pattern: re.Pattern[str]
    rewrite: str

    @classmethod
    def from_dict(cls, d: dict[str, t.Any]) -> "Shortcut":
        return cls(
            name=str(d["name"]),
            pattern=re.compile(str(d["pattern"])),
            rewrite=str(d["rewrite"]),
        )

    def apply(self, query: str) -> str | None:
        """Return the rewritten DID if ``pattern`` matches ``query``, else None."""
        m = self.pattern.match(query)
        if not m:
            return None
        positional = (m.group(0),) + m.groups()
        try:
            return self.rewrite.format(*positional, **m.groupdict())
        except (IndexError, KeyError):
            return None


class SXNGPlugin(Plugin):
    """Resolve a DID via a Universal Resolver HTTP API endpoint."""

    id = "did_resolve"

    def __init__(self, plg_cfg: "PluginCfg") -> None:
        super().__init__(plg_cfg)
        self.uniresolver_url: str = ""
        self.api_key: str | None = None
        self.timeout: float = 10.0
        self.methods: set[str] = set()
        self.shortcuts: list[Shortcut] = []
        self.network_name: str | None = None
        self.ui_url: str = "https://dev.uniresolver.io"

        self.info = PluginInfo(
            id=self.id,
            name=gettext("DID resolver plugin"),
            description=gettext(
                "Detects Decentralized Identifiers (DIDs) in the query and resolves"
                " them through a Universal Resolver HTTP API."
            ),
            examples=[
                "did:web:example.com",
                "nfdomains.algo",
                "0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B",
            ],
            preference_section="query",
        )

    def init(self, app: "flask.Flask") -> bool:  # pylint: disable=unused-argument
        cfg = settings.get(self.id) or {}
        uniresolver_url = cfg.get("uniresolver_url")
        if not uniresolver_url:
            # No configuration provided => plugin stays inactive.
            return False

        self.uniresolver_url = str(uniresolver_url).rstrip("/")
        self.api_key = cfg.get("api_key") or None
        self.timeout = float(cfg.get("timeout", 10))
        self.methods = {str(m).lower() for m in (cfg.get("methods") or [])}
        self.network_name = cfg.get("network") or None
        self.ui_url = str(cfg.get("ui_url") or "https://dev.uniresolver.io").rstrip("/")

        raw_shortcuts = cfg.get("shortcuts")
        if raw_shortcuts is None:
            raw_shortcuts = DEFAULT_SHORTCUTS
        self.shortcuts = []
        for raw in raw_shortcuts:
            try:
                self.shortcuts.append(Shortcut.from_dict(raw))
            except (re.error, KeyError, TypeError) as exc:
                self.log.warning("skipping invalid shortcut %r: %s", raw, exc)
        return True

    def _to_did(self, query: str) -> str | None:
        """Return the DID to resolve for ``query``, or ``None``."""
        if DID_REGEX.match(query):
            return query
        for sc in self.shortcuts:
            rewritten = sc.apply(query)
            if rewritten is None:
                continue
            if not DID_REGEX.match(rewritten):
                self.log.warning(
                    "shortcut %r produced non-DID value %r for query %r",
                    sc.name, rewritten, query,
                )
                continue
            self.log.debug("shortcut %r rewrote %r => %r", sc.name, query, rewritten)
            return rewritten
        return None

    def post_search(self, request: "SXNG_Request", search: "SearchWithPlugins") -> EngineResults:
        results = EngineResults()

        if search.search_query.pageno > 1:
            return results

        query = search.search_query.query.strip()
        did = self._to_did(query)
        if did is None:
            return results

        # MainResult goes into the scored/sorted main results.  Register a
        # per-engine score counter + a stub engine with a high weight so our
        # overview card always sorts to the top (lazy registration because
        # ``metrics.initialize`` and ``engines.load_engines`` wipe their
        # registries during ``search.initialize`` — *after* ``plugin.init``).
        #
        # We use the bare plugin id (``did_resolve``) as the engine label so
        # the card's "hit source" badge shows just the plugin name — not the
        # ``plugin: <id>`` string that PluginStorage would otherwise stamp.
        synthetic_engine = self.id
        _ensure_engine_metrics(synthetic_engine)
        _ensure_engine_stub(synthetic_engine, weight=1000.0)

        method = DID_REGEX.match(did).group("method")  # type: ignore[union-attr]
        if self.methods and method not in self.methods:
            return results

        try:
            payload = self._resolve(did)
        except HTTPError as exc:
            self.log.warning("Universal Resolver resolve failed for %s: %s", did, exc)
            results.add(
                results.types.Answer(
                    answer=gettext("Could not resolve DID %(did)s via Universal Resolver.")
                    % {"did": did}
                )
            )
            return results

        if not payload:
            return results

        # Universal Resolver can return either:
        # - a wrapped DID Resolution Result: {didDocument, didResolutionMetadata, didDocumentMetadata}
        # - or the DID Document itself (when the driver honours
        #   ``Accept: application/did+ld+json``), recognisable by its top-level
        #   ``id`` starting with ``did:``.
        if "didDocument" in payload or "did_document" in payload:
            doc = payload.get("didDocument") or payload.get("did_document") or {}
            resolution_meta = payload.get("didResolutionMetadata") or {}
            document_meta = payload.get("didDocumentMetadata") or {}
        elif isinstance(payload.get("id"), str) and payload["id"].startswith("did:"):
            doc = payload
            resolution_meta = {}
            document_meta = {}
        else:
            doc = {}
            resolution_meta = payload.get("didResolutionMetadata") or {}
            document_meta = payload.get("didDocumentMetadata") or {}

        error = resolution_meta.get("error") if isinstance(resolution_meta, dict) else None
        if error:
            msg = resolution_meta.get("errorMessage") or error
            results.add(
                results.types.Answer(
                    answer=gettext("Universal Resolver could not resolve %(did)s: %(err)s")
                    % {"did": did, "err": msg}
                )
            )
            return results

        results.add(results.types.Answer(answer=_summary(did, doc)))

        # Overview as a clickable main result linking to the resolver UI.
        # The URL carries ``?{did}`` (no ``=``) as well as the SPA fragment
        # ``#{did}``.  ``get_pretty_url`` renders the query after a ``›``
        # separator, so the breadcrumb above the title reads
        # ``{ui_url} › {did}``.  The SPA ignores the query; it routes on the
        # fragment alone.
        services = doc.get("service") or []
        top_pairs = _top_service_pairs(services, 2)
        title = top_pairs[0][1] if top_pairs else did
        avatar = _avatar_url(services)
        self.log.debug("did_resolve avatar for %s: %r", did, avatar)
        results.add(
            results.types.MainResult(
                title=title,
                url=f"{self.ui_url}/?{did}#{did}",
                content=_overview_content(document_meta, services),
                thumbnail=avatar,
                engine=synthetic_engine,
            )
        )

        return results

    def _resolve(self, did: str) -> dict[str, t.Any] | None:
        url = f"{self.uniresolver_url}/1.0/identifiers/{did}"
        # Prefer the wrapped DID Resolution Result (has separate metadata).
        # Fall back to plain JSON/DID Document for drivers that don't honour
        # the profile parameter; the caller copes with either shape.
        headers = {
            "Accept": (
                'application/ld+json;profile="https://w3id.org/did-resolution",'
                "application/json,"
                "application/did+ld+json"
            )
        }
        if self.api_key:
            headers["X-API-Key"] = self.api_key

        with _use_network(self.network_name):
            resp = http_get(url, headers=headers, timeout=self.timeout)
        resp.raise_for_status()
        try:
            return resp.json()
        except ValueError:
            self.log.warning("Universal Resolver response for %s is not JSON", did)
            return None


class _EngineStub:
    """Minimal engine-like object so the score/sort/metrics pipeline accepts a
    synthetic plugin-emitted result.  Only ``weight`` is actually consulted by
    ``calculate_score`` — the other attributes satisfy downstream accesses in
    ``ResultContainer.extend`` / ``get_ordered_results``.

    ``tokens`` carries a private value so the stub is filtered out of the
    ``/preferences``, ``/stats`` and ``/config`` engine listings (which all
    run through :py:obj:`searx.preferences.Preferences.validate_token`);
    otherwise those pages would crash trying to read histograms / traits the
    stub doesn't provide.
    """

    def __init__(self, name: str, weight: float):
        self.name = name
        self.weight = weight
        self.categories: list[str] = []
        self.paging = False
        self.timeout = 0.0
        self.tokens: list[str] = [f"__plugin:{name}__"]


def _ensure_engine_stub(engine_name: str, weight: float) -> None:
    if engine_name not in searx.engines.engines:
        searx.engines.engines[engine_name] = t.cast(
            t.Any, _EngineStub(engine_name, weight)
        )


def _ensure_engine_metrics(engine_name: str) -> None:
    """Ensure the per-engine counter + histogram entries for ``engine_name``
    exist.  Synthetic plugin engine names are not registered by
    :py:obj:`searx.metrics.initialize`, so lookups in :py:obj:`counter_storage`
    and :py:obj:`histogram_storage` would otherwise raise.
    """
    counters = metrics.counter_storage
    score_key = ("engine", engine_name, "score")
    if score_key not in counters.counters:
        counters.configure(*score_key)

    histograms = metrics.histogram_storage
    hist_key = ("engine", engine_name, "result", "count")
    if hist_key not in histograms.measures:
        histograms.configure(1, 100, *hist_key)


@contextmanager
def _use_network(name: str | None):
    """Switch ``searx.network``'s thread-local context to a named network for
    the duration of the ``with`` block and restore the previous network on
    exit.  When ``name`` is falsy the context is left untouched.
    """
    if not name:
        yield
        return

    had_prev = "network" in THREADLOCAL.__dict__
    prev = THREADLOCAL.__dict__.get("network")
    try:
        set_context_network_name(name)
        yield
    finally:
        if had_prev:
            THREADLOCAL.network = prev
        else:
            THREADLOCAL.__dict__.pop("network", None)


def _summary(did: str, doc: dict[str, t.Any]) -> str:
    vm_count = len(doc.get("verificationMethod") or [])
    svc_count = len(doc.get("service") or [])
    return gettext(
        "Resolved %(did)s — %(vm)d verification method(s), %(svc)d service(s)"
    ) % {"did": did, "vm": vm_count, "svc": svc_count}


def _stringify(val: t.Any) -> str:
    """Flatten a DID-document value (string / list / dict) to one string."""
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, list):
        return "\n".join(_stringify(item) for item in val)
    if isinstance(val, dict):
        return "\n".join(f"{k}: {_stringify(v)}" for k, v in val.items())
    return str(val)


def _rank_length(raw_value: t.Any, val_str: str) -> int:
    """Effective length of a service-field value for ranking.

    Returns ``0`` — i.e. ineligible for title/content promotion — when the
    value:
    - is a nested object (dict / list),
    - contains any whitespace character, or
    - looks like a URL (contains a ``://`` scheme separator).

    These are surfaced elsewhere (the resolver UI link, service cards) and
    make poor one-line captions.  Otherwise the string length is returned.
    """
    if not val_str:
        return 0
    if isinstance(raw_value, (dict, list)):
        return 0
    if any(ch.isspace() for ch in val_str):
        return 0
    if "://" in val_str:
        return 0
    return len(val_str)


def _top_service_pairs(services: list[dict[str, t.Any]], n: int) -> list[tuple[str, str]]:
    """For each non-meta field of each service, emit a ``(service_type, value)``
    pair.  URL-like, whitespace-containing, and nested-object values are
    skipped.  Sort by value length (descending) and return the top ``n``.

    ``service_type`` is the service's ``type`` attribute (e.g. ``LinkedDomains``,
    ``DIDCommMessaging``) — used as the human-readable label in renderings.
    Fields ``id`` and ``type`` themselves are excluded from the pair set.
    """
    candidates: list[tuple[str, str, int]] = []
    for svc in services:
        if not isinstance(svc, dict):
            continue
        svc_type = svc.get("type")
        if isinstance(svc_type, list):
            svc_type = ", ".join(str(x) for x in svc_type)
        elif svc_type is None:
            svc_type = gettext("Service")
        else:
            svc_type = str(svc_type)
        for k, v in svc.items():
            if k in ("id", "type"):
                continue
            if v in (None, "", [], {}):
                continue
            val_str = _stringify(v)
            rank = _rank_length(v, val_str)
            if rank == 0:
                continue
            candidates.append((svc_type, val_str, rank))
    candidates.sort(key=lambda p: p[2], reverse=True)
    return [(svc_type, val_str) for (svc_type, val_str, _) in candidates[:n]]


def _avatar_url(services: list[dict[str, t.Any]]) -> str:
    """Return the first URL-looking value stored under an ``avatar`` key inside
    a dict-valued ``serviceEndpoint``, or ``""`` if none is found.
    """
    for svc in services:
        if not isinstance(svc, dict):
            continue
        endpoint = svc.get("serviceEndpoint")
        if not isinstance(endpoint, dict):
            continue
        avatar = endpoint.get("avatar")
        if not isinstance(avatar, str):
            continue
        if "://" in avatar:
            return avatar
    return ""


def _object_endpoint_values(services: list[dict[str, t.Any]]) -> list[str]:
    """Return all non-URL string values from the first service whose
    ``serviceEndpoint`` is an object (dict).  Nested structures are flattened
    and stringified; entries containing ``://`` are skipped.
    """
    for svc in services:
        if not isinstance(svc, dict):
            continue
        endpoint = svc.get("serviceEndpoint")
        if not isinstance(endpoint, dict):
            continue
        values: list[str] = []
        for v in endpoint.values():
            if v in (None, "", [], {}):
                continue
            val_str = _stringify(v)
            if not val_str or "://" in val_str:
                continue
            values.append(val_str)
        if values:
            return values
    return []


def _overview_content(
    document_meta: dict[str, t.Any],
    services: list[dict[str, t.Any]],
) -> str:
    """Content for the overview result: the ``updated`` date (if any) followed
    by the non-URL values of the first service whose ``serviceEndpoint`` is an
    object.  All parts are joined with `` • ``.

    Note: ``content`` is HTML-escaped by ``webapp.py`` *before* the template's
    ``|safe`` filter renders it, so injecting ``<br>`` for real line breaks is
    not possible — we use a visible separator instead.
    """
    parts: list[str] = []
    updated = document_meta.get("updated")
    if updated:
        s = str(updated)
        parts.append(gettext("Updated") + ": " + s.split("T", 1)[0].split(" ", 1)[0])
    parts.extend(_object_endpoint_values(services))
    return " • ".join(parts)
