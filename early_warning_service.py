"""Terms-compliant, public-source Early Warning prototype backend.

Run with the Python standard library: python early_warning_service.py
This demo has no production authentication; put a trusted identity-aware API
gateway in front of every route before deployment.
"""

from __future__ import annotations

import base64
import hashlib
import html
import hmac
import json
import os
import re
import secrets
import sqlite3
import smtplib
import ssl
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
OFFICIAL_TYPES = (
    "Police officer",
    "Military intelligence",
    "Immigration officer",
    "Correctional service officer",
    "Media official",
)
PASSCODE_ITERATIONS = 240_000
MAX_OFFICIAL_PHOTO_BYTES = 5 * 1024 * 1024
MAX_CASE_PHOTO_BYTES = 2 * 1024 * 1024
DEMO_SUPERVISOR_SERVICE_NUMBER = "MZ-123"
DEMO_SUPERVISOR_PASSCODE = "12345678"
FAMILY_OTP_KEY = os.urandom(32)
AUTH_SESSIONS: dict[str, dict[str, Any]] = {}
CASE_TYPES = {"Missing person", "Suspected kidnapping", "Abduction of a minor"}
CASE_STATUSES = {
    "New", "Under review", "Active", "Located safe", "Located deceased",
    "Found by family", "Closed (insufficient information)", "Withdrawn (false report)",
}
CASE_TERMINAL_STATUSES = {
    "Located safe", "Located deceased", "Found by family",
    "Closed (insufficient information)", "Withdrawn (false report)",
}
CASE_STAFF_TYPES = {"Police officer", "Military intelligence"}
NIGERIA_BOUNDS = {"minLat": 4.0, "maxLat": 14.0, "minLon": 2.0, "maxLon": 15.0}


def load_local_environment() -> None:
    environment_file = ROOT / ".env"
    if not environment_file.exists():
        return
    for line_number, raw_line in enumerate(environment_file.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        key = key.strip()
        allowed_keys = {
            "NSP_PORT", "NSP_DB_PATH", "NSP_SMTP_HOST", "NSP_SMTP_PORT",
            "NSP_SMTP_USERNAME", "NSP_SMTP_PASSWORD", "NSP_SMTP_FROM",
            "NSP_SMTP_USE_SSL", "NSP_SMTP_USE_STARTTLS",
            "NSP_X_BEARER_TOKEN", "NSP_META_PAGE_ACCESS_TOKEN",
        }
        if not separator or key not in allowed_keys:
            raise ValueError(f"Invalid .env entry on line {line_number}; unsupported configuration key.")
        if key not in os.environ:
            os.environ[key] = value.strip().strip("\"'")


load_local_environment()
PORT = int(os.environ.get("NSP_PORT", "8765"))
SMTP_HOST = os.environ.get("NSP_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("NSP_SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("NSP_SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("NSP_SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("NSP_SMTP_FROM", SMTP_USERNAME)
SMTP_USE_SSL = os.environ.get("NSP_SMTP_USE_SSL", "false").casefold() == "true"
SMTP_USE_STARTTLS = os.environ.get("NSP_SMTP_USE_STARTTLS", "true").casefold() == "true"
X_BEARER_TOKEN = os.environ.get("NSP_X_BEARER_TOKEN", "").strip()
META_PAGE_ACCESS_TOKEN = os.environ.get("NSP_META_PAGE_ACCESS_TOKEN", "").strip()
META_GRAPH_API_VERSION = "v26.0"
PIPELINE_INTERVAL_SECONDS = 12 * 60
REQUEST_TIMEOUT_SECONDS = 12
MAX_FEED_BYTES = 2_000_000
DB_PATH = Path(os.environ.get("NSP_DB_PATH", "nsp_early_warning.sqlite3"))
if not DB_PATH.is_absolute():
    DB_PATH = ROOT / DB_PATH

EVENT_TERMS = {
    "Kidnapping report": ("kidnap", "abduct", "taken hostage"),
    "Threat report": ("threat", "threatened", "threatening", "death threat", "bomb threat"),
    "Attack report": ("attack", "bomb", "explosion", "blast", "gunmen", "bandits", "insurgent", "terrorist", "air strike", "airstrike", "violence", "violent", "gunfire", "shooting", "shot dead", "massacre", "murder"),
    "Protest or unrest": ("protest", "unrest", "riot", "curfew", "demonstrat", "communal clash", "clash with police", "clash with security"),
}
RUMOR_TERMS = ("unconfirmed", "unverified", "rumour", "rumor", "unsubstantiated", "viral claim", "claim circulated")
MISINFORMATION_TERMS = ("false claim", "fact check", "misleading claim", "fabricated report", "false report")
NON_INCIDENT_TERMS = ("football", "premier league", "champions league", "ucl:", "vs ", "versus", "court strikes out", "arraigned", "appears in court", "court charges", "witness gives evidence")
PIDGIN_TERMS = ("dey", "una", "dem", "wahala", "abeg", "na so")
YORUBA_TERMS = ("ẹ", "ọ", "ṣ", "ẹni", "jẹ")
HAUSA_TERMS = ("yan bindiga", "sace", "garkuwa", "rikici", "hari")
IGBO_TERMS = ("ndị", "ọgụ", "ndị uwe ojii", "ntọhapụ")

def load_location_gazetteer() -> dict[str, tuple[str, ...]]:
    raw = json.loads((ROOT / "data" / "nigeria_lgas.json").read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or len(raw) != 37:
        raise ValueError("The Nigeria LGA gazetteer must contain all 37 state/FCT entries.")
    gazetteer = {
        str(state): tuple(str(name).casefold() for name in names)
        for state, names in raw.items()
        if isinstance(names, list)
    }
    if len(gazetteer) != 37 or sum(map(len, gazetteer.values())) != 774:
        raise ValueError("The Nigeria LGA gazetteer must contain 774 LGA names.")
    return gazetteer


STATE_GAZETTEER = load_location_gazetteer()

CREDIBLE_NEWS_DOMAINS = {
    "punchng.com", "vanguardngr.com", "premiumtimesng.com", "channelstv.com",
    "dailytrust.com", "thenationonlineng.net", "guardian.ng", "bbc.com",
}

KEYWORDS = "attack OR kidnapping OR kidnap OR clash OR protest OR curfew OR unrest"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clean_text(value: str, limit: int = 700) -> str:
    value = re.sub(r"<[^>]*>", " ", value or "")
    value = html.unescape(value)
    return re.sub(r"\s+", " ", value).strip()[:limit]


def clean_public_text(value: str, limit: int = 700) -> str:
    text = clean_text(value, limit * 2)
    text = re.sub(r"(?<![\w.+-])@[A-Za-z0-9_.]{1,64}\b", "[account omitted]", text)
    return text[:limit]


def safe_datetime(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            try:
                parsed = datetime.strptime(value, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
                return parsed.isoformat(timespec="seconds")
            except ValueError:
                return ""


def safe_datetime_epoch(value: str) -> float | None:
    normalised = safe_datetime(value)
    if not normalised:
        return None
    try:
        return datetime.fromisoformat(normalised).timestamp()
    except ValueError:
        return None


def classify(text: str) -> str | None:
    folded = text.casefold()
    if any(term in folded for term in NON_INCIDENT_TERMS):
        return None
    if any(term in folded for term in MISINFORMATION_TERMS):
        return "Misinformation"
    if any(term in folded for term in RUMOR_TERMS):
        return "Rumor risk"
    if re.search(r"\b(kill|killed|kills|neutralised|neutralized)\b", folded) and any(
        term in folded for term in ("troops", "soldier", "terrorist", "insurgent", "bandit", "police officer", "gunmen")
    ):
        return "Attack report"
    for label, terms in EVENT_TERMS.items():
        if any(term in folded for term in terms):
            return label
    return None


def detect_language(text: str) -> str:
    folded = text.casefold()
    if any(term in folded for term in HAUSA_TERMS):
        return "Hausa"
    if any(term in folded for term in IGBO_TERMS):
        return "Igbo"
    if any(term in folded for term in YORUBA_TERMS):
        return "Yoruba"
    if any(re.search(rf"\b{re.escape(term)}\b", folded) for term in PIDGIN_TERMS):
        return "Pidgin"
    return "English"


def extract_location(text: str) -> dict[str, str]:
    folded = text.casefold()
    matches: list[tuple[int, int, str, str]] = []
    explicit_states = [
        (folded.index(state.casefold()), state)
        for state in STATE_GAZETTEER
        if re.search(rf"(?<!\w){re.escape(state.casefold())}(?!\w)", folded)
    ]
    for state, places in STATE_GAZETTEER.items():
        for place in set(places) | {state.casefold()}:
            if re.search(rf"(?<!\w){re.escape(place)}(?!\w)", folded):
                matches.append((folded.index(place), -len(place), state, place))
    if not matches:
        return {"state": "", "lga": ""}
    local_matches = [match for match in matches if match[3] != match[2].casefold()]
    if explicit_states:
        explicit_names = {state for _, state in explicit_states}
        local_matches = [match for match in local_matches if match[2] in explicit_names]
        if not local_matches:
            _, state = min(explicit_states)
            return {"state": state, "lga": ""}
    _, _, matched_state, matched_place = min(local_matches or matches)
    matched_lga = "" if matched_place == matched_state.casefold() else matched_place.title()
    return {"state": matched_state, "lga": matched_lga}


def stable_id(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:20]


class Connector:
    def __init__(self, connector_id: str, name: str, category: str, configured: bool = True,
                 note: str = "") -> None:
        self.id = connector_id
        self.name = name
        self.category = category
        self.configured = configured
        self.enabled = True
        self.status = "not configured" if not configured else "not configured"
        self.note = note
        self.last_run = ""
        self.item_count = 0
        self.last_error = ""
        self.lock = threading.Lock()

    def fetch(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    def get_items(self) -> list[dict[str, Any]]:
        if not self.enabled or not self.configured:
            self.status = "not configured"
            self.item_count = 0
            return []
        self.last_run = utc_now()
        try:
            items = self.fetch()
            self.status = "active"
            self.last_error = ""
            self.item_count = len(items)
            return items
        except Exception as exc:  # Connector boundary: retain explicit failing status, keep other plug-ins running.
            self.status = "failing"
            if isinstance(exc, urllib.error.HTTPError):
                message = f"HTTP Error {exc.code}: {exc.reason}"
                if exc.code == 403:
                    message += "; confirm the publisher permits this public feed or contact the publisher for access."
                elif exc.code == 429:
                    message += "; provider rate limit reached; next automatic attempt is in 12 minutes."
            elif isinstance(exc, urllib.error.URLError):
                message = f"Network error: {exc.reason}"
            elif isinstance(exc, TimeoutError):
                message = f"Request timed out after {REQUEST_TIMEOUT_SECONDS} seconds."
            else:
                message = str(exc).strip() or f"{type(exc).__name__} while fetching source"
            for name in ("token", "password", "api_key"):
                secret = getattr(self, name, "")
                if secret:
                    message = message.replace(secret, "[REDACTED]")
            self.last_error = clean_text(message, 180)
            self.item_count = 0
            print(f"[connector:{self.id}] failing: {self.last_error}", flush=True)
            return []

    def state(self) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "category": self.category,
            "status": self.status, "enabled": self.enabled, "configured": self.configured, "note": self.note,
            "lastRun": self.last_run, "itemCount": self.item_count,
            "error": self.last_error,
        }


def request_bytes(url: str, headers: dict[str, str] | None = None) -> bytes:
    request_headers = {
        "User-Agent": "NSP-EarlyWarning-Prototype/1.0 (public-feed reader)",
        "Accept": "application/rss+xml, application/atom+xml, application/json, text/xml, */*",
    }
    request_headers.update(headers or {})
    request = urllib.request.Request(url, headers=request_headers)
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        payload = response.read(MAX_FEED_BYTES + 1)
    if len(payload) > MAX_FEED_BYTES:
        raise ValueError("Response exceeded the configured size limit")
    return payload


def request_json(url: str, headers: dict[str, str]) -> dict[str, Any]:
    try:
        payload = request_bytes(url, headers)
    except urllib.error.HTTPError as exc:
        body = exc.read(MAX_FEED_BYTES)
        try:
            error = json.loads(body).get("error", {})
            message = error.get("message", "") if isinstance(error, dict) else ""
        except (json.JSONDecodeError, UnicodeDecodeError):
            message = ""
        if message:
            raise ValueError(f"Provider API error {exc.code}: {message}") from exc
        raise
    try:
        result = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError("Provider API returned a non-JSON response.") from exc
    if not isinstance(result, dict):
        raise ValueError("Provider API returned an unexpected response.")
    return result


def parse_feed(data: bytes, connector: Connector) -> list[dict[str, Any]]:
    root = ET.fromstring(data)
    items = []
    for element in root.iter():
        tag = element.tag.split("}")[-1].lower()
        if tag not in {"item", "entry"}:
            continue
        fields = {}
        for child in element:
            child_tag = child.tag.split("}")[-1].lower()
            if child_tag == "link":
                fields[child_tag] = child.attrib.get("href") or child.text or ""
            elif child_tag in {"title", "description", "summary", "content", "pubdate", "published", "updated"}:
                fields[child_tag] = "".join(child.itertext())
        title = clean_public_text(fields.get("title", ""), 220)
        summary = clean_public_text(fields.get("description") or fields.get("summary") or fields.get("content") or "", 500)
        snippet = clean_public_text(f"{title}. {summary}".strip(". "), 700)
        link = fields.get("link", "").strip()
        if not snippet or not link.startswith(("https://", "http://")):
            continue
        timestamp = safe_datetime(fields.get("pubdate") or fields.get("published") or fields.get("updated") or "")
        items.append({
            "platform": connector.name,
            "category": connector.category,
            "headline": title,
            "snippet": snippet,
            "link": link,
            "timestamp": timestamp,
            "location": extract_location(snippet),
            "language": detect_language(snippet),
            "engagement": {"likes": 0, "shares": 0, "comments": 0},
            "sourceKey": connector.id,
            "domain": urllib.parse.urlparse(link).hostname or "",
        })
    return items


class RSSConnector(Connector):
    def __init__(self, connector_id: str, name: str, url: str) -> None:
        super().__init__(connector_id, name, "News", note="Public RSS feed")
        self.url = url

    def fetch(self) -> list[dict[str, Any]]:
        return parse_feed(request_bytes(self.url), self)


class GDELTConnector(Connector):
    def __init__(self) -> None:
        super().__init__("gdelt", "GDELT", "Other", note="Free global news events API, queried for Nigeria and Nigerian states")
        state_query = " OR ".join(f'"{state}"' for state in STATE_GAZETTEER)
        query = f"({KEYWORDS}) (Nigeria OR Nigerian OR {state_query})"
        self.url = "https://api.gdeltproject.org/api/v2/doc/doc?" + urllib.parse.urlencode({
            "query": query, "mode": "ArtList", "format": "json", "maxrecords": "100",
            "sort": "HybridRel", "timespan": "24h",
        })

    def fetch(self) -> list[dict[str, Any]]:
        try:
            payload = json.loads(request_bytes(self.url))
        except json.JSONDecodeError as exc:
            raise ValueError("GDELT returned a non-JSON response; check its public API availability or rate-limit response.") from exc
        articles = payload.get("articles", [])
        items = []
        for article in articles:
            snippet = clean_public_text(f"{article.get('title', '')}. {article.get('description', '')}", 700)
            link = article.get("url", "")
            if not snippet or not link.startswith(("https://", "http://")):
                continue
            items.append({
                "platform": self.name, "category": self.category, "headline": clean_public_text(article.get("title", ""), 220), "snippet": snippet,
                "link": link, "timestamp": safe_datetime(article.get("seendate", "")),
                "location": extract_location(snippet),
                "language": article.get("language") or detect_language(snippet),
                "engagement": {"likes": 0, "shares": 0, "comments": 0},
                "sourceKey": self.id, "domain": article.get("domain", ""),
            })
        return items


class XRecentSearchConnector(Connector):
    SEARCH_URL = "https://api.x.com/2/tweets/search/recent"
    SEARCH_QUERY = (
        '("Nigeria" OR "Nigerian") '
        '(threat OR threatened OR attack OR attacked OR violence OR violent OR '
        'kidnapping OR kidnapped OR abducted OR bomb OR explosion OR gunmen OR '
        'clash OR riot OR protest OR shooting OR gunfire OR massacre OR murder) -is:retweet'
    )

    def __init__(self, bearer_token: str) -> None:
        super().__init__(
            "x-official-api", "X", "X", bool(bearer_token),
            "Recent public posts matching Nigeria and threat/violence terms; API access required",
        )
        self.token = bearer_token

    def fetch(self) -> list[dict[str, Any]]:
        query = urllib.parse.urlencode({
            "query": self.SEARCH_QUERY,
            "max_results": "100",
            "tweet.fields": "created_at,lang,public_metrics",
        })
        payload = request_json(
            f"{self.SEARCH_URL}?{query}",
            {"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
        )
        items = []
        for post in payload.get("data", []):
            text = clean_public_text(post.get("text", ""), 700)
            post_id = str(post.get("id", ""))
            if not text or not post_id.isdigit():
                continue
            metrics = post.get("public_metrics") or {}
            items.append({
                "platform": self.name, "category": self.category,
                "headline": clean_public_text(text, 220), "snippet": text,
                "link": f"https://x.com/i/web/status/{post_id}",
                "timestamp": safe_datetime(post.get("created_at", "")),
                "location": extract_location(text),
                "language": post.get("lang") or detect_language(text),
                "engagement": {
                    "likes": int(metrics.get("like_count", 0) or 0),
                    "shares": int(metrics.get("retweet_count", 0) or 0),
                    "comments": int(metrics.get("reply_count", 0) or 0),
                },
                "sourceKey": self.id, "domain": "x.com",
            })
        return items


class MetaGraphConnector(Connector):
    def __init__(self, connector_id: str, name: str, token: str) -> None:
        category = name
        note = (
            "Authorized Facebook Page posts; requires a Page access token and approved permissions"
            if name == "Facebook" else
            "Media from the Page's linked Instagram professional account; no public-platform search"
        )
        super().__init__(connector_id, name, category, bool(token), note)
        self.token = token
        self.base_url = f"https://graph.facebook.com/{META_GRAPH_API_VERSION}"

    def _get(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        url = f"{self.base_url}/{path.lstrip('/')}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        return request_json(
            url, {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        )

    def fetch(self) -> list[dict[str, Any]]:
        if self.name == "Facebook":
            response = self._get("me/feed", {
                "fields": "message,permalink_url,created_time,is_published",
                "limit": "100",
            })
            posts = response.get("data", [])
            fields = ("message", "permalink_url", "created_time")
        else:
            page = self._get("me", {"fields": "id,instagram_business_account"})
            instagram = page.get("instagram_business_account")
            instagram_id = instagram.get("id") if isinstance(instagram, dict) else None
            if not instagram_id:
                raise ValueError(
                    "The Meta token has no linked Instagram professional account; "
                    "connect one to its Facebook Page and grant instagram_basic."
                )
            response = self._get(f"{urllib.parse.quote(str(instagram_id), safe='')}/media", {
                "fields": "caption,permalink,timestamp",
                "limit": "100",
            })
            posts = response.get("data", [])
            fields = ("caption", "permalink", "timestamp")

        items = []
        for post in posts:
            if self.name == "Facebook" and post.get("is_published") is False:
                continue
            text = clean_public_text(post.get(fields[0], ""), 700)
            link = post.get(fields[1], "")
            if not text or not link.startswith(("https://", "http://")):
                continue
            items.append({
                "platform": self.name, "category": self.category,
                "headline": clean_public_text(text, 220), "snippet": text,
                "link": link, "timestamp": safe_datetime(post.get(fields[2], "")),
                "location": extract_location(text), "language": detect_language(text),
                "engagement": {"likes": 0, "shares": 0, "comments": 0},
                "sourceKey": self.id, "domain": urllib.parse.urlparse(link).hostname or "",
            })
        return items


def canonical_article_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    query = [
        (key, item) for key, item in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if not key.casefold().startswith("utm_")
        and key.casefold() not in {"fbclid", "gclid", "mc_cid", "mc_eid"}
    ]
    return urllib.parse.urlunsplit((
        parsed.scheme.casefold(), parsed.netloc.casefold(), parsed.path.rstrip("/") or "/",
        urllib.parse.urlencode(query), "",
    ))


def persist_and_load_source_items(items: list[dict[str, Any]], now: float | None = None) -> tuple[list[dict[str, Any]], int]:
    current_time = now if now is not None else time.time()
    connection = sqlite3.connect(DB_PATH, timeout=10)
    try:
        before = connection.total_changes
        rows = []
        for item in items:
            canonical_url = canonical_article_url(item.get("link", ""))
            if not canonical_url:
                continue
            fingerprint = stable_id(canonical_url)
            persisted_item = {key: value for key, value in item.items() if not key.startswith("_")}
            rows.append((
                fingerprint, item["sourceKey"], canonical_url, item.get("headline", ""),
                item.get("snippet", ""), item.get("timestamp", ""),
                json.dumps(persisted_item, ensure_ascii=False), current_time,
            ))
        connection.executemany(
            """INSERT OR IGNORE INTO source_items
               (fingerprint, source_key, canonical_url, headline, snippet, published_at, item_json, first_seen_epoch)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )
        inserted = connection.total_changes - before
        connection.commit()
        stored = connection.execute(
            """SELECT item_json, first_seen_epoch FROM source_items
               WHERE first_seen_epoch >= ? ORDER BY first_seen_epoch DESC""",
            (current_time - 24 * 60 * 60,),
        ).fetchall()
    finally:
        connection.close()
    loaded = []
    for item_json, first_seen in stored:
        item = json.loads(item_json)
        item["_seenAt"] = first_seen
        loaded.append(item)
    return loaded, inserted


def make_connectors() -> list[Connector]:
    connectors = [
        RSSConnector("news-punch", "Punch", "https://punchng.com/feed/"),
        RSSConnector("news-vanguard", "Vanguard", "https://www.vanguardngr.com/feed/"),
        RSSConnector("news-premium-times", "Premium Times", "https://www.premiumtimesng.com/feed/"),
        RSSConnector("news-channels", "Channels TV", "https://www.channelstv.com/feed/"),
        RSSConnector("news-daily-trust", "Daily Trust", "https://dailytrust.com/feed/"),
        RSSConnector("news-the-nation", "The Nation", "https://thenationonlineng.net/feed/"),
        RSSConnector("news-guardian", "Guardian Nigeria", "https://guardian.ng/feed/"),
        RSSConnector("news-bbc-pidgin", "BBC Pidgin", "https://feeds.bbci.co.uk/pidgin/rss.xml"),
        GDELTConnector(),
        Connector("google-news", "Google News RSS", "Google", False,
                  "Stub only; not configured for this checklist scope"),
        Connector("google-programmable-search", "Google Programmable Search", "Google", False,
                  "Stub only; not configured for this checklist scope"),
        Connector("google-trends", "Google Trends aggregate", "Google", False,
                  "Stub only; not configured for this checklist scope"),
        MetaGraphConnector("facebook-pages", "Facebook", META_PAGE_ACCESS_TOKEN),
        MetaGraphConnector("instagram-graph", "Instagram", META_PAGE_ACCESS_TOKEN),
        XRecentSearchConnector(X_BEARER_TOKEN),
        Connector("tiktok-api", "TikTok", "Other", False,
                  "Stub only; not configured for this checklist scope"),
        Connector("youtube-data-api", "YouTube", "Other", False,
                  "Stub only; not configured for this checklist scope"),
        Connector("acled", "ACLED", "Other", False,
                  "Stub only; not configured for this checklist scope"),
        Connector("citizen-tips", "Citizen tips", "Other", False,
                  "Stub only; not configured for this checklist scope"),
    ]
    return connectors


CONNECTORS = {connector.id: connector for connector in make_connectors()}
PIPELINE_LOCK = threading.Lock()
STATE_LOCK = threading.Lock()
LATEST_ITEMS: list[dict[str, Any]] = []
ITEM_WINDOW: dict[str, dict[str, Any]] = {}
ALERTS: list[dict[str, Any]] = []
PENDING_HIGH: dict[str, dict[str, Any]] = {}
LAST_PIPELINE_RUN = ""
PIPELINE_ERROR = ""
PREVIOUS_EVENT_COUNTS: dict[tuple[str, str], int] = {}
REVIEW_DECISIONS: dict[str, dict[str, str]] = {}


def audit_event(who: str, action: str, reason: str, case_ref: str = "—", details: dict[str, Any] | None = None) -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=5)
    try:
        connection.execute(
            "INSERT INTO audit_log (when_utc, who, action, case_ref, reason, details_json) VALUES (?, ?, ?, ?, ?, ?)",
            (utc_now(), clean_text(who, 80) or "UNKNOWN", clean_text(action, 220),
             clean_text(case_ref, 100) or "—", clean_text(reason, 500) or "Not provided",
             json.dumps(details or {}, ensure_ascii=False)),
        )
        connection.commit()
    finally:
        connection.close()


def send_family_verification_email(email: str, code: str) -> None:
    if not SMTP_HOST or not SMTP_FROM:
        raise RuntimeError("Family email verification is not configured. Set the NSP_SMTP_* settings in the local environment.")
    message = EmailMessage()
    message["Subject"] = "Your ROUGE family report verification code"
    message["From"] = SMTP_FROM
    message["To"] = email
    message.set_content(
        f"Your family report verification code is {code}.\n"
        "It expires in 10 minutes and can only be used once. "
        "If you did not request this code, you can ignore this message."
    )
    context = ssl.create_default_context()
    if SMTP_USE_SSL:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=context, timeout=15) as client:
            if SMTP_USERNAME:
                client.login(SMTP_USERNAME, SMTP_PASSWORD)
            client.send_message(message)
        return
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as client:
        client.ehlo()
        if SMTP_USE_STARTTLS:
            client.starttls(context=context)
            client.ehlo()
        if SMTP_USERNAME:
            client.login(SMTP_USERNAME, SMTP_PASSWORD)
        client.send_message(message)


def _case_event(
    connection: sqlite3.Connection,
    case_id: str,
    event_type: str,
    author: str,
    details: dict[str, Any],
    visibility: str = "all",
) -> None:
    connection.execute(
        """INSERT INTO case_events
           (case_id, event_type, author, created_epoch, visibility, details_json)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (case_id, event_type, clean_text(author, 100) or "UNKNOWN", time.time(),
         visibility, json.dumps(details, ensure_ascii=False)),
    )


def _case_notify(
    connection: sqlite3.Connection,
    case_id: str,
    assigned: list[str],
    roles: list[str],
    event_type: str,
    summary: str,
) -> None:
    targets = [(service, "official") for service in assigned]
    targets.extend((role, "role") for role in roles)
    for recipient, kind in dict.fromkeys(targets):
        connection.execute(
            """INSERT INTO case_notifications
               (id, case_id, recipient, recipient_kind, event_type, summary, created_epoch)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (f"CN-{uuid.uuid4().hex[:12].upper()}", case_id, recipient, kind,
             event_type, clean_text(summary, 240), time.time()),
        )


def _validate_case_photo(photo: Any) -> str:
    if not isinstance(photo, str):
        raise ValueError("Each case photo must be an image data URL.")
    match = re.fullmatch(r"data:image/(png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})", photo)
    if not match:
        raise ValueError("Case photos must be PNG, JPEG, or WebP images.")
    try:
        image_bytes = base64.b64decode(match.group(2), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValueError("A case photo has invalid image data.") from exc
    image_type = match.group(1)
    signature_valid = (
        image_bytes.startswith(b"\x89PNG\r\n\x1a\n") if image_type == "png"
        else image_bytes.startswith(b"\xff\xd8\xff") if image_type == "jpeg"
        else len(image_bytes) >= 12 and image_bytes.startswith(b"RIFF") and image_bytes[8:12] == b"WEBP"
    )
    if not image_bytes or len(image_bytes) > MAX_CASE_PHOTO_BYTES or not signature_valid:
        raise ValueError("Each case photo must be a valid PNG, JPEG, or WebP file no larger than 2 MB.")
    return photo


def _normalise_case_payload(payload: dict[str, Any], family: bool) -> dict[str, Any]:
    case_type = clean_text(str(payload.get("caseType", "")), 60)
    if case_type not in CASE_TYPES:
        raise ValueError("Choose a supported missing-person case type.")
    person = payload.get("person")
    location = payload.get("location")
    circumstances = payload.get("circumstances")
    reporter = payload.get("reporter")
    consent = payload.get("consent")
    photos = payload.get("photos")
    if not all(isinstance(value, dict) for value in (person, location, circumstances, reporter, consent)):
        raise ValueError("Person, location, circumstances, reporter, and consent details are required.")
    if not isinstance(photos, list) or not 1 <= len(photos) <= 5:
        raise ValueError("Upload between one and five recent photos.")
    valid_photos = [_validate_case_photo(photo) for photo in photos]
    full_name = clean_text(str(person.get("fullName", "")), 120)
    other_names = person.get("otherNames", [])
    if not full_name or not isinstance(other_names, list) or len(other_names) > 20:
        raise ValueError("Provide the person's full name and a valid other-names list.")
    try:
        age_value = person.get("age")
        age = int(age_value) if age_value not in (None, "") else None
    except (TypeError, ValueError):
        raise ValueError("Age must be a whole number.") from None
    dob = clean_text(str(person.get("dateOfBirth", "")), 10)
    if age is not None and not 0 <= age <= 120:
        raise ValueError("Age must be between 0 and 120.")
    if age is None and not dob:
        raise ValueError("Provide an age or date of birth.")
    if dob:
        try:
            datetime.strptime(dob, "%Y-%m-%d")
        except ValueError:
            raise ValueError("Date of birth must use YYYY-MM-DD format.") from None
    if age is not None and dob:
        raise ValueError("Provide age or date of birth, not both.")
    sex = clean_text(str(person.get("sex", "")), 40)
    if sex not in {"Female", "Male", "Other", "Not known"}:
        raise ValueError("Choose a supported sex option.")
    accuracy = clean_text(str(location.get("accuracy", "")), 20)
    if accuracy not in {"exact", "area", "unsure"}:
        raise ValueError("Choose exact, area, or unsure location accuracy.")
    place_name = clean_text(str(location.get("placeName", "")), 180)
    state = clean_text(str(location.get("state", "")), 80)
    lga = clean_text(str(location.get("lga", "")), 80)
    if not place_name or not state:
        raise ValueError("Provide the last-known place and state.")
    latitude, longitude = location.get("latitude"), location.get("longitude")
    if (latitude is None) != (longitude is None):
        raise ValueError("Map pin must include both latitude and longitude.")
    if latitude is not None:
        try:
            latitude, longitude = float(latitude), float(longitude)
        except (TypeError, ValueError):
            raise ValueError("Map pin coordinates must be numeric.") from None
        if not (NIGERIA_BOUNDS["minLat"] <= latitude <= NIGERIA_BOUNDS["maxLat"]
                and NIGERIA_BOUNDS["minLon"] <= longitude <= NIGERIA_BOUNDS["maxLon"]):
            raise ValueError("The map pin must be within Nigeria.")
    if accuracy == "unsure":
        latitude = longitude = None
    happened = clean_text(str(circumstances.get("whatHappened", "")), 3000)
    if not happened:
        raise ValueError("Describe what happened.")
    if family and circumstances.get("ransomDemand"):
        raise ValueError("Only an authorised officer may record ransom information.")
    case_notes = clean_text(str(payload.get("caseNotes", "")), 8000)
    email = clean_text(str(reporter.get("email", "")), 254).casefold()
    phone = clean_text(str(reporter.get("phone", "")), 40)
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise ValueError("Provide a valid email address for verification and updates.")
    if not phone:
        raise ValueError("Provide a reporter phone number.")
    languages = person.get("languages", [])
    if not isinstance(languages, list):
        raise ValueError("Languages spoken must be a list.")
    if consent.get("accuracyConfirmed") is not True or consent.get("authorisedToReport") is not True:
        raise ValueError("Confirm the report is accurate and you are authorised to report it.")
    if (age is not None and age >= 18) and consent.get("adultOnBehalf") is not True:
        raise ValueError("For an adult, confirm you are reporting on their behalf and understand the privacy notice.")
    return {
        "caseType": case_type,
        "person": {
            "fullName": full_name,
            "otherNames": [clean_text(str(name), 120) for name in other_names if clean_text(str(name), 120)],
            "age": age, "dateOfBirth": dob, "sex": sex,
            "height": clean_text(str(person.get("height", "")), 30),
            "distinguishingMarks": clean_text(str(person.get("distinguishingMarks", "")), 1000),
            "clothingLastSeen": clean_text(str(person.get("clothingLastSeen", "")), 1000),
            "medicalNeeds": clean_text(str(person.get("medicalNeeds", "")), 1000),
            "languages": [clean_text(str(language), 60) for language in languages
                          if clean_text(str(language), 60)][:20],
            "nin": clean_text(str(person.get("nin", "")), 32),
        },
        "photos": valid_photos,
        "photoChecks": payload.get("photoChecks", [])[:5] if isinstance(payload.get("photoChecks"), list) else [],
        "location": {
            "placeName": place_name, "state": state, "lga": lga,
            "latitude": latitude, "longitude": longitude,
            "time": clean_text(str(location.get("time", "")), 40),
            "accuracy": accuracy,
        },
        "circumstances": {
            "whatHappened": happened,
            "lastWith": clean_text(str(circumstances.get("lastWith", "")), 500),
            "vehicleDetails": clean_text(str(circumstances.get("vehicleDetails", "")), 500),
            "ransomDemand": clean_text(str(circumstances.get("ransomDemand", "")), 1000) if not family else "",
        },
        "reporter": {
            "name": clean_text(str(reporter.get("name", "")), 120),
            "relationship": clean_text(str(reporter.get("relationship", "")), 80),
            "phone": phone, "email": email,
        },
        # Free-text officer record of the case. Family submissions may not set it.
        "caseNotes": "" if family else case_notes,
        "consent": {
            "accuracyConfirmed": True, "authorisedToReport": True,
            "adultOnBehalf": bool(consent.get("adultOnBehalf")),
        },
    }


def initialise_database() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=5)
    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                when_utc TEXT NOT NULL,
                who TEXT NOT NULL,
                action TEXT NOT NULL,
                case_ref TEXT NOT NULL,
                reason TEXT NOT NULL,
                details_json TEXT NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS source_items (
                fingerprint TEXT PRIMARY KEY,
                source_key TEXT NOT NULL,
                canonical_url TEXT NOT NULL UNIQUE,
                headline TEXT NOT NULL,
                snippet TEXT NOT NULL,
                published_at TEXT NOT NULL,
                item_json TEXT NOT NULL,
                first_seen_epoch REAL NOT NULL
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS source_items_first_seen ON source_items(first_seen_epoch)"
        )
        connection.execute("""
            CREATE TABLE IF NOT EXISTS link_location_requests (
                id TEXT PRIMARY KEY,
                requester TEXT NOT NULL,
                legal_authorization TEXT NOT NULL,
                case_ref TEXT NOT NULL,
                reason TEXT NOT NULL,
                period_start TEXT NOT NULL,
                period_end TEXT NOT NULL,
                people_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_epoch REAL NOT NULL,
                reviewer TEXT,
                decision_reason TEXT,
                expires_epoch REAL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS saved_link_boards (
                id TEXT PRIMARY KEY,
                who TEXT NOT NULL,
                case_ref TEXT NOT NULL,
                reason TEXT NOT NULL,
                board_json TEXT NOT NULL,
                saved_epoch REAL NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS app_workspace (
                workspace_id TEXT PRIMARY KEY,
                data_json TEXT NOT NULL,
                updated_epoch REAL NOT NULL
            )
        """)
        connection.execute("""
            CREATE TABLE IF NOT EXISTS official_access (
                service_key TEXT PRIMARY KEY,
                service_number TEXT NOT NULL,
                full_name TEXT NOT NULL,
                official_type TEXT NOT NULL,
                agency_unit TEXT NOT NULL,
                passcode_salt TEXT NOT NULL,
                passcode_hash TEXT NOT NULL,
                photo_data TEXT NOT NULL,
                fingerprint_enrolled INTEGER NOT NULL CHECK (fingerprint_enrolled = 1),
                status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled')),
                requested_epoch REAL NOT NULL,
                reviewer TEXT,
                reviewed_epoch REAL
            )
        """)
        connection.execute(
            "CREATE INDEX IF NOT EXISTS official_access_status ON official_access(status, requested_epoch)"
        )
        supervisor_key = DEMO_SUPERVISOR_SERVICE_NUMBER.casefold()
        existing_supervisor = connection.execute(
            "SELECT 1 FROM official_access WHERE service_key=?", (supervisor_key,)
        ).fetchone()
        if not existing_supervisor:
            salt = secrets.token_bytes(16)
            passcode_hash = hashlib.pbkdf2_hmac(
                "sha256", DEMO_SUPERVISOR_PASSCODE.encode("utf-8"),
                salt, PASSCODE_ITERATIONS,
            )
            connection.execute(
                """INSERT INTO official_access
                   (service_key, service_number, full_name, official_type, agency_unit,
                    passcode_salt, passcode_hash, photo_data, fingerprint_enrolled,
                    status, requested_epoch, reviewer, reviewed_epoch)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'approved', ?, ?, ?)""",
                (supervisor_key, DEMO_SUPERVISOR_SERVICE_NUMBER, "Demo Supervisor",
                 "Military intelligence", "Prototype supervisor access",
                 salt.hex(), passcode_hash.hex(), "", time.time(),
                 "Prototype default account", time.time()),
            )
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS family_verifications (
                id TEXT PRIMARY KEY,
                email_key TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                created_epoch REAL NOT NULL,
                expires_epoch REAL NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                verified_token_hash TEXT,
                verified_epoch REAL,
                consumed_epoch REAL
            );
            CREATE INDEX IF NOT EXISTS family_verifications_email_time
                ON family_verifications(email_key, created_epoch);
            CREATE INDEX IF NOT EXISTS family_verifications_ip_time
                ON family_verifications(client_ip, created_epoch);
            CREATE TABLE IF NOT EXISTS family_submission_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email_key TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                created_epoch REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS family_submission_limits_email_time
                ON family_submission_limits(email_key, created_epoch);
            CREATE TABLE IF NOT EXISTS missing_cases (
                id TEXT PRIMARY KEY,
                public_ref TEXT NOT NULL UNIQUE,
                source TEXT NOT NULL CHECK (source IN ('officer', 'family')),
                case_type TEXT NOT NULL,
                person_json TEXT NOT NULL,
                photos_json TEXT NOT NULL,
                location_json TEXT NOT NULL,
                circumstances_json TEXT NOT NULL,
                reporter_json TEXT NOT NULL,
                consent_json TEXT NOT NULL,
                status TEXT NOT NULL,
                verified INTEGER NOT NULL DEFAULT 0,
                priority TEXT NOT NULL,
                priority_reason TEXT NOT NULL,
                assigned_json TEXT NOT NULL,
                border_watch INTEGER NOT NULL DEFAULT 0,
                notes TEXT NOT NULL DEFAULT '',
                created_epoch REAL NOT NULL,
                updated_epoch REAL NOT NULL,
                stale_alerted_epoch REAL NOT NULL DEFAULT 0,
                family_token_hash TEXT
            );
            CREATE INDEX IF NOT EXISTS missing_cases_order
                ON missing_cases(status, priority, created_epoch);
            CREATE TABLE IF NOT EXISTS case_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id TEXT NOT NULL REFERENCES missing_cases(id),
                event_type TEXT NOT NULL,
                author TEXT NOT NULL,
                created_epoch REAL NOT NULL,
                visibility TEXT NOT NULL DEFAULT 'all',
                details_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS case_events_case_time ON case_events(case_id, created_epoch);
            CREATE TABLE IF NOT EXISTS case_notifications (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL REFERENCES missing_cases(id),
                recipient TEXT NOT NULL,
                recipient_kind TEXT NOT NULL,
                event_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                created_epoch REAL NOT NULL,
                acknowledged_by TEXT,
                acknowledged_epoch REAL
            );
            CREATE INDEX IF NOT EXISTS case_notifications_recipient_time
                ON case_notifications(recipient, acknowledged_epoch, created_epoch);
            CREATE TABLE IF NOT EXISTS case_area_alerts (
                id TEXT PRIMARY KEY,
                case_id TEXT NOT NULL REFERENCES missing_cases(id),
                author TEXT NOT NULL,
                area_json TEXT NOT NULL,
                units_json TEXT NOT NULL,
                summary TEXT NOT NULL,
                instructions TEXT NOT NULL,
                photo_data TEXT NOT NULL,
                created_epoch REAL NOT NULL,
                acknowledgements_json TEXT NOT NULL
            );
        """)
        connection.executescript("""
            CREATE TRIGGER IF NOT EXISTS audit_no_update
            BEFORE UPDATE ON audit_log BEGIN
                SELECT RAISE(ABORT, 'audit log is append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS audit_no_delete
            BEFORE DELETE ON audit_log BEGIN
                SELECT RAISE(ABORT, 'audit log is append-only');
            END;
        """)
        # Migrate databases created before the officer case-notebook column existed.
        case_columns = {row[1] for row in connection.execute("PRAGMA table_info(missing_cases)")}
        if "notes" not in case_columns:
            connection.execute("ALTER TABLE missing_cases ADD COLUMN notes TEXT NOT NULL DEFAULT ''")
        connection.commit()
    finally:
        connection.close()


def simulated_items() -> list[dict[str, Any]]:
    now = utc_now()
    examples = [
        ("Fictional community bulletin reports a simulated road closure after a loud blast in Demo District, Kaduna.",
         "https://example.invalid/simulated/kaduna-1", "Kaduna", "Zaria"),
        ("Simulated local notice: fictional residents report a temporary curfew following an unverified clash in Sample Ward, Kaduna.",
         "https://example.invalid/simulated/kaduna-2", "Kaduna", "Zaria"),
        ("SIMULATED DATA: invented reports describe a protest in Example Town, Kano; no real incident is asserted.",
         "https://example.invalid/simulated/kano-1", "Kano", "Kano"),
    ]
    return [{
        "platform": "SIMULATED DATA", "category": "Other", "headline": clean_text(snippet, 220), "snippet": snippet, "link": link,
        "timestamp": now, "location": {"state": state, "lga": lga}, "language": "English",
        "engagement": {"likes": 0, "shares": 0, "comments": 0},
        "sourceKey": "simulated-fallback", "domain": "example.invalid", "simulated": True,
    } for snippet, link, state, lga in examples]


def normalised_key(item: dict[str, Any]) -> tuple[str, ...]:
    words = re.findall(r"[a-z0-9]+", item.get("headline") or item["snippet"].casefold())
    meaningful = [word for word in words if (len(word) > 3 or word.isdigit()) and word not in {"report", "according", "nigeria"}]
    return tuple(sorted(set(meaningful)))


def similarity(left: tuple[str, ...], right: tuple[str, ...]) -> float:
    if not left or not right:
        return 0.0
    a, b = set(left), set(right)
    return len(a & b) / len(a | b)


def same_event(item: dict[str, Any], cluster: list[dict[str, Any]], item_key: tuple[str, ...]) -> bool:
    for candidate in cluster:
        if classify(item["snippet"]) != classify(candidate["snippet"]):
            continue
        if item["location"].get("state") != candidate["location"].get("state"):
            continue
        candidate_key = set(normalised_key(candidate))
        common = set(item_key) & candidate_key
        if similarity(item_key, tuple(candidate_key)) >= 0.62:
            return True
        shared_numbers = {word for word in common if word.isdigit()}
        if shared_numbers and len(common) >= 3:
            return True
        if len(common) >= 3 and len(common) / max(1, min(len(item_key), len(candidate_key))) >= 0.55:
            return True
    return False


def confidence_for(items: list[dict[str, Any]], category: str, volume_rising: bool) -> tuple[str, list[str]]:
    independent = {item["domain"] or item["sourceKey"] for item in items}
    credible = any(any(domain == known or domain.endswith("." + known) for known in CREDIBLE_NEWS_DOMAINS)
                   for domain in independent)
    verified_match = any(item["sourceKey"] in {"gdelt", "acled"} for item in items)
    reasons = [f"{len(independent)} independent source(s)"]
    if credible:
        reasons.append("credible news outlet matched")
    if verified_match:
        reasons.append("GDELT/ACLED comparison matched")
    if volume_rising:
        reasons.append("local report volume is rising versus the previous pipeline window")
    if len(independent) >= 3 and credible and verified_match:
        return "High", reasons
    if len(independent) >= 2 or (credible and verified_match) or (volume_rising and len(independent) >= 2):
        return "Medium", reasons
    if not credible and any(item["category"] in {"Facebook", "Instagram", "X"} for item in items):
        reasons.append("no news confirmation; social-only claim")
    else:
        reasons.append("limited independent confirmation")
    return "Low", reasons


def make_alert(cluster: list[dict[str, Any]]) -> dict[str, Any] | None:
    classifications = [classify(item["snippet"]) for item in cluster]
    classifications = [item for item in classifications if item]
    if not classifications:
        return None
    category = Counter(classifications).most_common(1)[0][0]
    combined = " ".join(item["snippet"] for item in cluster)
    location = next((item["location"] for item in cluster if item["location"].get("state")), {"state": "", "lga": ""})
    location_key = location.get("state") or "unknown"
    current_count = sum(
        len([item for item in cluster if item["location"].get("state") == location.get("state")])
        for _ in (0,)
    )
    previous_count = PREVIOUS_EVENT_COUNTS.get((location_key, category), 0)
    volume_rising = current_count >= max(3, previous_count * 1.5) and current_count > previous_count
    confidence, reasons = confidence_for(cluster, category, volume_rising)
    sources = []
    for source_name in sorted({item["platform"] for item in cluster}):
        matching = [item for item in cluster if item["platform"] == source_name]
        sources.append({
            "platform": source_name, "category": matching[0]["category"],
            "count": len(matching),
            "articles": [
                {
                    "headline": clean_text(item.get("headline") or item["snippet"].split(".")[0], 220),
                    "link": item["link"],
                }
                for item in matching[:5]
            ],
            "links": [item["link"] for item in matching[:5]],
        })
    snippet_key = "|".join(sorted(item["snippet"].casefold() for item in cluster))
    event_id = stable_id(snippet_key)
    social_only = bool(cluster) and all(item["category"] in {"Facebook", "Instagram", "X"} for item in cluster)
    recycled = len(cluster) > len({item["sourceKey"] for item in cluster}) or len({item["snippet"].casefold() for item in cluster}) == 1 and len(cluster) > 1
    time_candidates = sorted(item["timestamp"] for item in cluster if item["timestamp"])
    return {
        "id": event_id,
        "title": clean_text(cluster[0].get("headline") or cluster[0]["snippet"].split(".")[0], 180),
        "category": category,
        "snippet": clean_text(combined, 900),
        "location": location,
        "timestamp": time_candidates[-1] if time_candidates else utc_now(),
        "language": Counter(item["language"] for item in cluster).most_common(1)[0][0],
        "confidence": confidence,
        "confidenceReasons": reasons,
        "verificationLabel": "Unverified, social media only" if social_only else "",
        "sources": sources,
        "sourceCategories": sorted({item["category"] for item in cluster}),
        "sourceCount": sum(source["count"] for source in sources),
        "coordinatedOrRecycled": recycled,
        "simulated": any(item.get("simulated", False) for item in cluster),
        "requiresAnalystConfirmation": confidence == "High",
        "links": list(dict.fromkeys(item["link"] for item in cluster))[:8],
        "engagement": {
            key: sum(int(item["engagement"].get(key, 0) or 0) for item in cluster)
            for key in ("likes", "shares", "comments")
        },
        "_sourceKeys": sorted({item["sourceKey"] for item in cluster}),
    }


def run_pipeline(trigger: str = "scheduled") -> None:
    global LATEST_ITEMS, ITEM_WINDOW, ALERTS, PENDING_HIGH, LAST_PIPELINE_RUN, PIPELINE_ERROR, PREVIOUS_EVENT_COUNTS
    if not PIPELINE_LOCK.acquire(blocking=False):
        return
    try:
        fetched: list[dict[str, Any]] = []
        futures = []
        result_buckets: dict[str, list[dict[str, Any]]] = {key: [] for key in CONNECTORS}
        source_counts: dict[str, int] = {}
        executor = ThreadPoolExecutor(max_workers=12, thread_name_prefix="nsp-source")
        for connector_id, connector in CONNECTORS.items():
            if connector.enabled and connector.configured:
                futures.append((connector_id, executor.submit(connector.get_items)))
        for connector_id, future in futures:
            try:
                result_buckets[connector_id] = future.result(timeout=REQUEST_TIMEOUT_SECONDS + 2)
            except Exception as exc:
                CONNECTORS[connector_id].status = "failing"
                CONNECTORS[connector_id].last_error = clean_text(str(exc), 180)
            source_counts[connector_id] = len(result_buckets[connector_id])
        executor.shutdown(wait=False, cancel_futures=True)
        for bucket in result_buckets.values():
            fetched.extend(bucket)

        live_connector_count = sum(
            connector.enabled and connector.configured and connector.status == "active"
            for connector in CONNECTORS.values()
        )
        simulated = live_connector_count == 0
        if simulated:
            fetched = simulated_items()

        now = time.time()
        if simulated:
            fetched = [{**item, "_seenAt": now} for item in fetched]
            newly_stored = 0
        else:
            fetched, newly_stored = persist_and_load_source_items(fetched, now)
        with STATE_LOCK:
            ITEM_WINDOW = {
                stable_id(canonical_article_url(item.get("link", "")) or f"simulated|{item['link']}"): item
                for item in fetched
            }

        # Content-level duplicate clustering only; no account or author profiling.
        clusters: list[list[dict[str, Any]]] = []
        keys: list[tuple[str, ...]] = []
        for item in fetched:
            if not classify(item["snippet"]):
                continue
            if not item["location"].get("state"):
                continue
            item_key = normalised_key(item)
            target = next((index for index, cluster in enumerate(clusters) if same_event(item, cluster, item_key)), None)
            if target is None:
                keys.append(item_key)
                clusters.append([item])
            else:
                clusters[target].append(item)

        alerts: list[dict[str, Any]] = []
        pending: dict[str, dict[str, Any]] = {}
        next_counts: Counter[tuple[str, str]] = Counter()
        for cluster in clusters:
            alert = make_alert(cluster)
            if not alert:
                continue
            next_counts[(alert["location"].get("state") or "unknown", alert["category"])] += len(cluster)
            if alert["requiresAnalystConfirmation"]:
                decision = REVIEW_DECISIONS.get(alert["id"])
                if decision and decision["decision"] == "confirm":
                    alert["requiresAnalystConfirmation"] = False
                    alert["analystReview"] = {
                        "decision": "confirmed", "reviewer": decision["reviewer"], "time": decision["time"],
                    }
                    alerts.append(alert)
                elif not decision:
                    # High-confidence events remain out of the field feed until a human review.
                    pending[alert["id"]] = alert
                continue
            alerts.append(alert)
        with STATE_LOCK:
            # Retain non-expired alert clusters when a source has no new item during this window.
            current_ids = {alert["id"] for alert in alerts}
            for existing in ALERTS:
                if existing["id"] not in current_ids and existing.get("timestamp"):
                    if time.time() - (safe_datetime_epoch(existing["timestamp"]) or now) <= 24 * 60 * 60:
                        alerts.append(existing)
            for alert_id, existing in PENDING_HIGH.items():
                if alert_id not in pending and alert_id not in REVIEW_DECISIONS:
                    pending[alert_id] = existing
        alerts.sort(key=lambda item: (item["confidence"] == "Medium", item["timestamp"]), reverse=True)
        with STATE_LOCK:
            LATEST_ITEMS = fetched
            ALERTS = alerts
            PENDING_HIGH = pending
            LAST_PIPELINE_RUN = utc_now()
            PIPELINE_ERROR = ""
            PREVIOUS_EVENT_COUNTS = dict(next_counts)
        source_summary = ", ".join(
            f"{CONNECTORS[key].name}: fetched={source_counts.get(key, 0)} status={CONNECTORS[key].status}"
            for key in CONNECTORS if CONNECTORS[key].configured
        )
        print(
            f"[pipeline][{trigger}][{LAST_PIPELINE_RUN}] completed: "
            f"{len(alerts)} field alerts, {len(pending)} awaiting analyst review, "
            f"fetched={sum(source_counts.values())}, newly_stored={newly_stored}, simulated={simulated}; "
            f"sources: {source_summary}",
            flush=True,
        )
    except Exception as exc:
        PIPELINE_ERROR = clean_text(str(exc), 300)
        print(f"[pipeline] failing: {PIPELINE_ERROR}", flush=True)
    finally:
        PIPELINE_LOCK.release()


def pipeline_loop() -> None:
    while True:
        run_pipeline()
        time.sleep(PIPELINE_INTERVAL_SECONDS)


def public_state() -> dict[str, Any]:
    with STATE_LOCK:
        alerts = json.loads(json.dumps(ALERTS))
        last_run = LAST_PIPELINE_RUN
        pipeline_error = PIPELINE_ERROR
        pending_count = len(PENDING_HIGH)
    live_connector_count = sum(
        connector.enabled and connector.configured and connector.status == "active"
        for connector in CONNECTORS.values()
    )
    return {
        "alerts": alerts, "simulated": live_connector_count == 0,
        "generatedAt": last_run, "pipeline": {
            "intervalMinutes": PIPELINE_INTERVAL_SECONDS // 60,
            "lastRun": last_run, "running": PIPELINE_LOCK.locked(), "error": pipeline_error,
            "pendingHighCount": pending_count,
        },
        "connectors": [connector.state() for connector in CONNECTORS.values()],
    }


def latest_alert_review_statuses(alert_ids: set[str]) -> dict[str, dict[str, str]]:
    if not alert_ids:
        return {}
    connection = sqlite3.connect(DB_PATH, timeout=5)
    try:
        rows = connection.execute(
            """SELECT when_utc, action, details_json FROM audit_log
               WHERE action LIKE 'ALERT %' ORDER BY id DESC"""
        ).fetchall()
    finally:
        connection.close()
    statuses: dict[str, dict[str, str]] = {}
    for when_utc, event_action, details_json in rows:
        action = event_action.partition(" · ")[0].removeprefix("ALERT ").lower()
        if action not in {"acknowledge", "flag", "mark_false_alarm", "escalate"}:
            continue
        alert_id = json.loads(details_json).get("alertId")
        if alert_id in alert_ids and alert_id not in statuses:
            statuses[alert_id] = {"action": action, "updatedAt": when_utc}
            if len(statuses) == len(alert_ids):
                break
    return statuses


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        # Static assets are edited in place during development; force
        # revalidation so a normal refresh never serves a stale vf.js/index.html.
        self.send_header("Cache-Control", "no-cache, must-revalidate")
        super().end_headers()

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        request_path = urllib.parse.urlsplit(self.path).path
        limit = (
            32 * 1024 * 1024 if request_path == "/api/workspace"
            else 8 * 1024 * 1024 if request_path == "/api/access-requests"
            else 16 * 1024 * 1024 if request_path in {"/api/cases", "/api/family/cases"}
            else 16_384
        )
        if length > limit:
            raise ValueError(f"Request body exceeds the {limit}-byte limit.")
        body = json.loads(self.rfile.read(length))
        if not isinstance(body, dict):
            raise ValueError("JSON body must be an object")
        return body

    @staticmethod
    def _official_access_json(row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "serviceNumber": row[0], "name": row[1], "officialType": row[2],
            "agencyUnit": row[3], "photo": row[4], "fingerprintEnrolled": bool(row[5]),
            "status": row[6], "requestedAt": int(row[7] * 1000),
            "reviewer": row[8], "reviewedAt": int(row[9] * 1000) if row[9] else None,
        }

    def _who(self) -> str:
        return clean_text(self.headers.get("X-NSP-Official", "UNKNOWN"), 80)

    def _require_demo_supervisor(self) -> bool:
        if self.headers.get("X-NSP-Supervisor") != "demo":
            self._json(403, {"error": "Supervisor demo mode is required for this action."})
            return False
        return True

    def _session_official(self) -> tuple[str, str] | None:
        """(service, official type) from a valid session, preferring the Bearer token.

        Image URLs carry the token as a query parameter because <img> cannot send
        headers; other calls send it as Authorization. Routes that must know who the
        analyst is use this instead of the spoofable X-NSP-Official header.
        """
        token = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if not token:
            token = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("token", [""])[0].strip()
        session = AUTH_SESSIONS.get(token)
        if not session or session["expires"] < time.time():
            return None
        return session["service"], session["type"]

    def _require_case_staff(self) -> str | None:
        token = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        # Plain <img src="..."> requests cannot set the Authorization or X-NSP-Official
        # headers, so the Visual Forensics viewer passes the session token as a query
        # parameter. In that case the official identity is taken from the session itself.
        token_from_query = False
        if not token:
            token = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get("token", [""])[0].strip()
            token_from_query = bool(token)
        session = AUTH_SESSIONS.get(token)
        if not session or session["expires"] < time.time():
            self._json(401, {"error": "A valid officer session for police or military intelligence is required to access case files."})
            return None
        official_type = session["type"] if token_from_query else self.headers.get("X-NSP-Official-Type", "")
        if (
            official_type not in CASE_STAFF_TYPES
            or session["service"] == ""
            or session["type"] != official_type
            # A token in the query string carries no headers, so the identity is the
            # session's own service number. Only header-authenticated requests are
            # matched against X-NSP-Official.
            or (not token_from_query and (
                self.headers.get("X-NSP-Official", "UNKNOWN") in {"", "UNKNOWN"}
                or session["service"].casefold() != self._who().casefold()))
        ):
            self._json(403, {"error": "A valid officer session for police or military intelligence is required to access case files."})
            return None
        return official_type

    def _require_session_roles(self, roles: set[str]) -> str | None:
        token = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        session = AUTH_SESSIONS.get(token)
        if (
            not session or session["expires"] < time.time()
            or session["type"] not in roles
            or session["service"].casefold() != self._who().casefold()
            or session["type"] != self.headers.get("X-NSP-Official-Type")
        ):
            self._json(401 if not session else 403, {"error": "A valid authorised official session is required for this action."})
            return None
        return session["type"]

    def _save_missing_case(
        self, payload: dict[str, Any], source: str, author: str,
        family_token_hash: str | None = None,
    ) -> dict[str, Any]:
        case = _normalise_case_payload(payload, family=source == "family")
        person = case["person"]
        priority = (
            "Critical" if case["caseType"] in {"Suspected kidnapping", "Abduction of a minor"}
            or person["age"] is not None and person["age"] < 18
            else "High" if person["medicalNeeds"] else "Normal"
        )
        priority_reason = (
            "Automatic time-critical default: minor or kidnapping case."
            if priority == "Critical" else
            "Automatic time-critical default: medical needs reported."
            if priority == "High" else "Default priority; officer review required."
        )
        case_id = f"MC-{uuid.uuid4().hex[:12].upper()}"
        reference = f"MP-{datetime.now(timezone.utc):%y%m%d}-{uuid.uuid4().hex[:6].upper()}"
        status = "New" if source == "family" else "Under review"
        now = time.time()
        connection = sqlite3.connect(DB_PATH, timeout=5)
        try:
            connection.execute(
                """INSERT INTO missing_cases
                   (id, public_ref, source, case_type, person_json, photos_json, location_json,
                    circumstances_json, reporter_json, consent_json, status, verified, priority,
                    priority_reason, assigned_json, created_epoch, updated_epoch, family_token_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, '[]', ?, ?, ?)""",
                (case_id, reference, source, case["caseType"],
                 json.dumps(case["person"], ensure_ascii=False),
                 json.dumps(case["photos"], ensure_ascii=False),
                 json.dumps(case["location"], ensure_ascii=False),
                 json.dumps(case["circumstances"], ensure_ascii=False),
                 json.dumps(case["reporter"], ensure_ascii=False),
                 json.dumps(case["consent"], ensure_ascii=False), status, priority,
                 priority_reason, now, now, family_token_hash),
            )
            if case.get("caseNotes"):
                connection.execute("UPDATE missing_cases SET notes=? WHERE id=?", (case["caseNotes"], case_id))
            _case_event(connection, case_id, "report_received", author,
                        {"status": status, "source": source, "photoChecks": case["photoChecks"]})
            if priority == "Critical":
                _case_notify(
                    connection, case_id, [], ["supervisor", *CASE_STAFF_TYPES],
                    "new_critical_case", f"New Critical {case['caseType'].lower()} case {reference}.",
                )
            if source == "family":
                _case_notify(
                    connection, case_id, [], ["supervisor", *CASE_STAFF_TYPES],
                    "family_report_received", f"New unverified family report {reference} requires review.",
                )
            connection.commit()
        finally:
            connection.close()
        audit_event(author, "MISSING-PERSON CASE REPORTED",
                    f"{'Family' if source == 'family' else 'Officer'} reported {case['caseType']}",
                    reference, {"caseId": case_id, "status": status, "priority": priority})
        return {"id": case_id, "reference": reference, "status": status,
                "priority": priority, "createdAt": int(now * 1000)}

    def _family_email_limits(self, email: str, client_ip: str, now: float) -> bool:
        connection = sqlite3.connect(DB_PATH, timeout=5)
        try:
            email_count = connection.execute(
                "SELECT COUNT(*) FROM family_verifications WHERE email_key=? AND created_epoch>?",
                (email, now - 15 * 60),
            ).fetchone()[0]
            ip_count = connection.execute(
                "SELECT COUNT(*) FROM family_verifications WHERE client_ip=? AND created_epoch>?",
                (client_ip, now - 15 * 60),
            ).fetchone()[0]
            recent = connection.execute(
                "SELECT created_epoch FROM family_verifications WHERE email_key=? ORDER BY created_epoch DESC LIMIT 1",
                (email,),
            ).fetchone()
        finally:
            connection.close()
        return email_count < 4 and ip_count < 10 and (not recent or now - recent[0] >= 60)

    @staticmethod
    def _case_public_status(case_row: tuple[Any, ...]) -> dict[str, Any]:
        return {
            "reference": case_row[0], "status": case_row[1],
            "updatedAt": int(case_row[2] * 1000),
        }

    @staticmethod
    def _case_row_json(row: tuple[Any, ...], detail: bool = False) -> dict[str, Any]:
        result = {
            "id": row[0], "reference": row[1], "source": row[2], "caseType": row[3],
            "person": json.loads(row[4]), "photoCount": len(json.loads(row[5])),
            "location": json.loads(row[6]), "status": row[7],
            "verified": bool(row[8]), "priority": row[9], "priorityReason": row[10],
            "assigned": json.loads(row[11]), "borderWatch": bool(row[12]),
            "createdAt": int(row[13] * 1000), "updatedAt": int(row[14] * 1000),
            "timeCritical": (
                row[3] in {"Suspected kidnapping", "Abduction of a minor"}
                or json.loads(row[4]).get("age") is not None and json.loads(row[4]).get("age") < 18
                or bool(json.loads(row[4]).get("medicalNeeds"))
            ),
        }
        if detail:
            result.update({
                "photos": json.loads(row[5]),
                "circumstances": json.loads(row[15]),
                "reporter": json.loads(row[16]),
                "consent": json.loads(row[17]),
                "caseNotes": row[18] or "",
            })
        return result

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path.startswith("/api/plate-search/"):
            import plate_reader
            if plate_reader.handle_get(self, path):
                return
        if path.startswith("/api/vf/"):
            import vf_routes
            if vf_routes.handle_vf_get(self, path):
                return
        if path == "/family-report":
            self.path = "/family_report.html"
            return super().do_GET()
        if path == "/api/cases/border-watch":
            if not self._require_session_roles({"Immigration officer"}):
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                rows = connection.execute(
                    """SELECT public_ref, case_type, status, location_json, updated_epoch
                       FROM missing_cases WHERE border_watch=1 AND status='Active'
                       ORDER BY updated_epoch DESC LIMIT 200"""
                ).fetchall()
            finally:
                connection.close()
            audit_event(self._who(), "CASE BORDER WATCH ALERTS VIEWED",
                        "Viewed border-watch alert summaries", details={"count": len(rows)})
            self._json(200, {"alerts": [
                {"reference": row[0], "caseType": row[1], "status": row[2],
                 "location": json.loads(row[3]), "updatedAt": int(row[4] * 1000)}
                for row in rows
            ]})
            return
        if path == "/api/cases/notifications":
            role = self._require_case_staff()
            if not role:
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                now = time.time()
                stale_rows = connection.execute(
                    """SELECT id, public_ref, assigned_json, stale_alerted_epoch FROM missing_cases
                       WHERE status='Active' AND priority='Critical' AND updated_epoch<=?
                         AND stale_alerted_epoch<?""",
                    (now - 24 * 60 * 60, now - 24 * 60 * 60),
                ).fetchall()
                for case_id, reference, assigned_json, _ in stale_rows:
                    assigned = json.loads(assigned_json)
                    _case_notify(connection, case_id, assigned, ["supervisor"], "stale_critical",
                                 f"Critical case {reference} has had no update for 24 hours.")
                    connection.execute(
                        "UPDATE missing_cases SET stale_alerted_epoch=? WHERE id=?", (now, case_id)
                    )
                rows = connection.execute(
                    """SELECT id, case_id, event_type, summary, created_epoch, acknowledged_by
                       FROM case_notifications
                       WHERE (recipient=? OR recipient=? OR (recipient_kind='role' AND recipient=?))
                       ORDER BY created_epoch DESC LIMIT 100""",
                    (self._who(), "supervisor", role),
                ).fetchall()
                connection.commit()
            finally:
                connection.close()
            self._json(200, {"notifications": [
                {"id": row[0], "caseId": row[1], "eventType": row[2], "summary": row[3],
                 "createdAt": int(row[4] * 1000), "acknowledged": bool(row[5])}
                for row in rows
            ]})
            return
        if path == "/api/case-alerts":
            if not self._require_case_staff():
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                rows = connection.execute(
                    """SELECT id, case_id, author, area_json, units_json, summary,
                              instructions, photo_data, created_epoch, acknowledgements_json
                       FROM case_area_alerts ORDER BY created_epoch DESC LIMIT 200"""
                ).fetchall()
            finally:
                connection.close()
            self._json(200, {"alerts": [
                {"id": row[0], "caseId": row[1], "author": row[2],
                 "area": json.loads(row[3]), "units": json.loads(row[4]),
                 "summary": row[5], "instructions": row[6], "photo": row[7],
                 "createdAt": int(row[8] * 1000),
                 "acknowledgements": json.loads(row[9])}
                for row in rows
            ]})
            return
        if path == "/api/cases/face-gallery":
            if not self._require_case_staff():
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                rows = connection.execute(
                    """SELECT public_ref, person_json, photos_json FROM missing_cases
                       WHERE verified=1 AND status='Active' ORDER BY updated_epoch DESC LIMIT 500"""
                ).fetchall()
            finally:
                connection.close()
            self._json(200, {"cases": [
                {"reference": row[0], "person": json.loads(row[1]), "photos": json.loads(row[2])}
                for row in rows
            ]})
            return
        if path == "/api/cases":
            role = self._require_case_staff()
            if not role:
                return
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            filters = {
                "type": query.get("type", [""])[0],
                "status": query.get("status", [""])[0],
                "state": query.get("state", [""])[0].casefold(),
                "priority": query.get("priority", [""])[0],
                "assigned": query.get("assigned", [""])[0].casefold(),
                "from": query.get("from", [""])[0],
                "to": query.get("to", [""])[0],
                "minors": query.get("minors", [""])[0] == "true",
                "search": query.get("search", [""])[0].casefold(),
            }
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                rows = connection.execute(
                    """SELECT id, public_ref, source, case_type, person_json, photos_json,
                              location_json, status, verified, priority, priority_reason,
                              assigned_json, border_watch, created_epoch, updated_epoch,
                              circumstances_json, reporter_json, consent_json
                       FROM missing_cases ORDER BY CASE priority WHEN 'Critical' THEN 0
                         WHEN 'High' THEN 1 ELSE 2 END, created_epoch ASC LIMIT 1000"""
                ).fetchall()
            finally:
                connection.close()
            cases = []
            for row in rows:
                case = self._case_row_json(row)
                person = case["person"]
                if filters["type"] and case["caseType"] != filters["type"]:
                    continue
                if filters["status"] and case["status"] != filters["status"]:
                    continue
                if filters["priority"] and case["priority"] != filters["priority"]:
                    continue
                if filters["state"] and case["location"]["state"].casefold() != filters["state"]:
                    continue
                if filters["assigned"] and not any(
                    filters["assigned"] in item.casefold() for item in case["assigned"]
                ):
                    continue
                if filters["minors"]:
                    age = person.get("age")
                    if age is None and person.get("dateOfBirth"):
                        try:
                            birth_date = datetime.strptime(person["dateOfBirth"], "%Y-%m-%d").date()
                            today = datetime.now(timezone.utc).date()
                            age = today.year - birth_date.year - (
                                (today.month, today.day) < (birth_date.month, birth_date.day)
                            )
                        except ValueError:
                            age = None
                    if age is None or age >= 18:
                        continue
                if filters["search"] and filters["search"] not in (
                    f"{case['reference']} {person['fullName']} {case['location']['state']}".casefold()
                ):
                    continue
                try:
                    created = datetime.fromtimestamp(case["createdAt"] / 1000, timezone.utc).date().isoformat()
                    if filters["from"] and created < filters["from"]:
                        continue
                    if filters["to"] and created > filters["to"]:
                        continue
                except (ValueError, OverflowError):
                    continue
                cases.append(case)
            audit_event(self._who(), "MISSING-PERSON CASE LIST VIEWED",
                        "Viewed filtered missing-person and kidnapping case list",
                        details={"count": len(cases)})
            self._json(200, {"cases": cases})
            return
        if path.startswith("/api/cases/"):
            role = self._require_case_staff()
            if not role:
                return
            case_reference = urllib.parse.unquote(path.removeprefix("/api/cases/"))
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                row = connection.execute(
                    """SELECT id, public_ref, source, case_type, person_json, photos_json,
                              location_json, status, verified, priority, priority_reason,
                              assigned_json, border_watch, created_epoch, updated_epoch,
                              circumstances_json, reporter_json, consent_json, notes
                       FROM missing_cases WHERE id=? OR public_ref=?""",
                    (case_reference, case_reference),
                ).fetchone()
                if not row:
                    self._json(404, {"error": "Case not found."})
                    return
                event_rows = connection.execute(
                    """SELECT id, event_type, author, created_epoch, visibility, details_json
                       FROM case_events WHERE case_id=? ORDER BY id""", (row[0],)
                ).fetchall()
            finally:
                connection.close()
            case = self._case_row_json(row, detail=True)
            assigned = case["assigned"]
            case["timeline"] = [
                {"id": item[0], "event": item[1], "author": item[2], "at": int(item[3] * 1000),
                 "visibility": item[4], "details": json.loads(item[5])}
                for item in event_rows if item[3] != "restricted" or self._who() in assigned
            ]
            audit_event(self._who(), "MISSING-PERSON CASE VIEWED",
                        "Viewed missing-person case file", row[1])
            self._json(200, {"case": case})
            return
        if path == "/api/admin/access-requests":
            if not self._require_demo_supervisor():
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                rows = connection.execute(
                    """SELECT service_number, full_name, official_type, agency_unit,
                              photo_data, fingerprint_enrolled, status, requested_epoch,
                              reviewer, reviewed_epoch
                       FROM official_access WHERE status='pending' ORDER BY requested_epoch"""
                ).fetchall()
            finally:
                connection.close()
            audit_event(self._who(), "OFFICIAL ACCESS REQUEST QUEUE VIEWED",
                        "Viewed pending official access requests", details={"count": len(rows)})
            self._json(200, {"requests": [self._official_access_json(row) for row in rows]})
            return
        if path == "/api/admin/services":
            if not self._require_demo_supervisor():
                return
            service_number = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query).get(
                "serviceNumber", [""]
            )[0].strip()
            if not service_number:
                self._json(400, {"error": "A service number is required."})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                row = connection.execute(
                    """SELECT service_number, full_name, official_type, agency_unit,
                              photo_data, fingerprint_enrolled, status, requested_epoch,
                              reviewer, reviewed_epoch
                       FROM official_access WHERE service_key=?""",
                    (service_number.casefold(),),
                ).fetchone()
            finally:
                connection.close()
            if not row:
                self._json(404, {"error": "No service record was found for that number."})
                return
            audit_event(self._who(), "OFFICIAL SERVICE LOOKUP",
                        "Supervisor searched for an official service number",
                        row[0], {"status": row[6]})
            self._json(200, {"service": self._official_access_json(row)})
            return
        if path == "/api/workspace":
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                row = connection.execute(
                    "SELECT data_json FROM app_workspace WHERE workspace_id='shared'"
                ).fetchone()
            finally:
                connection.close()
            workspace = json.loads(row[0]) if row else {
                "citizens": [], "notes": [], "savedCases": [],
                "accessRequests": [], "audit": [],
            }
            self._json(200, {"workspace": workspace})
            return
        if path == "/api/link-analysis/location-requests/pending":
            if not self._require_demo_supervisor():
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                rows = connection.execute(
                    """SELECT id, requester, legal_authorization, case_ref, reason,
                              period_start, period_end, people_json, status, expires_epoch
                       FROM link_location_requests WHERE status='pending' ORDER BY created_epoch"""
                ).fetchall()
            finally:
                connection.close()
            audit_event(self._who(), "LINK ANALYSIS SUPERVISOR QUEUE VIEWED",
                        "Viewed pending location authorization requests",
                        self.headers.get("X-NSP-Case-Ref", "—"), {"count": len(rows)})
            self._json(200, {"requests": [self._location_request_json(row) for row in rows]})
            return
        if path == "/api/link-analysis/location-requests/mine":
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                rows = connection.execute(
                    """SELECT id, requester, legal_authorization, case_ref, reason,
                              period_start, period_end, people_json, status, expires_epoch
                       FROM link_location_requests WHERE requester=? ORDER BY created_epoch DESC LIMIT 50""",
                    (self._who(),),
                ).fetchall()
            finally:
                connection.close()
            self._json(200, {"requests": [self._location_request_json(row) for row in rows]})
            return
        if path == "/api/link-analysis/boards":
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                rows = connection.execute(
                    "SELECT id, case_ref, reason, board_json FROM saved_link_boards WHERE who=? ORDER BY saved_epoch DESC LIMIT 100",
                    (self._who(),),
                ).fetchall()
            finally:
                connection.close()
            audit_event(self._who(), "LINK ANALYSIS SAVED BOARDS VIEWED",
                        "Viewed own saved link-analysis boards",
                        self.headers.get("X-NSP-Case-Ref", "—"), {"count": len(rows)})
            boards = [{"id": row[0], **json.loads(row[3])} for row in rows]
            self._json(200, {"boards": boards})
            return
        if path.startswith("/api/link-analysis/location-requests/"):
            request_id = urllib.parse.unquote(path.removeprefix("/api/link-analysis/location-requests/"))
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                row = connection.execute(
                    """SELECT id, requester, legal_authorization, case_ref, reason,
                              period_start, period_end, people_json, status, expires_epoch
                       FROM link_location_requests WHERE id=?""", (request_id,)
                ).fetchone()
            finally:
                connection.close()
            if not row:
                self._json(404, {"error": "Location authorization request not found."})
                return
            if row[1] != self._who() and self.headers.get("X-NSP-Supervisor") != "demo":
                self._json(403, {"error": "Only the requester or a supervisor may view this request."})
                return
            self._json(200, {"request": self._location_request_json(row)})
            return
        if path == "/api/alerts":
            response = public_state()
            statuses = latest_alert_review_statuses({alert["id"] for alert in response["alerts"]})
            if self.headers.get("X-NSP-Official-Type") == "Media official":
                response = {
                    "alerts": [
                        {
                            "id": alert["id"],
                            "title": alert["title"],
                            "category": alert["category"],
                            "reviewStatus": statuses[alert["id"]],
                        }
                        for alert in response["alerts"]
                        if alert["id"] in statuses
                    ],
                    "generatedAt": response["generatedAt"],
                }
            else:
                for alert in response["alerts"]:
                    if alert["id"] in statuses:
                        alert["reviewStatus"] = statuses[alert["id"]]
            audit_event(
                self._who(), "EARLY WARNING FEED VIEW",
                self.headers.get("X-NSP-Reason", "Viewed processed alert feed"),
                self.headers.get("X-NSP-Case-Ref", "—"),
            )
            self._json(200, response)
            return
        if path == "/api/admin/alerts/pending":
            if not self._require_demo_supervisor():
                return
            audit_event(
                self._who(), "HIGH ALERT REVIEW QUEUE VIEW", "Viewed pending analyst review queue",
                self.headers.get("X-NSP-Case-Ref", "—"),
            )
            with STATE_LOCK:
                pending = json.loads(json.dumps(list(PENDING_HIGH.values())))
            self._json(200, {"alerts": pending})
            return
        if path == "/api/admin/audit":
            if not self._require_demo_supervisor():
                return
            audit_event(
                self._who(), "AUDIT LOG VIEW", "Viewed recent audit events",
                self.headers.get("X-NSP-Case-Ref", "—"),
            )
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                rows = connection.execute(
                    "SELECT when_utc, who, action, case_ref, reason FROM audit_log ORDER BY id DESC LIMIT 200"
                ).fetchall()
            finally:
                connection.close()
            self._json(200, {"events": [
                {"when": row[0], "who": row[1], "action": row[2], "caseRef": row[3], "reason": row[4]}
                for row in rows
            ]})
            return
        if path not in {
            "/", "/index.html", "/family_report.html", "/case_forms.js",
            "/family_report.js", "/vf.js", "/assets/platform-background.svg",
            "/assets/platform-background.png",
        }:
            self._json(404, {"error": "Resource not found."})
            return
        self.path = path if path not in {"/", "/index.html"} else "/index.html"
        return super().do_GET()

    def do_POST(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/plate-search":
            import plate_reader
            if plate_reader.handle_post(self, path):
                return
        if path.startswith("/api/vf/"):
            import vf_routes
            payload: dict[str, Any] = {}
            if path != "/api/vf/upload":
                try:
                    payload = self._body()
                except (ValueError, json.JSONDecodeError) as exc:
                    self._json(400, {"error": f"Invalid request body: {exc}"})
                    return
            try:
                if vf_routes.handle_vf_post(self, path, payload):
                    return
            except Exception as exc:
                import traceback
                traceback.print_exc()
                self._json(500, {"error": f"Visual Forensics request failed: {exc}"})
                return
        try:
            payload = self._body()
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": f"Invalid request body: {exc}"})
            return
        who = self._who()
        if path == "/api/family/reports":
            reference = clean_text(str(payload.get("reference", "")), 80)
            token = payload.get("token")
            if not reference or not isinstance(token, str) or not token:
                self._json(400, {"error": "Enter the report reference and private status-check token."})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                row = connection.execute(
                    """SELECT public_ref, status, updated_epoch, family_token_hash, source
                       FROM missing_cases WHERE public_ref=?""", (reference,)
                ).fetchone()
                if not row or row[4] != "family" or not hmac.compare_digest(
                    hashlib.sha256(token.encode("utf-8")).hexdigest(), row[3] or ""
                ):
                    self._json(404, {"error": "No family report matched those private status-check details."})
                    return
                timeline_rows = connection.execute(
                    """SELECT event_type, created_epoch, details_json FROM case_events
                       WHERE case_id=(SELECT id FROM missing_cases WHERE public_ref=?)
                         AND event_type IN ('report_received', 'status_changed')
                       ORDER BY id""",
                    (reference,),
                ).fetchall()
            finally:
                connection.close()
            self._json(200, {"report": self._case_public_status(row),
                             "timeline": [{"event": item[0], "at": int(item[1] * 1000),
                                           "status": json.loads(item[2]).get("status")}
                                          for item in timeline_rows]})
            return
        if path == "/api/family/verification/request":
            email = clean_text(str(payload.get("email", "")), 254).casefold()
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
                self._json(400, {"error": "Enter a valid email address."})
                return
            if not SMTP_HOST or not SMTP_FROM:
                self._json(503, {"error": "Email verification is not configured. The report cannot be submitted yet; contact the service administrator."})
                return
            now = time.time()
            client_ip = self.client_address[0]
            if not self._family_email_limits(email, client_ip, now):
                self._json(429, {"error": "Too many code requests. Wait at least one minute and retry; limits reset after 15 minutes."})
                return
            code_id = uuid.uuid4().hex
            code = f"{secrets.randbelow(1_000_000):06d}"
            code_digest = hmac.new(
                FAMILY_OTP_KEY, f"{code_id}:{code}".encode("utf-8"), hashlib.sha256
            ).hexdigest()
            try:
                send_family_verification_email(email, code)
            except (OSError, smtplib.SMTPException, RuntimeError) as exc:
                self._json(502, {"error": f"Could not deliver the verification email: {clean_text(str(exc), 220)}"})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                connection.execute(
                    """INSERT INTO family_verifications
                       (id, email_key, client_ip, code_hash, created_epoch, expires_epoch)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (code_id, email, client_ip, code_digest, now, now + 10 * 60),
                )
                connection.commit()
            finally:
                connection.close()
            self._json(202, {"ok": True, "verificationId": code_id,
                             "message": "Verification code sent. It expires in 10 minutes."})
            return
        if path == "/api/family/verification/confirm":
            verification_id = clean_text(str(payload.get("verificationId", "")), 80)
            code = clean_text(str(payload.get("code", "")), 6)
            if not verification_id or not re.fullmatch(r"\d{6}", code):
                self._json(400, {"error": "Enter the six-digit code sent to your email."})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """SELECT email_key, code_hash, expires_epoch, attempts, verified_token_hash,
                              consumed_epoch, client_ip
                       FROM family_verifications WHERE id=?""",
                    (verification_id,),
                ).fetchone()
                if not row or row[2] < time.time() or row[3] >= 5 or row[5] is not None:
                    self._json(400, {"error": "Verification code has expired or is unavailable. Request a new code."})
                    return
                if row[6] != self.client_address[0]:
                    self._json(403, {"error": "Complete email verification from the same browser and network."})
                    return
                expected = hmac.new(
                    FAMILY_OTP_KEY, f"{verification_id}:{code}".encode("utf-8"), hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(expected, row[1]):
                    connection.execute(
                        "UPDATE family_verifications SET attempts=attempts+1 WHERE id=?",
                        (verification_id,),
                    )
                    connection.commit()
                    self._json(400, {"error": "Verification code is incorrect."})
                    return
                verification_token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(verification_token.encode("utf-8")).hexdigest()
                connection.execute(
                    """UPDATE family_verifications SET verified_token_hash=?, verified_epoch=?
                       WHERE id=?""",
                    (token_hash, time.time(), verification_id),
                )
                connection.commit()
            finally:
                connection.close()
            self._json(200, {"ok": True, "verificationToken": verification_token,
                             "message": "Email verified. Submit the report within 15 minutes."})
            return
        if path == "/api/family/cases":
            if clean_text(str(payload.get("website", "")), 200):
                self._json(400, {"error": "The report could not be accepted."})
                return
            verification_token = payload.get("verificationToken")
            if not isinstance(verification_token, str) or not verification_token:
                self._json(403, {"error": "Verify your email before submitting this report."})
                return
            try:
                case = _normalise_case_payload(payload, family=True)
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
                return
            now = time.time()
            email = case["reporter"]["email"]
            verification_hash = hashlib.sha256(verification_token.encode("utf-8")).hexdigest()
            family_token = secrets.token_urlsafe(32)
            family_token_hash = hashlib.sha256(family_token.encode("utf-8")).hexdigest()
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                connection.execute("BEGIN IMMEDIATE")
                verification = connection.execute(
                    """SELECT id, email_key FROM family_verifications
                       WHERE verified_token_hash=? AND consumed_epoch IS NULL
                         AND verified_epoch>=? AND expires_epoch>?""",
                    (verification_hash, now - 15 * 60, now),
                ).fetchone()
                if not verification or verification[1] != email:
                    self._json(403, {"error": "The verified email does not match this report, or the verification expired."})
                    return
                email_count = connection.execute(
                    "SELECT COUNT(*) FROM family_submission_limits WHERE email_key=? AND created_epoch>?",
                    (email, now - 60 * 60),
                ).fetchone()[0]
                ip_count = connection.execute(
                    "SELECT COUNT(*) FROM family_submission_limits WHERE client_ip=? AND created_epoch>?",
                    (self.client_address[0], now - 60 * 60),
                ).fetchone()[0]
                if email_count >= 3 or ip_count >= 5:
                    self._json(429, {"error": "Submission limit reached. Try again after one hour or contact the local service desk."})
                    return
                connection.execute(
                    "UPDATE family_verifications SET consumed_epoch=? WHERE id=?",
                    (now, verification[0]),
                )
                connection.execute(
                    """INSERT INTO family_submission_limits (email_key, client_ip, created_epoch)
                       VALUES (?, ?, ?)""",
                    (email, self.client_address[0], now),
                )
                connection.commit()
            finally:
                connection.close()
            try:
                result = self._save_missing_case(
                    payload, "family", f"FAMILY:{email}", family_token_hash
                )
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
                return
            self._json(201, {"report": result, "statusCheckToken": family_token,
                             "message": "Your report is received and marked Unverified until an officer reviews it."})
            return
        if path == "/api/cases":
            if not self._require_case_staff():
                return
            try:
                result = self._save_missing_case(payload, "officer", who)
            except ValueError as exc:
                self._json(400, {"error": str(exc)})
                return
            self._json(201, {"case": result})
            return
        if path.startswith("/api/cases/") and path.endswith("/status"):
            if not self._require_case_staff():
                return
            case_reference = urllib.parse.unquote(path.removeprefix("/api/cases/").removesuffix("/status"))
            new_status = clean_text(str(payload.get("status", "")), 60)
            reason = clean_text(str(payload.get("reason", "")), 500)
            if new_status not in CASE_STATUSES or not reason:
                self._json(400, {"error": "Choose a valid case status and provide a reason."})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """SELECT id, public_ref, status, verified, assigned_json, case_type, person_json
                       FROM missing_cases WHERE id=? OR public_ref=?""",
                    (case_reference, case_reference),
                ).fetchone()
                if not row:
                    self._json(404, {"error": "Case not found."})
                    return
                allowed_transitions = {
                    "New": {"Under review", "Withdrawn (false report)"},
                    "Under review": {"Active", "Closed (insufficient information)", "Withdrawn (false report)"},
                    "Active": CASE_TERMINAL_STATUSES,
                }
                if new_status not in allowed_transitions.get(row[2], set()):
                    self._json(409, {"error": f"A case in {row[2]} cannot transition to {new_status}."})
                    return
                if new_status == "Active" and payload.get("verify") is not True:
                    self._json(400, {"error": "An officer must verify this report before making it Active."})
                    return
                now = time.time()
                connection.execute(
                    """UPDATE missing_cases SET status=?, verified=CASE WHEN ?='Active' THEN 1 ELSE verified END,
                              updated_epoch=?, stale_alerted_epoch=0 WHERE id=?""",
                    (new_status, new_status, now, row[0]),
                )
                _case_event(connection, row[0], "status_changed", who,
                            {"from": row[2], "status": new_status, "reason": reason,
                             "verified": new_status == "Active"})
                assigned = json.loads(row[4])
                _case_notify(connection, row[0], assigned, ["supervisor"],
                             "status_changed", f"Case {row[1]} status changed to {new_status}.")
                connection.commit()
            finally:
                connection.close()
            audit_event(who, "MISSING-PERSON CASE STATUS CHANGED", reason, row[1],
                        {"from": row[2], "status": new_status, "verified": new_status == "Active"})
            self._json(200, {"ok": True, "reference": row[1], "status": new_status,
                             "verified": new_status == "Active" or bool(row[3])})
            return
        if path.startswith("/api/cases/") and path.endswith("/sightings"):
            if not self._require_case_staff():
                return
            case_reference = urllib.parse.unquote(path.removeprefix("/api/cases/").removesuffix("/sightings"))
            place_name = clean_text(str(payload.get("placeName", "")), 180)
            state_name = clean_text(str(payload.get("state", "")), 80)
            source_name = clean_text(str(payload.get("source", "")), 30)
            confidence = clean_text(str(payload.get("confidence", "")), 20)
            reason = clean_text(str(payload.get("reason", "")), 500)
            if not place_name or not state_name or source_name not in {"family", "public tip", "officer"} or confidence not in {"Low", "Medium", "High"} or not reason:
                self._json(400, {"error": "Provide a location, state, valid sighting source, confidence, and reason."})
                return
            try:
                lat, lon = payload.get("latitude"), payload.get("longitude")
                if lat is not None or lon is not None:
                    lat, lon = float(lat), float(lon)
                    if not (NIGERIA_BOUNDS["minLat"] <= lat <= NIGERIA_BOUNDS["maxLat"] and NIGERIA_BOUNDS["minLon"] <= lon <= NIGERIA_BOUNDS["maxLon"]):
                        raise ValueError
                else:
                    lat = lon = None
            except (TypeError, ValueError):
                self._json(400, {"error": "Sighting pin must contain valid coordinates within Nigeria."})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                row = connection.execute(
                    "SELECT id, public_ref, assigned_json FROM missing_cases WHERE id=? OR public_ref=?",
                    (case_reference, case_reference),
                ).fetchone()
                if not row:
                    self._json(404, {"error": "Case not found."})
                    return
                sighting = {
                    "placeName": place_name, "state": state_name,
                    "lga": clean_text(str(payload.get("lga", "")), 80),
                    "latitude": lat, "longitude": lon,
                    "time": clean_text(str(payload.get("time", "")), 40),
                    "source": source_name, "confidence": confidence, "reason": reason,
                }
                connection.execute("BEGIN IMMEDIATE")
                _case_event(connection, row[0], "sighting_added", who, sighting)
                connection.execute(
                    "UPDATE missing_cases SET updated_epoch=?, stale_alerted_epoch=0 WHERE id=?",
                    (time.time(), row[0]),
                )
                _case_notify(connection, row[0], json.loads(row[2]), ["supervisor"],
                             "new_sighting", f"New {confidence.lower()}-confidence sighting for case {row[1]}.")
                connection.commit()
            finally:
                connection.close()
            audit_event(who, "MISSING-PERSON CASE SIGHTING ADDED", reason, row[1], sighting)
            self._json(201, {"ok": True, "sighting": sighting})
            return
        if path.startswith("/api/cases/") and path.endswith("/case-notes"):
            if not self._require_case_staff():
                return
            case_reference = urllib.parse.unquote(path.removeprefix("/api/cases/").removesuffix("/case-notes"))
            notes = clean_text(str(payload.get("caseNotes", "")), 8000)
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                row = connection.execute(
                    "SELECT id, public_ref FROM missing_cases WHERE id=? OR public_ref=?",
                    (case_reference, case_reference),
                ).fetchone()
                if not row:
                    self._json(404, {"error": "Case not found."})
                    return
                now = time.time()
                connection.execute(
                    "UPDATE missing_cases SET notes=?, updated_epoch=? WHERE id=?",
                    (notes, now, row[0]),
                )
                _case_event(connection, row[0], "case_notes_updated", who,
                            {"notes": notes, "length": len(notes)})
                connection.commit()
            finally:
                connection.close()
            audit_event(self._who(), "MISSING-PERSON CASE NOTES UPDATED",
                        "Officer case record updated", row[1], {"length": len(notes)})
            self._json(200, {"ok": True, "caseNotes": notes, "updatedAt": int(now * 1000)})
            return
        if path.startswith("/api/cases/") and path.endswith("/notes"):
            if not self._require_case_staff():
                return
            case_reference = urllib.parse.unquote(path.removeprefix("/api/cases/").removesuffix("/notes"))
            note = clean_text(str(payload.get("note", "")), 3000)
            visibility = "restricted" if payload.get("restricted") is True else "all"
            if not note:
                self._json(400, {"error": "Enter a case note."})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                row = connection.execute(
                    "SELECT id, public_ref, assigned_json FROM missing_cases WHERE id=? OR public_ref=?",
                    (case_reference, case_reference),
                ).fetchone()
                if not row:
                    self._json(404, {"error": "Case not found."})
                    return
                connection.execute("BEGIN IMMEDIATE")
                _case_event(connection, row[0], "note_added", who, {"note": note}, visibility)
                connection.execute(
                    "UPDATE missing_cases SET updated_epoch=?, stale_alerted_epoch=0 WHERE id=?",
                    (time.time(), row[0]),
                )
                connection.commit()
            finally:
                connection.close()
            audit_event(who, "MISSING-PERSON CASE NOTE ADDED", "Added an append-only case note",
                        row[1], {"restricted": visibility == "restricted"})
            self._json(201, {"ok": True, "visibility": visibility})
            return
        if path.startswith("/api/cases/") and "/notes/" in path and path.endswith("/correction"):
            if not self._require_case_staff():
                return
            case_reference, event_id = path.removeprefix("/api/cases/").removesuffix("/correction").split("/notes/", 1)
            case_reference, event_id = urllib.parse.unquote(case_reference), urllib.parse.unquote(event_id)
            correction = clean_text(str(payload.get("correction", "")), 3000)
            reason = clean_text(str(payload.get("reason", "")), 500)
            if not correction or not reason or not event_id.isdigit():
                self._json(400, {"error": "Provide a correction and reason for the original note."})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                original = connection.execute(
                    """SELECT e.case_id, e.visibility, c.public_ref FROM case_events e
                       JOIN missing_cases c ON c.id=e.case_id
                       WHERE e.id=? AND e.event_type='note_added' AND (c.id=? OR c.public_ref=?)""",
                    (int(event_id), case_reference, case_reference),
                ).fetchone()
                if not original:
                    self._json(404, {"error": "Original case note not found."})
                    return
                connection.execute("BEGIN IMMEDIATE")
                _case_event(connection, original[0], "note_correction", who,
                            {"correctsEventId": int(event_id), "correction": correction, "reason": reason},
                            original[1])
                connection.execute(
                    "UPDATE missing_cases SET updated_epoch=?, stale_alerted_epoch=0 WHERE id=?",
                    (time.time(), original[0]),
                )
                connection.commit()
            finally:
                connection.close()
            audit_event(who, "MISSING-PERSON CASE NOTE CORRECTED",
                        reason, original[2], {"correctsEventId": int(event_id)})
            self._json(201, {"ok": True, "correctsEventId": int(event_id)})
            return
        if path.startswith("/api/cases/") and path.endswith("/assign"):
            if not self._require_case_staff():
                return
            case_reference = urllib.parse.unquote(path.removeprefix("/api/cases/").removesuffix("/assign"))
            assignees = payload.get("assigned")
            reason = clean_text(str(payload.get("reason", "")), 500)
            if (
                not isinstance(assignees, list) or len(assignees) > 30
                or any(not isinstance(item, str) or not clean_text(item, 120) for item in assignees)
                or not reason
            ):
                self._json(400, {"error": "Provide up to 30 officer/unit assignments and a reason."})
                return
            assigned = list(dict.fromkeys(clean_text(item, 120) for item in assignees))
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT id, public_ref FROM missing_cases WHERE id=? OR public_ref=?",
                    (case_reference, case_reference),
                ).fetchone()
                if not row:
                    self._json(404, {"error": "Case not found."})
                    return
                connection.execute(
                    "UPDATE missing_cases SET assigned_json=?, updated_epoch=?, stale_alerted_epoch=0 WHERE id=?",
                    (json.dumps(assigned), time.time(), row[0]),
                )
                _case_event(connection, row[0], "case_assigned", who,
                            {"assigned": assigned, "reason": reason})
                _case_notify(connection, row[0], assigned, ["supervisor"], "case_assigned",
                             f"Case {row[1]} has new assigned officers or units.")
                connection.commit()
            finally:
                connection.close()
            audit_event(who, "MISSING-PERSON CASE ASSIGNED", reason, row[1],
                        {"assigned": assigned})
            self._json(200, {"ok": True, "assigned": assigned})
            return
        if path.startswith("/api/cases/") and path.endswith("/priority"):
            if not self._require_case_staff():
                return
            case_reference = urllib.parse.unquote(path.removeprefix("/api/cases/").removesuffix("/priority"))
            priority = clean_text(str(payload.get("priority", "")), 20)
            reason = clean_text(str(payload.get("reason", "")), 500)
            if priority not in {"Critical", "High", "Normal"} or not reason:
                self._json(400, {"error": "Choose Critical, High, or Normal and provide a reason."})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT id, public_ref, assigned_json FROM missing_cases WHERE id=? OR public_ref=?",
                    (case_reference, case_reference),
                ).fetchone()
                if not row:
                    self._json(404, {"error": "Case not found."})
                    return
                connection.execute(
                    """UPDATE missing_cases SET priority=?, priority_reason=?, updated_epoch=?,
                              stale_alerted_epoch=0 WHERE id=?""",
                    (priority, reason, time.time(), row[0]),
                )
                _case_event(connection, row[0], "priority_changed", who,
                            {"priority": priority, "reason": reason})
                if priority == "Critical":
                    _case_notify(connection, row[0], json.loads(row[2]), ["supervisor"],
                                 "critical_priority", f"Case {row[1]} is now Critical.")
                connection.commit()
            finally:
                connection.close()
            audit_event(who, "MISSING-PERSON CASE PRIORITY CHANGED", reason, row[1],
                        {"priority": priority})
            self._json(200, {"ok": True, "priority": priority})
            return
        if path.startswith("/api/cases/") and path.endswith("/border-watch"):
            if not self._require_case_staff():
                return
            case_reference = urllib.parse.unquote(path.removeprefix("/api/cases/").removesuffix("/border-watch"))
            enabled = payload.get("enabled")
            reason = clean_text(str(payload.get("reason", "")), 500)
            if not isinstance(enabled, bool) or not reason:
                self._json(400, {"error": "Choose whether border watch is enabled and provide a reason."})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT id, public_ref FROM missing_cases WHERE id=? OR public_ref=?",
                    (case_reference, case_reference),
                ).fetchone()
                if not row:
                    self._json(404, {"error": "Case not found."})
                    return
                connection.execute(
                    "UPDATE missing_cases SET border_watch=?, updated_epoch=? WHERE id=?",
                    (int(enabled), time.time(), row[0]),
                )
                _case_event(connection, row[0], "border_watch_changed", who,
                            {"enabled": enabled, "reason": reason})
                connection.commit()
            finally:
                connection.close()
            audit_event(who, "MISSING-PERSON CASE BORDER WATCH CHANGED", reason, row[1],
                        {"enabled": enabled})
            self._json(200, {"ok": True, "borderWatch": enabled})
            return
        if path.startswith("/api/cases/") and path.endswith("/links"):
            if not self._require_case_staff():
                return
            case_reference = urllib.parse.unquote(path.removeprefix("/api/cases/").removesuffix("/links"))
            link_type = clean_text(str(payload.get("type", "")), 20)
            target = clean_text(str(payload.get("target", "")), 100)
            reason = clean_text(str(payload.get("reason", "")), 500)
            if link_type not in {"case", "board"} or not target or not reason:
                self._json(400, {"error": "Choose a case or Link analysis board reference and provide a reason."})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                case_row = connection.execute(
                    "SELECT id, public_ref FROM missing_cases WHERE id=? OR public_ref=?",
                    (case_reference, case_reference),
                ).fetchone()
                if not case_row:
                    self._json(404, {"error": "Case not found."})
                    return
                if link_type == "case":
                    target_row = connection.execute(
                        "SELECT id, public_ref FROM missing_cases WHERE id=? OR public_ref=?",
                        (target, target),
                    ).fetchone()
                    if not target_row or target_row[0] == case_row[0]:
                        self._json(404, {"error": "A different existing case is required."})
                        return
                    target = target_row[1]
                else:
                    board_row = connection.execute(
                        "SELECT id FROM saved_link_boards WHERE id=? AND who=?",
                        (target, who),
                    ).fetchone()
                    if not board_row:
                        self._json(404, {"error": "Link analysis board not found for this official."})
                        return
                connection.execute("BEGIN IMMEDIATE")
                _case_event(connection, case_row[0], "case_linked", who,
                            {"type": link_type, "target": target, "reason": reason})
                connection.execute(
                    "UPDATE missing_cases SET updated_epoch=? WHERE id=?", (time.time(), case_row[0])
                )
                connection.commit()
            finally:
                connection.close()
            audit_event(who, "MISSING-PERSON CASE LINKED", reason, case_row[1],
                        {"type": link_type, "target": target})
            self._json(201, {"ok": True, "type": link_type, "target": target})
            return
        if path.startswith("/api/cases/") and path.endswith("/alerts"):
            if not self._require_case_staff():
                return
            case_reference = urllib.parse.unquote(path.removeprefix("/api/cases/").removesuffix("/alerts"))
            area = payload.get("area")
            units = payload.get("units")
            instructions = clean_text(str(payload.get("instructions", "")), 1000)
            if not isinstance(area, dict) or not isinstance(units, list) or not 1 <= len(units) <= 50 or not instructions:
                self._json(400, {"error": "Choose an alert area, at least one unit/checkpoint, and instructions."})
                return
            alert_units = list(dict.fromkeys(clean_text(str(unit), 120) for unit in units if clean_text(str(unit), 120)))
            if not alert_units:
                self._json(400, {"error": "Enter at least one valid unit or checkpoint."})
                return
            area_type = area.get("type")
            if area_type not in {"state", "lga", "radius"}:
                self._json(400, {"error": "Alert area must be a state, LGA, or radius around the last-known location."})
                return
            radius_km = None
            if area_type in {"state", "lga"} and not clean_text(str(area.get("name", "")), 80):
                self._json(400, {"error": "Enter the state or LGA for this alert."})
                return
            if area_type == "radius":
                try:
                    radius_km = float(area.get("radiusKm"))
                    if not 1 <= radius_km <= 500:
                        raise ValueError
                except (TypeError, ValueError):
                    self._json(400, {"error": "Radius must be between 1 and 500 kilometres."})
                    return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    """SELECT id, public_ref, case_type, person_json, photos_json, location_json,
                              status, verified, assigned_json
                       FROM missing_cases WHERE id=? OR public_ref=?""",
                    (case_reference, case_reference),
                ).fetchone()
                if not row:
                    self._json(404, {"error": "Case not found."})
                    return
                if row[6] != "Active" or not row[7]:
                    self._json(409, {"error": "Targeted alerts can only be sent for verified Active cases."})
                    return
                area_result = {
                    "type": area_type,
                    "name": clean_text(str(area.get("name", "")), 80) if area_type != "radius" else "",
                    "radiusKm": radius_km,
                }
                if area_type == "radius":
                    location = json.loads(row[5])
                    if location.get("latitude") is None or location.get("longitude") is None:
                        self._json(409, {"error": "This case has no map pin for a radius alert."})
                        return
                    area_result["latitude"] = location["latitude"]
                    area_result["longitude"] = location["longitude"]
                person = json.loads(row[3])
                summary = f"{row[2]}: {person['fullName']}"
                if person.get("age") is not None:
                    summary += f", age {person['age']}"
                summary += f". Last known: {json.loads(row[5])['placeName']}."
                alert_id = f"CA-{uuid.uuid4().hex[:12].upper()}"
                connection.execute(
                    """INSERT INTO case_area_alerts
                       (id, case_id, author, area_json, units_json, summary, instructions,
                        photo_data, created_epoch, acknowledgements_json)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '[]')""",
                    (alert_id, row[0], who, json.dumps(area_result), json.dumps(alert_units),
                     summary, instructions, json.loads(row[4])[0], time.time()),
                )
                _case_event(connection, row[0], "targeted_alert_sent", who,
                            {"alertId": alert_id, "area": area_result, "units": alert_units,
                             "summary": summary, "instructions": instructions})
                _case_notify(connection, row[0], json.loads(row[8]), ["supervisor"],
                             "targeted_alert_sent", f"Targeted alert {alert_id} was sent for case {row[1]}.")
                for unit in alert_units:
                    _case_notify(connection, row[0], [], [f"unit:{unit}"], "targeted_alert_received",
                                 f"Action required: {summary}")
                connection.commit()
            finally:
                connection.close()
            audit_event(who, "MISSING-PERSON TARGETED ALERT SENT", instructions, row[1],
                        {"alertId": alert_id, "area": area_result, "units": alert_units,
                         "delivery": "simulated"})
            self._json(201, {"ok": True, "alertId": alert_id,
                             "delivery": "simulated", "requiresAcknowledgement": True})
            return
        if path.startswith("/api/cases/notifications/") and path.endswith("/acknowledge"):
            if not self._require_case_staff():
                return
            notification_id = urllib.parse.unquote(path.removeprefix("/api/cases/notifications/").removesuffix("/acknowledge"))
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                row = connection.execute(
                    """SELECT recipient, recipient_kind, event_type FROM case_notifications
                       WHERE id=?""", (notification_id,)
                ).fetchone()
                if not row:
                    self._json(404, {"error": "Notification not found."})
                    return
                if row[1] == "official" and row[0] != who:
                    self._json(403, {"error": "This notification is assigned to another officer."})
                    return
                if row[1] == "role" and row[0] != self.headers.get("X-NSP-Official-Type"):
                    if not self._require_demo_supervisor():
                        return
                if row[1] == "unit":
                    self._json(403, {"error": "A unit alert must be acknowledged through its targeted alert."})
                    return
                connection.execute(
                    """UPDATE case_notifications SET acknowledged_by=?, acknowledged_epoch=?
                       WHERE id=? AND acknowledged_epoch IS NULL""",
                    (who, time.time(), notification_id),
                )
                connection.commit()
            finally:
                connection.close()
            audit_event(who, "MISSING-PERSON CASE NOTIFICATION ACKNOWLEDGED",
                        "Acknowledged an internal case notification",
                        details={"notificationId": notification_id, "eventType": row[2]})
            self._json(200, {"ok": True})
            return
        if path.startswith("/api/case-alerts/") and path.endswith("/acknowledge"):
            role = self._require_case_staff()
            if not role:
                return
            alert_id = urllib.parse.unquote(path.removeprefix("/api/case-alerts/").removesuffix("/acknowledge"))
            unit = clean_text(str(payload.get("unit", "")), 120)
            if not unit:
                self._json(400, {"error": "Enter the unit or checkpoint acknowledging this alert."})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                row = connection.execute(
                    "SELECT case_id, units_json, acknowledgements_json FROM case_area_alerts WHERE id=?",
                    (alert_id,),
                ).fetchone()
                if not row:
                    self._json(404, {"error": "Targeted alert not found."})
                    return
                units = json.loads(row[1])
                if unit not in units:
                    self._json(403, {"error": "This alert was not sent to that unit."})
                    return
                acknowledgements = json.loads(row[2])
                if not any(item["unit"] == unit for item in acknowledgements):
                    acknowledgements.append({"unit": unit, "official": who,
                                              "acknowledgedAt": int(time.time() * 1000)})
                    connection.execute(
                        "UPDATE case_area_alerts SET acknowledgements_json=? WHERE id=?",
                        (json.dumps(acknowledgements), alert_id),
                    )
                    _case_event(connection, row[0], "targeted_alert_acknowledged", who,
                                {"alertId": alert_id, "unit": unit})
                    connection.commit()
            finally:
                connection.close()
            audit_event(who, "MISSING-PERSON TARGETED ALERT ACKNOWLEDGED",
                        "Unit acknowledged a simulated case alert",
                        details={"alertId": alert_id, "unit": unit})
            self._json(200, {"ok": True, "unit": unit, "acknowledgedAt": int(time.time() * 1000)})
            return
        if path == "/api/access-requests":
            name = clean_text(str(payload.get("name", "")), 120)
            service_number = clean_text(str(payload.get("serviceNumber", "")), 80)
            official_type = clean_text(str(payload.get("officialType", "")), 80)
            agency_unit = clean_text(str(payload.get("agencyUnit", "")), 120)
            passcode = payload.get("passcode")
            photo = payload.get("photo")
            fingerprint_verified = payload.get("fingerprintVerified")
            if (
                not name or not service_number or not agency_unit
                or official_type not in OFFICIAL_TYPES
                or not isinstance(passcode, str) or not 8 <= len(passcode) <= 128
                or fingerprint_verified is not True
            ):
                self._json(400, {"error": "Provide a name, service number, official type, agency/unit, an 8–128 character passcode, and the demo fingerprint verification."})
                return
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,79}", service_number):
                self._json(400, {"error": "Service number contains unsupported characters."})
                return
            if not isinstance(photo, str):
                self._json(400, {"error": "Upload a PNG, JPEG, or WebP profile photo."})
                return
            photo_match = re.fullmatch(r"data:image/(png|jpeg|webp);base64,([A-Za-z0-9+/]+={0,2})", photo)
            if not photo_match:
                self._json(400, {"error": "Upload a valid PNG, JPEG, or WebP profile photo."})
                return
            try:
                photo_bytes = base64.b64decode(photo_match.group(2), validate=True)
            except (ValueError, base64.binascii.Error):
                self._json(400, {"error": "Profile photo data is invalid."})
                return
            image_type = photo_match.group(1)
            valid_signature = (
                photo_bytes.startswith(b"\x89PNG\r\n\x1a\n") if image_type == "png"
                else photo_bytes.startswith(b"\xff\xd8\xff") if image_type == "jpeg"
                else len(photo_bytes) >= 12 and photo_bytes.startswith(b"RIFF") and photo_bytes[8:12] == b"WEBP"
            )
            if not photo_bytes or len(photo_bytes) > MAX_OFFICIAL_PHOTO_BYTES or not valid_signature:
                self._json(400, {"error": "Profile photo must be a valid image no larger than 5 MB."})
                return
            salt = os.urandom(16)
            passcode_hash = hashlib.pbkdf2_hmac(
                "sha256", passcode.encode("utf-8"), salt, PASSCODE_ITERATIONS
            )
            service_key = service_number.casefold()
            now = time.time()
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                connection.execute("BEGIN IMMEDIATE")
                existing = connection.execute(
                    "SELECT status FROM official_access WHERE service_key=?", (service_key,)
                ).fetchone()
                if existing and existing[0] in {"pending", "approved"}:
                    self._json(409, {"error": "An active or pending request already exists for this service number."})
                    return
                connection.execute(
                    """INSERT INTO official_access
                       (service_key, service_number, full_name, official_type, agency_unit,
                        passcode_salt, passcode_hash, photo_data, fingerprint_enrolled,
                        status, requested_epoch, reviewer, reviewed_epoch)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 'pending', ?, NULL, NULL)
                       ON CONFLICT(service_key) DO UPDATE SET
                           service_number=excluded.service_number, full_name=excluded.full_name,
                           official_type=excluded.official_type, agency_unit=excluded.agency_unit,
                           passcode_salt=excluded.passcode_salt, passcode_hash=excluded.passcode_hash,
                           photo_data=excluded.photo_data, fingerprint_enrolled=1, status='pending',
                           requested_epoch=excluded.requested_epoch, reviewer=NULL, reviewed_epoch=NULL""",
                    (service_key, service_number, name, official_type, agency_unit, salt.hex(),
                     passcode_hash.hex(), photo, now),
                )
                connection.commit()
            finally:
                connection.close()
            audit_event(service_number, "OFFICIAL ACCESS REQUEST SUBMITTED",
                        "Submitted official access request with demo fingerprint verification",
                        service_number, {"officialType": official_type, "agencyUnit": agency_unit})
            self._json(201, {"ok": True, "status": "pending"})
            return
        if path == "/api/auth/login":
            service_number = clean_text(str(payload.get("serviceNumber", "")), 80)
            official_type = clean_text(str(payload.get("officialType", "")), 80)
            passcode = payload.get("passcode")
            if not service_number or official_type not in OFFICIAL_TYPES or not isinstance(passcode, str):
                self._json(400, {"error": "Enter a valid service number, official type, and passcode."})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                row = connection.execute(
                    """SELECT official_type, passcode_salt, passcode_hash, status
                       FROM official_access WHERE service_key=?""",
                    (service_number.casefold(),),
                ).fetchone()
            finally:
                connection.close()
            if (
                not row or row[0] != official_type or row[3] != "approved"
                or payload.get("fingerprintVerified") is not True
            ):
                self._json(401, {"error": "No approved active account matches those sign-in details."})
                return
            expected = hashlib.pbkdf2_hmac(
                "sha256", passcode.encode("utf-8"), bytes.fromhex(row[1]), PASSCODE_ITERATIONS
            ).hex()
            if not hmac.compare_digest(expected, row[2]):
                self._json(401, {"error": "No approved active account matches those sign-in details."})
                return
            token = secrets.token_urlsafe(32)
            AUTH_SESSIONS[token] = {
                "service": service_number, "type": official_type, "expires": time.time() + 12 * 60 * 60,
            }
            audit_event(service_number, "OFFICIAL SIGN-IN", "Approved official authenticated using passcode and demo scan",
                        service_number, {"officialType": official_type})
            self._json(200, {"ok": True, "serviceNumber": service_number,
                             "officialType": official_type, "sessionToken": token})
            return
        if path.startswith("/api/admin/access-requests/") and path.endswith("/decision"):
            if not self._require_demo_supervisor():
                return
            service_number = urllib.parse.unquote(
                path.removeprefix("/api/admin/access-requests/").removesuffix("/decision")
            )
            decision = payload.get("decision")
            reason = clean_text(str(payload.get("reason", "")), 500)
            if decision not in {"accept", "reject"} or not reason:
                self._json(400, {"error": "Choose accept or reject and provide a review reason."})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                row = connection.execute(
                    "SELECT service_number, status FROM official_access WHERE service_key=?",
                    (service_number.casefold(),),
                ).fetchone()
                if not row:
                    self._json(404, {"error": "Access request not found."})
                    return
                if row[1] != "pending":
                    self._json(409, {"error": "This access request has already been reviewed."})
                    return
                status = "approved" if decision == "accept" else "rejected"
                cursor = connection.execute(
                    """UPDATE official_access SET status=?, reviewer=?, reviewed_epoch=?
                       WHERE service_key=? AND status='pending'""",
                    (status, who, time.time(), service_number.casefold()),
                )
                if cursor.rowcount != 1:
                    self._json(409, {"error": "This access request has already been reviewed."})
                    return
                connection.commit()
            finally:
                connection.close()
            audit_event(who, f"OFFICIAL ACCESS REQUEST {decision.upper()}", reason, row[0],
                        {"serviceNumber": row[0]})
            self._json(200, {"ok": True, "serviceNumber": row[0], "status": status})
            return
        if path.startswith("/api/admin/services/") and path.endswith("/cancel"):
            if not self._require_demo_supervisor():
                return
            service_number = urllib.parse.unquote(
                path.removeprefix("/api/admin/services/").removesuffix("/cancel")
            )
            reason = clean_text(str(payload.get("reason", "")), 500)
            if not reason:
                self._json(400, {"error": "A cancellation reason is required."})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                cursor = connection.execute(
                    """UPDATE official_access SET status='cancelled', reviewer=?, reviewed_epoch=?
                       WHERE service_key=? AND status='approved'""",
                    (who, time.time(), service_number.casefold()),
                )
                if cursor.rowcount != 1:
                    found = connection.execute(
                        "SELECT status FROM official_access WHERE service_key=?",
                        (service_number.casefold(),),
                    ).fetchone()
                    if not found:
                        self._json(404, {"error": "No service record was found for that number."})
                    else:
                        self._json(409, {"error": "Only an approved active service can be cancelled."})
                    return
                connection.commit()
            finally:
                connection.close()
            audit_event(who, "OFFICIAL SERVICE CANCELLED", reason, service_number,
                        {"serviceNumber": service_number})
            self._json(200, {"ok": True, "status": "cancelled"})
            return
        if path == "/api/workspace":
            required_lists = ("citizens", "notes", "savedCases", "accessRequests", "audit")
            if any(not isinstance(payload.get(key), list) for key in required_lists):
                self._json(400, {"error": "Workspace data must include citizen, note, case, access-request, and audit lists."})
                return
            data_json = json.dumps(
                {key: payload[key] for key in required_lists}, ensure_ascii=False, separators=(",", ":")
            )
            if len(data_json.encode("utf-8")) > 32 * 1024 * 1024:
                self._json(413, {"error": "Workspace data exceeds the 32 MB storage limit."})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                connection.execute(
                    """INSERT INTO app_workspace (workspace_id, data_json, updated_epoch)
                       VALUES ('shared', ?, ?)
                       ON CONFLICT(workspace_id) DO UPDATE SET
                           data_json=excluded.data_json, updated_epoch=excluded.updated_epoch""",
                    (data_json, time.time()),
                )
                connection.commit()
            finally:
                connection.close()
            self._json(200, {"ok": True})
            return
        if path == "/api/audit":
            action = payload.get("action")
            reason = clean_text(str(payload.get("reason", "")), 500)
            case_ref = clean_text(str(payload.get("caseRef", "—")), 100)
            if not isinstance(action, str):
                self._json(400, {"error": "An allowed audit action and reason are required."})
                return
            allowed = action in {"EARLY WARNING FILTER", "EARLY WARNING PAGE VIEW"} or (
                action.startswith("LINK ANALYSIS ") and len(action) <= 100
            )
            if not allowed or not reason:
                self._json(400, {"error": "An allowed audit action and reason are required."})
                return
            details = payload.get("details", {})
            if not isinstance(details, dict):
                self._json(400, {"error": "Audit details must be an object."})
                return
            audit_event(who, action, reason, case_ref, details)
            self._json(200, {"ok": True})
            return
        if path == "/api/link-analysis/location-requests":
            # Demo workflow only: production must validate identity/roles and authorization server-side
            # and obtain location data through a separately secured, lawful agency connector.
            legal = clean_text(str(payload.get("legalAuthorization", "")), 120)
            case_ref = clean_text(str(payload.get("caseRef", "")), 100)
            reason = clean_text(str(payload.get("reason", "")), 500)
            period_start = str(payload.get("periodStart", ""))
            period_end = str(payload.get("periodEnd", ""))
            people = payload.get("people")
            try:
                start_date = datetime.strptime(period_start, "%Y-%m-%d").date()
                end_date = datetime.strptime(period_end, "%Y-%m-%d").date()
            except ValueError:
                self._json(400, {"error": "Provide valid authorization start and end dates."})
                return
            if not legal or not case_ref or not reason or start_date > end_date:
                self._json(400, {"error": "Legal authorization, case, reason, and a valid authorized period are required."})
                return
            if not isinstance(people, list) or not 2 <= len(people) <= 10 or any(
                not isinstance(person, str) or not re.fullmatch(r"\d{11}", person) for person in people
            ) or len(set(people)) != len(people):
                self._json(400, {"error": "A location request must name between 2 and 10 distinct synthetic NINs."})
                return
            request_id = f"LAR-{uuid.uuid4().hex[:12].upper()}"
            now = time.time()
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                connection.execute(
                    """INSERT INTO link_location_requests
                       (id, requester, legal_authorization, case_ref, reason, period_start,
                        period_end, people_json, status, created_epoch)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
                    (request_id, who, legal, case_ref, reason, period_start, period_end,
                     json.dumps(people), now),
                )
                connection.commit()
            finally:
                connection.close()
            audit_event(who, "LINK ANALYSIS LOCATION AUTHORIZATION SUBMITTED", reason, case_ref,
                        {"requestId": request_id, "legalAuthorization": legal, "people": people,
                         "periodStart": period_start, "periodEnd": period_end})
            self._json(201, {"request": {
                "id": request_id, "requester": who, "legalAuthorization": legal, "caseRef": case_ref,
                "reason": reason, "periodStart": period_start, "periodEnd": period_end,
                "people": people, "status": "pending", "expiresAt": 0,
            }})
            return
        if path.startswith("/api/link-analysis/location-requests/") and path.endswith("/decision"):
            if not self._require_demo_supervisor():
                return
            request_id = urllib.parse.unquote(path.removeprefix("/api/link-analysis/location-requests/").removesuffix("/decision"))
            decision = payload.get("decision")
            reason = clean_text(str(payload.get("reason", "")), 500)
            if not isinstance(decision, str) or decision not in {"approve", "reject"} or not reason:
                self._json(400, {"error": "Choose approve or reject and provide a decision reason."})
                return
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                row = connection.execute(
                    "SELECT requester, case_ref, status FROM link_location_requests WHERE id=?",
                    (request_id,),
                ).fetchone()
                if not row:
                    self._json(404, {"error": "Location authorization request not found."})
                    return
                if row[0] == who:
                    self._json(403, {"error": "A supervisor cannot approve their own location request."})
                    return
                if row[2] != "pending":
                    self._json(409, {"error": "This location request has already been decided."})
                    return
                expiry = time.time() + 24 * 60 * 60 if decision == "approve" else None
                status = "approved" if decision == "approve" else "rejected"
                connection.execute(
                    """UPDATE link_location_requests
                       SET status=?, reviewer=?, decision_reason=?, expires_epoch=? WHERE id=?""",
                    (status, who, reason, expiry, request_id),
                )
                connection.commit()
            finally:
                connection.close()
            audit_event(who, f"LINK ANALYSIS LOCATION {decision.upper()}",
                        reason, row[1], {"requestId": request_id, "requester": row[0],
                                         "expiresEpoch": expiry})
            request_result = self._get_location_request(request_id)
            self._json(200, {"request": request_result})
            return
        if path == "/api/link-analysis/boards":
            case_ref = clean_text(str(payload.get("caseRef", "")), 100)
            reason = clean_text(str(payload.get("reason", "")), 500)
            people = payload.get("people")
            if (not case_ref or not reason or not isinstance(people, list)
                    or not 1 <= len(people) <= 10
                    or any(not isinstance(person, str) or not re.fullmatch(r"\d{11}", person) for person in people)
                    or len(set(people)) != len(people)):
                self._json(400, {"error": "A case, reason, and board of 1 to 10 records are required."})
                return
            board_id = f"LAB-{uuid.uuid4().hex[:12].upper()}"
            saved = {key: payload.get(key) for key in
                     ("caseRef", "reason", "type", "people", "links", "authorizationId")}
            connection = sqlite3.connect(DB_PATH, timeout=5)
            try:
                connection.execute(
                    """INSERT INTO saved_link_boards (id, who, case_ref, reason, board_json, saved_epoch)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (board_id, who, case_ref, reason, json.dumps(saved, ensure_ascii=False), time.time()),
                )
                connection.commit()
            finally:
                connection.close()
            audit_event(who, "LINK ANALYSIS BOARD SAVED", reason, case_ref,
                        {"boardId": board_id, "people": people, "type": saved["type"]})
            self._json(201, {"board": {"id": board_id, **saved}})
            return
        if path == "/api/pipeline/run":
            if not self._require_demo_supervisor():
                return
            run_pipeline("manual")
            self._json(200, public_state())
            return
        if path.startswith("/api/admin/connectors/"):
            if not self._require_demo_supervisor():
                return
            connector_id = urllib.parse.unquote(path.removeprefix("/api/admin/connectors/"))
            connector = CONNECTORS.get(connector_id)
            if not connector:
                self._json(404, {"error": "Unknown connector."})
                return
            enabled = payload.get("enabled")
            if not isinstance(enabled, bool):
                self._json(400, {"error": "enabled must be a boolean."})
                return
            if enabled and not connector.configured:
                self._json(409, {"error": "Connector cannot be enabled until its approved access is configured."})
                return
            connector.enabled = enabled
            if not enabled:
                connector.status = "not configured"
            audit_event(who, f"CONNECTOR {'ENABLED' if enabled else 'DISABLED'} · {connector.name}",
                        payload.get("reason", "Supervisor changed connector configuration"), details={"connector": connector.id})
            threading.Thread(target=run_pipeline, args=("connector-change",), daemon=True).start()
            self._json(200, {"connector": connector.state()})
            return
        if path.startswith("/api/admin/alerts/") and path.endswith("/review"):
            if not self._require_demo_supervisor():
                return
            alert_id = path.removeprefix("/api/admin/alerts/").removesuffix("/review")
            decision = payload.get("decision")
            if decision not in {"confirm", "reject"}:
                self._json(400, {"error": "decision must be confirm or reject."})
                return
            with STATE_LOCK:
                alert = PENDING_HIGH.pop(alert_id, None)
                if alert and decision == "confirm":
                    alert["requiresAnalystConfirmation"] = False
                    alert["analystReview"] = {"decision": "confirmed", "reviewer": who, "time": utc_now()}
                    ALERTS.insert(0, alert)
                    REVIEW_DECISIONS[alert_id] = {
                        "decision": "confirm", "reviewer": who, "time": alert["analystReview"]["time"],
                    }
                elif alert:
                    REVIEW_DECISIONS[alert_id] = {
                        "decision": "reject", "reviewer": who, "time": utc_now(),
                    }
            if not alert:
                self._json(404, {"error": "Pending alert not found."})
                return
            audit_event(who, f"ALERT ANALYST {decision.upper()} · {alert['title']}",
                        payload.get("reason", "Human analyst review"), payload.get("caseRef", "—"),
                        {"alertId": alert_id})
            self._json(200, {"ok": True, "decision": decision})
            return
        if path.startswith("/api/alerts/") and path.endswith("/action"):
            alert_id = path.removeprefix("/api/alerts/").removesuffix("/action")
            with STATE_LOCK:
                alert = next((item for item in ALERTS if item["id"] == alert_id), None)
            if not alert:
                self._json(404, {"error": "Alert not found."})
                return
            action = clean_text(str(payload.get("action", "")), 80)
            reason = clean_text(str(payload.get("reason", "")), 500)
            if action not in {"acknowledge", "flag", "mark_false_alarm", "escalate", "open"} or not reason:
                self._json(400, {"error": "Use a supported alert action and provide a reason."})
                return
            details = {"alertId": alert_id}
            if action == "open":
                details["action"] = action
            audit_event(who, f"ALERT {action.upper()} · {alert['title']}", reason,
                        payload.get("caseRef", "—"), details)
            self._json(200, {"ok": True})
            return
        if path.startswith("/api/alerts/") and path.endswith("/export"):
            alert_id = path.removeprefix("/api/alerts/").removesuffix("/export")
            with STATE_LOCK:
                alert = next((item for item in ALERTS if item["id"] == alert_id), None)
                export = json.loads(json.dumps(alert)) if alert else None
            if not export:
                self._json(404, {"error": "Alert not found."})
                return
            reason = clean_text(str(payload.get("reason", "")), 500)
            case_ref = clean_text(str(payload.get("caseRef", "—")), 100)
            if not reason:
                self._json(400, {"error": "An export reason is required."})
                return
            audit_event(who, f"ALERT EXPORT · {alert['title']}", reason, case_ref, {"alertId": alert_id})
            self._json(200, {"alert": export})
            return
        self._json(404, {"error": "Unknown API route."})

    @staticmethod
    def _location_request_json(row: tuple[Any, ...]) -> dict[str, Any]:
        expires_epoch = row[9] or 0
        status = row[8]
        if status == "approved" and expires_epoch <= time.time():
            status = "expired"
        return {
            "id": row[0], "requester": row[1], "legalAuthorization": row[2],
            "caseRef": row[3], "reason": row[4], "periodStart": row[5],
            "periodEnd": row[6], "people": json.loads(row[7]), "status": status,
            "expiresAt": int(expires_epoch * 1000),
        }

    def _get_location_request(self, request_id: str) -> dict[str, Any]:
        connection = sqlite3.connect(DB_PATH, timeout=5)
        try:
            row = connection.execute(
                """SELECT id, requester, legal_authorization, case_ref, reason,
                          period_start, period_end, people_json, status, expires_epoch
                   FROM link_location_requests WHERE id=?""", (request_id,)
            ).fetchone()
        finally:
            connection.close()
        if not row:
            raise RuntimeError("Saved location request disappeared before it could be returned.")
        return self._location_request_json(row)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[http] {self.address_string()} {fmt % args}", flush=True)


def main() -> None:
    initialise_database()
    import vf_image
    vf_image.initialise_forensics_tables()
    worker = threading.Thread(target=pipeline_loop, daemon=True)
    worker.start()
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"NSP prototype backend listening on http://127.0.0.1:{PORT}", flush=True)
    print(f"Connector interval: {PIPELINE_INTERVAL_SECONDS // 60} minutes", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
