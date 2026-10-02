"""wordlist: build a targeted password wordlist from site content.

TARGET_KIND "url". Fetches the target homepage plus up to 10 same-host
linked pages, extracts lowercased words (length 4 or more), and generates
mutations: year suffixes 2019-2026, common suffixes (123, !, @, #), and
leet-speak variants of the most frequent words. The wordlist is saved to the
workspace (or a local fallback file) and reported as an informational
finding.

Module contract: NAME, DESCRIPTION, TARGET_KIND, INTRUSIVE,
run(target, ctx) -> list[dict]. ctx provides .config, .log, .workspace,
.scope, .safe_mode and .allow_intrusive. Findings carry the keys module,
target, severity, confidence, title, description, evidence, cwe and
remediation.
"""

import html as html_module
import os
import re
from collections import Counter
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from arsenal.http import fetch
from arsenal.findings import make_finding

NAME = "wordlist"
DESCRIPTION = (
    "Builds a targeted password wordlist from words found on the target "
    "site, with year, suffix and leet mutations for authorized testing."
)
TARGET_KIND = "url"
INTRUSIVE = False

MAX_PAGES = 10
MAX_PAGE_BYTES = 200 * 1024
MAX_WORDS = 5000
TIMEOUT = 10

YEARS = [str(year) for year in range(2019, 2027)]
SUFFIXES = ["123", "!", "@", "#"]
LEET_MAP = {
    "a": "4",
    "b": "8",
    "e": "3",
    "g": "9",
    "i": "1",
    "l": "1",
    "o": "0",
    "s": "5",
    "t": "7",
}
TOP_LEET_WORDS = 50
MIN_WORD_LEN = 4


# ---------------------------------------------------------------------------
# Small internal helpers
# ---------------------------------------------------------------------------
class _LinkParser(HTMLParser):
    """Collects href attributes from anchor tags."""

    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for attr_name, value in attrs:
                if attr_name.lower() == "href" and value:
                    self.hrefs.append(value)


def _log(ctx, message):
    log = getattr(ctx, "log", None)
    if callable(log):
        try:
            log(message)
        except Exception:
            pass


def _make_finding(**fields):
    try:
        return make_finding(**fields)
    except Exception:
        return dict(fields)


def _http_get(url, timeout=TIMEOUT, max_bytes=None):
    """GET url. Returns (status, body text) via the canonical fetch()."""
    try:
        status, _headers, body, _final = fetch(url, timeout=timeout)
    except Exception:
        return None, ""
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)
    if max_bytes:
        text = text[:max_bytes]
    return status, text


def _http_text(url, timeout=TIMEOUT):
    status, text = _http_get(url, timeout=timeout)
    if not status or status >= 400:
        return ""
    return text


# ---------------------------------------------------------------------------
# Crawling and word extraction
# ---------------------------------------------------------------------------
def _discover_links(page_url, html):
    """Return ordered, deduplicated same-host page links."""
    found = []
    seen = set()
    base_netloc = urlparse(page_url).netloc.lower()

    def add(raw):
        if not raw or raw.startswith(("data:", "javascript:", "#", "mailto:")):
            return
        abs_url = urljoin(page_url, raw.strip())
        parts = urlparse(abs_url)
        if parts.scheme not in ("http", "https"):
            return
        if parts.netloc.lower() != base_netloc:
            return
        clean = parts._replace(fragment="").geturl()
        if clean not in seen and clean != page_url:
            seen.add(clean)
            found.append(clean)

    parser = _LinkParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    for href in parser.hrefs:
        add(href)
    return found


def _extract_words(html):
    """Strip markup and return lowercased words of length >= 4."""
    text = re.sub(r"(?is)<script.*?</script>", " ", html)
    text = re.sub(r"(?is)<style.*?</style>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = html_module.unescape(text)
    return [
        word.lower()
        for word in re.findall(r"[A-Za-z]{%d,}" % MIN_WORD_LEN, text)
    ]


def _leet(word):
    return "".join(LEET_MAP.get(char, char) for char in word)


def _generate_wordlist(counter):
    """Build the mutated wordlist, capped at MAX_WORDS entries."""
    ranked = [word for word, _ in counter.most_common()]
    words = []
    seen = set()

    def add(candidate):
        if len(words) >= MAX_WORDS:
            return False
        if candidate and candidate not in seen:
            seen.add(candidate)
            words.append(candidate)
        return len(words) < MAX_WORDS

    for word in ranked:
        if not add(word):
            break
        for year in YEARS:
            if not add(word + year):
                break
        for suffix in SUFFIXES:
            if not add(word + suffix):
                break
        if len(words) >= MAX_WORDS:
            break

    for word in ranked[:TOP_LEET_WORDS]:
        variant = _leet(word)
        if variant != word:
            if not add(variant):
                break
    return words


def _save_wordlist(ctx, target, content):
    """Save via the workspace when available, else a local fallback file."""
    workspace = getattr(ctx, "workspace", None)
    if workspace is not None and hasattr(workspace, "save_blob"):
        try:
            saved = workspace.save_blob(target, "wordlist.txt", content)
            if saved:
                return str(saved)
            return "workspace:wordlist.txt"
        except Exception:
            pass
    host = urlparse(target).netloc or "target"
    safe_host = re.sub(r"[^A-Za-z0-9._-]", "_", host)
    path = os.path.abspath("wordlist-%s.txt" % safe_host)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def _run(target, ctx):
    findings = []
    html = _http_text(target, timeout=TIMEOUT)
    if not html:
        _log(ctx, "wordlist: could not fetch page %s" % target)
        return findings

    pages = [html]
    links = _discover_links(target, html)[:MAX_PAGES]
    _log(
        ctx,
        "wordlist: fetching %d linked page(s) for %s" % (len(links), target),
    )
    for link in links:
        status, body = _http_get(link, timeout=TIMEOUT, max_bytes=MAX_PAGE_BYTES)
        if status == 200 and body:
            pages.append(body[:MAX_PAGE_BYTES])

    counter = Counter()
    for page in pages:
        counter.update(_extract_words(page))
    if not counter:
        _log(ctx, "wordlist: no words extracted from %s" % target)
        return findings

    words = _generate_wordlist(counter)
    content = "\n".join(words) + "\n"
    try:
        saved_path = _save_wordlist(ctx, target, content)
    except Exception as exc:
        _log(ctx, "wordlist: could not save wordlist: %s" % exc)
        return findings

    _log(
        ctx,
        "wordlist: generated %d entries from %d page(s) for %s"
        % (len(words), len(pages), target),
    )
    findings.append(
        _make_finding(
            module=NAME,
            target=target,
            severity="info",
            confidence="strong",
            title="Targeted wordlist generated from site content",
            description=(
                "Crawled %d page(s) on %s, extracted %d unique words and "
                "generated %d wordlist entries with year (2019-2026), suffix "
                "and leet mutations for authorized password testing."
                % (len(pages), target, len(counter), len(words))
            ),
            evidence="wordlist path: %s | entries: %d" % (saved_path, len(words)),
            cwe="N/A",
            remediation=(
                "Informational artifact only. Use solely against systems you "
                "are authorized to test."
            ),
        )
    )
    return findings


def run(target, ctx):
    """Build a targeted wordlist from the target site's content."""
    try:
        return _run(target, ctx)
    except Exception as exc:
        _log(ctx, "wordlist: unexpected error: %s" % exc)
        return []
