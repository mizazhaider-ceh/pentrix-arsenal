"""VISUAL RECON for PENTRIX ARSENAL.

capture(url, out_path, ctx) fetches a page and renders a *structural*
thumbnail: the HTML tag tree is parsed and drawn as colored blocks with
PIL into an 800x600 PNG. This is the offline default backend; it needs
no browser and no network beyond the target fetch itself.

dhash(path) -> int computes a 64-bit difference hash of a thumbnail.
cluster(hashes) groups near-duplicate thumbnails (hamming distance <= 6)
so outliers (login pages, error pages, parked domains) surface quickly.
visual_changed(old_path, new_path) -> bool reports True when the
perceptual distance exceeds 10 bits.

Backend note: for pixel-accurate screenshots, plug in a real browser
backend via capture_live() below. The current stub documents the
integration point; wire it to Playwright (or similar) by implementing
the documented steps. The structural renderer stays the offline default.
"""

import os
import urllib.request
from html.parser import HTMLParser

from PIL import Image, ImageDraw, ImageFont

WIDTH, HEIGHT = 800, 600

TAG_COLORS = {
    "h1": (240, 240, 245),
    "h2": (225, 228, 235),
    "h3": (210, 214, 224),
    "form": (255, 110, 110),
    "input": (255, 190, 60),
    "button": (255, 150, 60),
    "select": (255, 190, 60),
    "textarea": (255, 190, 60),
    "label": (255, 205, 120),
    "img": (110, 200, 130),
    "video": (90, 180, 160),
    "iframe": (120, 160, 200),
    "table": (170, 120, 235),
    "a": (110, 170, 255),
    "nav": (90, 140, 230),
    "header": (130, 150, 210),
    "footer": (130, 150, 210),
    "p": (190, 200, 215),
    "ul": (200, 180, 150),
    "li": (215, 200, 175),
    "div": (70, 110, 190),
    "section": (80, 125, 200),
    "article": (85, 130, 205),
    "aside": (100, 120, 190),
    "main": (75, 118, 195),
    "span": (150, 165, 190),
}

BLOCK_TAGS = set(TAG_COLORS)

TAG_HEIGHTS = {
    "h1": 46, "h2": 38, "h3": 32, "form": 74, "input": 26,
    "button": 30, "select": 26, "textarea": 44, "label": 22,
    "img": 64, "video": 64, "iframe": 56, "table": 54, "a": 24,
    "nav": 40, "header": 44, "footer": 44, "p": 26, "ul": 40,
    "li": 22, "div": 26, "section": 30, "article": 30,
    "aside": 30, "main": 30, "span": 20,
}


class _TagParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []  # list of (tag, depth)
        self.title = ""
        self._in_title = False
        self._depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag == "title":
            self._in_title = True
            return
        if tag in BLOCK_TAGS:
            self.tags.append((tag, self._depth))
        self._depth += 1

    def handle_endtag(self, tag):
        self._depth = max(0, self._depth - 1)
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data.strip() + " "


def _fetch_html(url: str, timeout: int = 15) -> str:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "PentrixArsenal/1.0 (visual recon)"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read(2_000_000)
    for encoding in ("utf-8", "latin-1"):
        try:
            return raw.decode(encoding)
        except Exception:
            continue
    return ""


def _render_structure(tags, title, out_path):
    img = Image.new("RGB", (WIDTH, HEIGHT), (18, 22, 32))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.load_default()
    except Exception:
        font = None

    # Title bar
    draw.rectangle([0, 0, WIDTH, 56], fill=(28, 34, 48))
    label = (title or "untitled").strip()[:72]
    draw.text((16, 18), label, fill=(235, 240, 250), font=font)

    y = 76
    for tag, depth in tags[:220]:
        h = TAG_HEIGHTS.get(tag, 24)
        if y + h > HEIGHT - 12:
            break
        x = 24 + min(depth, 8) * 26
        w = max(120, WIDTH - 48 - min(depth, 8) * 26)
        color = TAG_COLORS.get(tag, (120, 130, 150))
        draw.rectangle([x, y, x + w, y + h], fill=color, outline=(10, 14, 22))
        draw.text((x + 8, y + 6), tag, fill=(15, 18, 26), font=font)
        y += h + 6

    img.save(out_path, "PNG")
    return out_path


def _render_error(message, out_path):
    img = Image.new("RGB", (WIDTH, HEIGHT), (40, 20, 24))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.load_default()
    except Exception:
        font = None
    draw.text((24, 24), "visual recon: fetch failed", fill=(255, 150, 150), font=font)
    draw.text((24, 52), str(message)[:100], fill=(200, 170, 170), font=font)
    img.save(out_path, "PNG")
    return out_path


def capture(url: str, out_path: str, ctx=None) -> str:
    """Fetch *url* and render a structural thumbnail PNG to *out_path*.

    Never raises: on fetch/parse failure an error placeholder PNG is
    written instead so pipelines keep running. Returns out_path.
    """
    try:
        directory = os.path.dirname(os.path.abspath(out_path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        html_text = _fetch_html(url)
        parser = _TagParser()
        try:
            parser.feed(html_text)
        except Exception:
            pass
        return _render_structure(parser.tags, parser.title, out_path)
    except Exception as exc:  # network or filesystem failure
        try:
            return _render_error(exc, out_path)
        except Exception:
            return out_path


def capture_live(url: str, out_path: str, backend: str = "playwright") -> str:
    """Optional real-screenshot hook (NOT the default backend).

    Integration steps for the operator:
      1. pip install playwright && playwright install chromium
      2. Implement: launch headless chromium, goto(url),
         wait for network idle, screenshot full page to out_path.
      3. Replace this stub body with that logic.

    Raises RuntimeError until a real backend is wired in.
    """
    raise RuntimeError(
        "capture_live: no %s backend configured. Follow the docstring "
        "steps to wire one in, or use capture() for the offline "
        "structural renderer." % backend
    )


def dhash(path: str) -> int:
    """64-bit difference hash of an image file (grayscale 9x8)."""
    img = Image.open(path).convert("L").resize((9, 8), Image.LANCZOS)
    pixels = list(img.getdata())
    bits = 0
    for row in range(8):
        base = row * 9
        for col in range(8):
            bits = (bits << 1) | (1 if pixels[base + col] > pixels[base + col + 1] else 0)
    return bits


def hamming(a: int, b: int) -> int:
    """Hamming distance between two integer hashes."""
    return bin(int(a) ^ int(b)).count("1")


def cluster(hashes: dict) -> list:
    """Group thumbnails whose dhash hamming distance is <= 6.

    hashes: mapping of name -> int hash. Returns a list of groups, each
    a sorted list of names. Singletons are returned as their own group.
    """
    names = list(hashes.keys())
    parent = {n: n for n in names}

    def find(n):
        while parent[n] != n:
            parent[n] = parent[parent[n]]
            n = parent[n]
        return n

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            try:
                if hamming(hashes[names[i]], hashes[names[j]]) <= 6:
                    union(names[i], names[j])
            except Exception:
                continue

    groups = {}
    for n in names:
        groups.setdefault(find(n), []).append(n)
    return [sorted(g) for g in groups.values()]


def visual_changed(old_path: str, new_path: str, threshold: int = 10) -> bool:
    """True when two thumbnails differ by more than *threshold* bits."""
    try:
        return hamming(dhash(old_path), dhash(new_path)) > threshold
    except Exception:
        return False
