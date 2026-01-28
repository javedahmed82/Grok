#!/usr/bin/env python3
"""
RSS Crypto Security Alerts -> Telegram

Features:
- Alert-only filtering (hack/drainer/scam/exploit)
- Impact score + BREAKING tag
- Clean MarkdownV2 formatting (safe escaping)
- Image handling: downloads OG image and uploads to Telegram (fixes "Wrong type of web page content")
- Caption length fix: short caption + long message split
- Memory persistence: saves item hash + telegram message_id + metadata into posted_memory.json
- Duplicate avoidance across runs using posted_memory.json (plus optional GitHub artifact persistence)

Env:
  TELEGRAM_BOT_TOKEN (required)
  TELEGRAM_CHAT_ID (required)
  MEMORY_FILE (default: posted_memory.json)
  MAX_POSTS_PER_RUN (default: 5)

Optional:
  RSS_FEEDS  (comma-separated; if empty uses default FEEDS list)
  ALERT_ONLY (1/true) -> only post alerts
  QUIET_HOURS (e.g. "01:00-07:00") -> only very high impact allowed in quiet hours
"""

import argparse
import asyncio
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone, time as dtime
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import feedparser
import httpx
from bs4 import BeautifulSoup
from telegram import Bot, InputFile
from telegram.constants import ParseMode
from telegram.error import BadRequest

# -------------------------
# Config
# -------------------------
DEFAULT_FEEDS = [
    # Security / Scam / Exploit focused (RSS or Atom)
    "https://medium.com/feed/@slowmist",                 # SlowMist Medium feed
    "https://scamsniffer.medium.com/feed",               # ScamSniffer Medium feed (if it works)
    "https://medium.com/feed/@revoke.cash",              # Revoke.cash Medium feed (some posts)
    "https://blog.certik.com/rss",                       # CertiK blog RSS (may redirect)
    "https://defillama.com/blog/rss.xml",                # DeFiLlama blog RSS
    "https://rekt.news/rss",                             # rekt.news RSS (if available)
]

RISK_KEYWORDS = [
    "wallet drainer", "drainer", "phishing", "fake site", "fake website", "malicious",
    "exploit", "hacked", "hack", "breach", "compromised", "stolen", "drained",
    "rug pull", "rugpull", "exit scam", "scam", "fraud", "honeypot",
    "bridge hack", "protocol hack", "approval", "setapprovalforall", "permit",
    "airdrop scam", "fake airdrop",
]

NETWORK_KEYWORDS = {
    "BNB (BSC)": ["bsc", "bnb chain", "bnb smart chain", "binance smart chain", "bep20", "bep-20"],
    "Ethereum": ["ethereum", "eth", "erc20", "erc-20", "mainnet"],
    "Solana": ["solana", "sol"],
    "Polygon": ["polygon", "matic"],
    "Arbitrum": ["arbitrum"],
    "Optimism": ["optimism"],
    "Avalanche": ["avalanche", "avax"],
    "Base": ["base chain", "coinbase base", "base l2", "base layer 2"],
    "Tron": ["tron", "trx"],
    "TON": ["ton", "toncoin", "the open network"],
    "XRP Ledger": ["xrp ledger", "xrpl", "ripple ledger"],
}

# Impact scoring weights (very simple heuristic)
IMPACT_RULES = [
    (re.compile(r"\b(bridge hack|bridge exploit)\b", re.I), 10),
    (re.compile(r"\b(funds?\s+(stolen|drained)|stolen funds)\b", re.I), 9),
    (re.compile(r"\b(wallet drainer|drainer)\b", re.I), 9),
    (re.compile(r"\b(exploit|hacked|hack)\b", re.I), 8),
    (re.compile(r"\b(phishing|fake (site|website)|malicious)\b", re.I), 7),
    (re.compile(r"\b(rug pull|rugpull|honeypot|exit scam)\b", re.I), 8),
    (re.compile(r"\b(vulnerability|critical bug|zero[- ]day)\b", re.I), 7),
    (re.compile(r"\b(advisory|report|analysis)\b", re.I), 4),
]

MARKDOWN_V2_SPECIAL = r"_*[]()~`>#+-=|{}.!\\"

def mdv2_escape(text: str) -> str:
    """Escape text for Telegram MarkdownV2."""
    if not text:
        return ""
    out = []
    for ch in text:
        if ch in MARKDOWN_V2_SPECIAL:
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()

def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))

def parse_bool(v: Optional[str], default: bool = False) -> bool:
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")

def within_quiet_hours(qh: str) -> bool:
    # qh format: "01:00-07:00"
    try:
        a, b = qh.split("-", 1)
        ah, am = map(int, a.split(":"))
        bh, bm = map(int, b.split(":"))
        start = dtime(ah, am)
        end = dtime(bh, bm)
        # local timezone not known in GH runner; assume UTC for quiet hours unless you want to set TZ
        t = datetime.now(timezone.utc).time()
        if start <= end:
            return start <= t <= end
        # wrap-around
        return t >= start or t <= end
    except Exception:
        return False

@dataclass
class Item:
    title: str
    link: str
    source: str
    published: str
    summary: str
    uid: str

# -------------------------
# Memory (posted_memory.json)
# -------------------------
def load_memory(path: str) -> Dict[str, Dict[str, Any]]:
    """
    Returns dict keyed by uid/hash -> metadata
    """
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        if isinstance(data, list):
            # legacy list -> convert
            mem = {}
            for x in data:
                if isinstance(x, str):
                    mem[x] = {"uid": x}
                elif isinstance(x, dict) and x.get("uid"):
                    mem[str(x["uid"])] = x
            return mem
        return {}
    except Exception:
        return {}

def save_memory(path: str, mem: Dict[str, Dict[str, Any]]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(mem, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

# -------------------------
# RSS + Article extraction
# -------------------------
async def fetch_url(client: httpx.AsyncClient, url: str, timeout: float = 20.0) -> Optional[str]:
    try:
        r = await client.get(url, timeout=timeout, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (compatible; GrokPediaBot/1.0; +https://example.com)"
        })
        if r.status_code >= 400:
            return None
        return r.text
    except Exception:
        return None

def html_to_text(html: str, max_chars: int = 1600) -> str:
    soup = BeautifulSoup(html, "html.parser")
    # Remove scripts/styles
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = soup.get_text("\n")
    text = re.sub(r"\n{3,}", "\n\n", text).strip()
    if len(text) > max_chars:
        text = text[:max_chars].rstrip() + "..."
    return text

def extract_og_image(html: str) -> Optional[str]:
    soup = BeautifulSoup(html, "html.parser")
    for prop in ["og:image", "twitter:image", "twitter:image:src"]:
        tag = soup.find("meta", attrs={"property": prop}) or soup.find("meta", attrs={"name": prop})
        if tag and tag.get("content"):
            return tag["content"].strip()
    return None

async def download_image_bytes(client: httpx.AsyncClient, url: str, max_bytes: int = 3_500_000) -> Optional[Tuple[bytes, str]]:
    """
    Downloads image and returns (bytes, filename). Returns None if not image or too large.
    Fixes Telegram "Wrong type of web page content" by uploading bytes.
    """
    try:
        r = await client.get(url, timeout=20.0, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (compatible; GrokPediaBot/1.0)"
        })
        if r.status_code >= 400:
            return None
        ctype = r.headers.get("content-type", "").lower()
        if not ctype.startswith("image/"):
            return None
        content = r.content
        if not content or len(content) > max_bytes:
            return None
        ext = "jpg"
        if "png" in ctype:
            ext = "png"
        elif "webp" in ctype:
            ext = "webp"
        elif "jpeg" in ctype or "jpg" in ctype:
            ext = "jpg"
        filename = f"image.{ext}"
        return content, filename
    except Exception:
        return None

def detect_network(text: str) -> str:
    t = text.lower()
    for net, keys in NETWORK_KEYWORDS.items():
        for k in keys:
            if k in t:
                return net
    return "Multi / Unknown"

def risk_tags(text: str) -> List[str]:
    t = text.lower()
    tags = []
    if any(k in t for k in ["wallet drainer", "drainer"]):
        tags.append("drainer")
    if any(k in t for k in ["phishing", "fake site", "fake website"]):
        tags.append("phishing")
    if any(k in t for k in ["exploit", "hacked", "hack", "breach", "compromised"]):
        tags.append("exploit")
    if any(k in t for k in ["rug pull", "rugpull", "honeypot", "exit scam"]):
        tags.append("scam")
    if any(k in t for k in ["stolen", "drained", "funds"]):
        tags.append("funds")
    return sorted(set(tags))

def is_alert(text: str) -> bool:
    t = text.lower()
    return any(k in t for k in RISK_KEYWORDS)

def impact_score(text: str) -> int:
    score = 0
    for rgx, val in IMPACT_RULES:
        if rgx.search(text):
            score = max(score, val)
    # small boost if multiple tags
    score += min(2, len(risk_tags(text)))
    return clamp(score, 1, 10)

def short_action_block(tags: List[str]) -> List[str]:
    # Context-aware “What to do NOW” in English
    actions = []
    if "drainer" in tags or "phishing" in tags:
        actions += [
            "Do NOT sign unknown transactions",
            "Revoke token approvals (revoke.cash)",
            "Disconnect wallet + clear dApp connections",
            "Avoid unknown links / DMs",
        ]
    if "exploit" in tags:
        actions += [
            "Stop interacting with the affected dApp",
            "Move funds to a safer wallet if needed",
            "Follow official incident updates",
        ]
    if "scam" in tags:
        actions += [
            "Do NOT buy or add liquidity",
            "Check contract risk (honeypot / taxes)",
            "Warn others and report the link",
        ]
    # de-dup while preserving order
    seen = set()
    out = []
    for a in actions:
        if a not in seen:
            seen.add(a)
            out.append(a)
    # Always keep it short
    return out[:5] if out else [
        "Do NOT sign unknown transactions",
        "Avoid unknown links",
        "Revoke suspicious approvals",
    ]

def build_alert_message(item: Item, context_text: str) -> Tuple[str, str]:
    """
    Returns (caption, body) in MarkdownV2.
    Caption must be <= 1024 for photo.
    Body must be split if > 4096 when sending.
    """
    combined = f"{item.title}\n{item.summary}\n{context_text}\n{item.link}\n{item.source}"
    tags = risk_tags(combined)
    net = detect_network(combined)
    score = impact_score(combined)

    header = "🚨 *BREAKING ALERT*" if score >= 8 else "🚨 *ALERT*"
    tag_line = f"🏷️ *Tags:* {', '.join(tags) if tags else 'risk'}"
    net_line = f"🧷 *Network:* {mdv2_escape(net)}"
    score_line = f"📊 *Impact:* 🔴 *{mdv2_escape('VERY HIGH' if score>=9 else 'HIGH' if score>=7 else 'MEDIUM')}* \\({score}/10\\)"

    # Risk bullets in pure English
    risk_bullets = []
    if "drainer" in tags:
        risk_bullets.append("Fake sites may drain wallets")
    if "phishing" in tags:
        risk_bullets.append("Phishing links can steal approvals / signatures")
    if "exploit" in tags:
        risk_bullets.append("Exploit activity may impact users")
    if "scam" in tags:
        risk_bullets.append("Scam behavior detected (rug / honeypot / fake token)")
    if not risk_bullets:
        risk_bullets = ["Potential security risk – verify before interacting"]

    actions = short_action_block(tags)

    title_line = f"*Title:* {mdv2_escape(item.title)}"
    source_line = f"🔗 *Source:* {mdv2_escape(item.source)}"
    time_line = f"🕒 *Time:* {mdv2_escape(item.published)}"

    risk_block = "\n".join([f"• {mdv2_escape(x)}" for x in risk_bullets])
    action_block = "\n".join([f"• {mdv2_escape(x)}" for x in actions])

    # Keep context shortish; full article can be opened via link
    context_clean = context_text.strip()
    if len(context_clean) > 1200:
        context_clean = context_clean[:1200].rstrip() + "..."
    context_clean = mdv2_escape(context_clean)

    body = (
        f"{header}\n"
        f"{title_line}\n"
        f"{net_line}\n"
        f"{tag_line}\n\n"
        f"⚠️ *Risk*\n{risk_block}\n\n"
        f"🧠 *What to do NOW*\n{action_block}\n\n"
        f"{score_line}\n"
        f"🔥 *Action:* *{mdv2_escape('STAY AWAY' if score>=7 else 'BE CAREFUL')}*\n\n"
        f"🧩 *Context*\n{context_clean}\n\n"
        f"{source_line}\n"
        f"👉 *Open Link:* {mdv2_escape(item.link)}\n"
        f"{time_line}"
    )

    # Caption should be short (<=1024). Put only header + title + impact.
    caption = (
        f"{header}\n"
        f"{mdv2_escape(item.title)}\n"
        f"{score_line}"
    )
    # Hard trim caption to safe length
    if len(caption) > 950:
        caption = caption[:950].rstrip() + "..."

    return caption, body

def split_telegram_text(text: str, limit: int = 4096) -> List[str]:
    if len(text) <= limit:
        return [text]
    parts = []
    buf = ""
    for line in text.split("\n"):
        # +1 for newline
        if len(buf) + len(line) + 1 > limit:
            if buf:
                parts.append(buf)
            buf = line
        else:
            buf = buf + ("\n" if buf else "") + line
    if buf:
        parts.append(buf)
    return parts

# -------------------------
# Telegram sending
# -------------------------
async def safe_send_alert(
    bot: Bot,
    chat_id: str,
    caption: str,
    body: str,
    image_bytes: Optional[Tuple[bytes, str]] = None,
) -> List[int]:
    """
    Sends alert with optional image.
    Returns list of telegram message_ids created.
    """
    sent_ids: List[int] = []

    body_parts = split_telegram_text(body, 4096)

    # If we have an image -> send photo with caption (short) then send body as message(s)
    if image_bytes:
        b, filename = image_bytes
        bio = InputFile(fp=io_bytes(b), filename=filename)
        try:
            msg = await bot.send_photo(
                chat_id=chat_id,
                photo=bio,
                caption=caption,
                parse_mode=ParseMode.MARKDOWN_V2,
            )
            sent_ids.append(msg.message_id)
        except BadRequest as e:
            # fallback: send without parse_mode
            msg = await bot.send_photo(chat_id=chat_id, photo=bio, caption=strip_markdown_v2(caption))
            sent_ids.append(msg.message_id)

        # Now send the long body as separate messages (without duplicating header too much)
        for i, part in enumerate(body_parts):
            # avoid repeating header if you want: keep full body (user asked long)
            try:
                m = await bot.send_message(chat_id=chat_id, text=part, parse_mode=ParseMode.MARKDOWN_V2, disable_web_page_preview=False)
                sent_ids.append(m.message_id)
            except BadRequest:
                m = await bot.send_message(chat_id=chat_id, text=strip_markdown_v2(part), disable_web_page_preview=False)
                sent_ids.append(m.message_id)
        return sent_ids

    # No image: just send body (can include preview)
    for part in body_parts:
        try:
            m = await bot.send_message(chat_id=chat_id, text=part, parse_mode=ParseMode.MARKDOWN_V2, disable_web_page_preview=False)
            sent_ids.append(m.message_id)
        except BadRequest:
            m = await bot.send_message(chat_id=chat_id, text=strip_markdown_v2(part), disable_web_page_preview=False)
            sent_ids.append(m.message_id)

    return sent_ids

def io_bytes(b: bytes):
    import io
    return io.BytesIO(b)

def strip_markdown_v2(text: str) -> str:
    # remove backslashes used for escaping, keep readable plain text
    return text.replace("\\", "")

# -------------------------
# Main run
# -------------------------
async def collect_items(client: httpx.AsyncClient, feeds: List[str], max_items_per_feed: int = 10) -> List[Item]:
    items: List[Item] = []
    for feed_url in feeds:
        raw = await fetch_url(client, feed_url)
        if not raw:
            continue
        parsed = feedparser.parse(raw)
        source = parsed.feed.get("title", urlparse(feed_url).netloc) or urlparse(feed_url).netloc
        for e in parsed.entries[:max_items_per_feed]:
            title = (e.get("title") or "").strip()
            link = (e.get("link") or "").strip()
            summary = (e.get("summary") or e.get("description") or "").strip()

            published = e.get("published") or e.get("updated") or now_utc_iso()
            # Make UID stable: prefer link; fallback to title+published
            uid = sha1(link or (title + "|" + str(published) + "|" + source))

            items.append(Item(
                title=title or "Untitled",
                link=link,
                source=source,
                published=str(published),
                summary=BeautifulSoup(summary, "html.parser").get_text(" ").strip(),
                uid=uid,
            ))
    # newest first is tricky without dates; keep as collected
    return items

async def build_context_and_image(client: httpx.AsyncClient, item: Item) -> Tuple[str, Optional[Tuple[bytes, str]]]:
    """
    Fetch article HTML and extract context + og:image bytes.
    """
    if not item.link:
        return item.summary[:800], None

    html = await fetch_url(client, item.link)
    if not html:
        return item.summary[:800], None

    context = html_to_text(html, max_chars=1400)
    og = extract_og_image(html)
    img_bytes = None
    if og:
        img_bytes = await download_image_bytes(client, og)
    return context or item.summary[:800], img_bytes

async def run_once() -> int:
    token = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if not token or not chat_id:
        raise SystemExit("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")

    memory_file = os.getenv("MEMORY_FILE", "posted_memory.json")
    max_posts = int(os.getenv("MAX_POSTS_PER_RUN", "5"))
    alert_only = parse_bool(os.getenv("ALERT_ONLY"), default=False)
    quiet_hours = os.getenv("QUIET_HOURS", "").strip()

    feeds_env = os.getenv("RSS_FEEDS", "").strip()
    feeds = [x.strip() for x in feeds_env.split(",") if x.strip()] if feeds_env else DEFAULT_FEEDS

    mem = load_memory(memory_file)

    bot = Bot(token=token)

    posted = 0
    async with httpx.AsyncClient() as client:
        items = await collect_items(client, feeds, max_items_per_feed=12)

        for it in items:
            if posted >= max_posts:
                break

            # duplicate check
            if it.uid in mem:
                continue

            combined = f"{it.title}\n{it.summary}\n{it.link}\n{it.source}"
            if alert_only and not is_alert(combined):
                continue

            # Quiet hours: only allow very high impact
            if quiet_hours and within_quiet_hours(quiet_hours):
                if impact_score(combined) < 9:
                    continue

            context, img = await build_context_and_image(client, it)

            caption, body = build_alert_message(it, context)

            # Send
            ids = await safe_send_alert(bot, chat_id, caption, body, image_bytes=img)

            # Save memory with telegram message_ids
            mem[it.uid] = {
                "uid": it.uid,
                "title": it.title,
                "link": it.link,
                "source": it.source,
                "published": it.published,
                "tags": risk_tags(combined),
                "impact": impact_score(combined),
                "telegram_message_ids": ids,
                "posted_at": now_utc_iso(),
            }
            save_memory(memory_file, mem)
            posted += 1

    print(f"[INFO] Posted {posted} alert(s). MEMORY_FILE={memory_file} saved={len(mem)}")
    return posted

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true", help="Run one cycle and exit")
    args = ap.parse_args()

    if args.once:
        asyncio.run(run_once())
    else:
        asyncio.run(run_once())

if __name__ == "__main__":
    main()