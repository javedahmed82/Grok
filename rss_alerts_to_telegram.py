#!/usr/bin/env python3
import argparse
import asyncio
import hashlib
import io
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from html import unescape as html_unescape
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import feedparser
import httpx
from bs4 import BeautifulSoup
from telegram import Bot, InputFile
from telegram.constants import ParseMode
from telegram.error import BadRequest


# =========================
# ENV
# =========================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

MEMORY_FILE = os.getenv("MEMORY_FILE", "posted_memory.json").strip()
MAX_POSTS_PER_RUN = int(os.getenv("MAX_POSTS_PER_RUN", "5"))
ALERT_ONLY = os.getenv("ALERT_ONLY", "true").strip().lower() in ("1", "true", "yes", "y")
DISABLE_WEB_PREVIEW = os.getenv("DISABLE_WEB_PREVIEW", "0").strip().lower() in ("1", "true", "yes", "y")

# Optional: override feeds via env (rare)
# Format:
#   RSS_FEEDS=CRYPTO|https://...,CYBERCRIME|https://...
RSS_FEEDS_ENV = os.getenv("RSS_FEEDS", "").strip()


# =========================
# FEEDS (tagged)
# =========================
DEFAULT_FEEDS: List[Tuple[str, str]] = [
    # --- CRYPTO security / scam / exploit ---
    ("CRYPTO", "https://medium.com/feed/@slowmist"),
    ("CRYPTO", "https://scamsniffer.medium.com/feed"),
    ("CRYPTO", "https://blog.certik.com/rss"),
    ("CRYPTO", "https://defillama.com/blog/rss.xml"),
    ("CRYPTO", "https://rekt.news/rss"),

    # --- Worldwide CYBERCRIME ---
    ("CYBERCRIME", "https://www.bleepingcomputer.com/feed/"),
    ("CYBERCRIME", "https://feeds.feedburner.com/TheHackersNews"),
    ("CYBERCRIME", "https://www.darkreading.com/rss.xml"),
    ("CYBERCRIME", "https://krebsonsecurity.com/feed/"),
    ("CYBERCRIME", "https://www.ransomware.live/rss.xml"),
    ("CYBERCRIME", "https://feeds.feedburner.com/HaveIBeenPwnedLatestBreaches"),
]


# =========================
# KEYWORDS (filtering)
# =========================
CRYPTO_KEYWORDS = [
    "wallet drainer", "drainer", "phishing", "fake site", "fake website", "malicious",
    "exploit", "exploited", "hacked", "hack", "breach", "compromised", "stolen", "drained",
    "rug pull", "rugpull", "exit scam", "scam", "fraud", "honeypot",
    "bridge hack", "approval", "setapprovalforall", "permit", "airdrop scam", "fake airdrop",
]

CYBER_KEYWORDS = [
    "ransomware", "data breach", "breach", "leak", "database leaked", "stolen data",
    "malware", "trojan", "botnet", "ddos", "zero-day", "0day", "zero day",
    "credential theft", "password leak", "account takeover", "phishing",
    "cyberattack", "cyber attack", "hacker group", "extortion", "backdoor",
]


# =========================
# Country / Region detection
# =========================
EU_COUNTRIES = [
    "austria","belgium","bulgaria","croatia","cyprus","czech","czech republic","denmark",
    "estonia","finland","france","germany","greece","hungary","ireland","italy","latvia",
    "lithuania","luxembourg","malta","netherlands","poland","portugal","romania","slovakia",
    "slovenia","spain","sweden","european union","eu "
]

US_PATTERNS = [r"\busa\b", r"\bunited states\b", r"\bu\.s\.\b", r"\bamerica\b", r"\bamerican\b"]
INDIA_PATTERNS = [r"\bindia\b", r"\bindian\b", r"\bdelhi\b", r"\bmumbai\b", r"\bbengaluru\b", r"\bbangalore\b", r"\bhyderabad\b"]


def detect_region(text: str) -> str:
    t = (text or "").lower()

    for p in US_PATTERNS:
        if re.search(p, t):
            return "US"

    for p in INDIA_PATTERNS:
        if re.search(p, t):
            return "India"

    # EU detection: explicit "EU" or any EU country name
    if " eu" in t or "european union" in t:
        return "EU"
    for c in EU_COUNTRIES:
        if c in t:
            return "EU"

    return "Global"


# =========================
# MarkdownV2 helpers
# =========================
MARKDOWN_V2_SPECIAL = r"_*[]()~`>#+-=|{}.!\\"

def mdv2_escape(text: str) -> str:
    if not text:
        return ""
    out = []
    for ch in text:
        if ch in MARKDOWN_V2_SPECIAL:
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)

def strip_mdv2(text: str) -> str:
    return (text or "").replace("\\", "")

def now_utc_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()

def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()


# =========================
# Memory
# =========================
def load_memory(path: str) -> Dict[str, Dict[str, Any]]:
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        return {}
    except Exception:
        return {}

def save_memory(path: str, mem: Dict[str, Dict[str, Any]]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(mem, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# =========================
# HTML -> text, OG image
# =========================
def html_to_text(html: str, max_chars: int = 1400) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    txt = soup.get_text("\n")
    txt = re.sub(r"\n{3,}", "\n\n", txt).strip()
    if len(txt) > max_chars:
        txt = txt[:max_chars].rstrip() + "..."
    return txt

def extract_og_image(html: str) -> Optional[str]:
    soup = BeautifulSoup(html, "html.parser")
    for key in ["og:image", "twitter:image", "twitter:image:src"]:
        tag = soup.find("meta", attrs={"property": key}) or soup.find("meta", attrs={"name": key})
        if tag and tag.get("content"):
            return tag["content"].strip()
    return None

async def fetch_url(client: httpx.AsyncClient, url: str, timeout: float = 20.0) -> Optional[str]:
    try:
        r = await client.get(url, timeout=timeout, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (compatible; RSSAlertsBot/1.0)"
        })
        if r.status_code >= 400:
            return None
        return r.text
    except Exception:
        return None

async def download_image_bytes(client: httpx.AsyncClient, url: str, max_bytes: int = 3_500_000) -> Optional[Tuple[bytes, str]]:
    try:
        r = await client.get(url, timeout=20.0, follow_redirects=True, headers={
            "User-Agent": "Mozilla/5.0 (compatible; RSSAlertsBot/1.0)"
        })
        if r.status_code >= 400:
            return None
        ctype = (r.headers.get("content-type") or "").lower()
        if not ctype.startswith("image/"):
            return None
        b = r.content
        if not b or len(b) > max_bytes:
            return None
        ext = "jpg"
        if "png" in ctype:
            ext = "png"
        elif "webp" in ctype:
            ext = "webp"
        elif "jpeg" in ctype or "jpg" in ctype:
            ext = "jpg"
        return b, f"image.{ext}"
    except Exception:
        return None


# =========================
# Classification + scoring
# =========================
CYBER_RANSOMWARE_RE = re.compile(r"\b(ransomware|ransom)\b", re.I)
CYBER_BREACH_RE = re.compile(r"\b(data breach|breach|leak|exposed|stolen data)\b", re.I)
CYBER_MASS_RE = re.compile(r"\b(million|millions|billion|billions|records|users|accounts|ssn|passport)\b", re.I)
CYBER_ZERO_DAY_RE = re.compile(r"\b(zero[- ]day|0day)\b", re.I)
CYBER_ACTIVE_EXPLOIT_RE = re.compile(r"\b(actively exploited|in the wild|exploitation)\b", re.I)

CRYPTO_DRAIN_RE = re.compile(r"\b(wallet drainer|drainer)\b", re.I)
CRYPTO_EXPLOIT_RE = re.compile(r"\b(exploit|hacked|hack|breach|compromised)\b", re.I)
CRYPTO_RUG_RE = re.compile(r"\b(rug pull|rugpull|honeypot|exit scam)\b", re.I)
CRYPTO_FUNDS_RE = re.compile(r"\b(drained|stolen|funds)\b", re.I)


def is_alert(tag: str, text: str) -> bool:
    t = (text or "").lower()
    if tag == "CRYPTO":
        return any(k in t for k in CRYPTO_KEYWORDS)
    return any(k in t for k in CYBER_KEYWORDS)

def impact_score(tag: str, text: str) -> int:
    """
    Tuned scoring:
      - CYBERCRIME: ransomware/mass breach/zero-day exploited high
      - CRYPTO: drainer/exploit/rug/funds high
    """
    t = text or ""
    score = 1

    if tag == "CYBERCRIME":
        if CYBER_RANSOMWARE_RE.search(t):
            score = max(score, 9)
        if CYBER_BREACH_RE.search(t) and CYBER_MASS_RE.search(t):
            score = max(score, 9)
        elif CYBER_BREACH_RE.search(t):
            score = max(score, 7)
        if CYBER_ZERO_DAY_RE.search(t):
            score = max(score, 8)
        if CYBER_ACTIVE_EXPLOIT_RE.search(t):
            score = max(score, 9)
        if re.search(r"\b(malware|botnet|backdoor)\b", t, re.I):
            score = max(score, 7)
        if re.search(r"\b(ddos|denial of service)\b", t, re.I):
            score = max(score, 6)
        if re.search(r"\b(advisory|report|analysis)\b", t, re.I):
            score = max(score, 4)

    else:  # CRYPTO
        if CRYPTO_DRAIN_RE.search(t):
            score = max(score, 9)
        if CRYPTO_EXPLOIT_RE.search(t):
            score = max(score, 8)
        if CRYPTO_RUG_RE.search(t):
            score = max(score, 8)
        if CRYPTO_FUNDS_RE.search(t):
            score = max(score, 8)
        if re.search(r"\b(bridge hack|bridge exploit)\b", t, re.I):
            score = max(score, 10)
        if re.search(r"\b(critical|emergency)\b", t, re.I):
            score = max(score, 8)

    return max(1, min(10, score))

def cyber_breaking_only(tag: str, text: str) -> bool:
    """
    Requested:
      🚨 BREAKING only for ransomware & mass breaches (CYBERCRIME).
    """
    if tag != "CYBERCRIME":
        return False
    if CYBER_RANSOMWARE_RE.search(text):
        return True
    if CYBER_BREACH_RE.search(text) and CYBER_MASS_RE.search(text):
        return True
    return False

def title_prefix(tag: str, score: int, text: str) -> str:
    if tag == "CYBERCRIME":
        return "🚨 *BREAKING*" if cyber_breaking_only(tag, text) else "🚨 *ALERT*"
    # CRYPTO behavior: BREAKING for high score
    return "🚨 *BREAKING*" if score >= 8 else "🚨 *ALERT*"


def risk_and_actions(tag: str, text: str) -> Tuple[List[str], List[str]]:
    """
    Pure English, context-aware.
    """
    t = text.lower()

    if tag == "CRYPTO":
        if "drainer" in t or "wallet drainer" in t or "phishing" in t:
            risk = [
                "Fake websites may drain wallets",
                "Malicious signatures can capture approvals",
                "Unauthorized transactions may be triggered",
            ]
            actions = [
                "Do NOT sign unknown transactions",
                "Revoke suspicious token approvals (revoke.cash)",
                "Disconnect wallet + remove dApp connections",
                "Avoid untrusted links / DMs",
            ]
            return risk, actions

        if "exploit" in t or "hacked" in t or "hack" in t:
            risk = [
                "Exploit/Hack indicators detected — funds may be at risk",
                "Interacting with the affected protocol/contract may be unsafe",
            ]
            actions = [
                "Stop interacting with the affected dApp",
                "Move funds to a safer wallet if exposed (when possible)",
                "Follow official incident updates only",
            ]
            return risk, actions

        if "rug" in t or "honeypot" in t or "exit scam" in t:
            risk = [
                "Scam/Rug signals detected — high probability of fund loss",
                "Liquidity drain or honeypot behavior is possible",
            ]
            actions = [
                "Avoid trading/interacting with the token",
                "Check and revoke wallet approvals",
                "Use only verified official links",
            ]
            return risk, actions

        return (
            ["Potential security risk — verify carefully before interacting"],
            ["Avoid unknown links/transactions", "Use trusted sources only"],
        )

    # CYBERCRIME
    if CYBER_RANSOMWARE_RE.search(text):
        risk = [
            "Ransomware activity reported — systems and data may be encrypted",
            "Potential data theft and extortion risk",
        ]
        actions = [
            "Avoid suspicious attachments and links",
            "Update endpoints + isolate affected machines",
            "Follow official advisories and incident response guidance",
        ]
        return risk, actions

    if CYBER_BREACH_RE.search(text):
        risk = [
            "Data breach/leak reported — personal data may be exposed",
            "Credential stuffing and account takeover risk",
        ]
        actions = [
            "Change passwords and enable MFA",
            "Monitor accounts for suspicious activity",
            "Check if your email appears in breach databases",
        ]
        return risk, actions

    if CYBER_ZERO_DAY_RE.search(text) or CYBER_ACTIVE_EXPLOIT_RE.search(text):
        risk = [
            "Active exploitation reported — high risk of compromise",
            "Patch availability may be limited or urgent",
        ]
        actions = [
            "Patch immediately when available",
            "Apply mitigations/workarounds from vendors",
            "Monitor logs and block IOCs if provided",
        ]
        return risk, actions

    risk = ["Cybercrime/security incident reported — verify exposure"]
    actions = ["Follow official advisories", "Stay cautious with links and downloads"]
    return risk, actions


# =========================
# RSS items
# =========================
@dataclass
class Item:
    tag: str
    title: str
    link: str
    source: str
    published: str
    summary: str
    uid: str


def parse_feeds_from_env() -> List[Tuple[str, str]]:
    if not RSS_FEEDS_ENV:
        return []
    out: List[Tuple[str, str]] = []
    parts = [p.strip() for p in RSS_FEEDS_ENV.split(",") if p.strip()]
    for p in parts:
        if "|" in p:
            tag, url = p.split("|", 1)
            tag = tag.strip().upper()
            url = url.strip()
            if tag in ("CRYPTO", "CYBERCRIME") and url:
                out.append((tag, url))
    return out


async def collect_items(client: httpx.AsyncClient, feeds: List[Tuple[str, str]], max_items_per_feed: int = 12) -> List[Item]:
    items: List[Item] = []
    for tag, feed_url in feeds:
        raw = await fetch_url(client, feed_url)
        if not raw:
            continue
        parsed = feedparser.parse(raw)
        source = parsed.feed.get("title", urlparse(feed_url).netloc) or urlparse(feed_url).netloc

        for e in (parsed.entries or [])[:max_items_per_feed]:
            title = (e.get("title") or "Untitled").strip()
            link = (e.get("link") or "").strip()
            summary_html = (e.get("summary") or e.get("description") or "").strip()
            summary = BeautifulSoup(summary_html, "html.parser").get_text(" ").strip()
            published = str(e.get("published") or e.get("updated") or now_utc_iso())

            uid = sha1(link or (title + "|" + published + "|" + source + "|" + tag))

            items.append(Item(
                tag=tag,
                title=title,
                link=link,
                source=source,
                published=published,
                summary=summary,
                uid=uid,
            ))
    return items


async def build_context_and_image(client: httpx.AsyncClient, item: Item) -> Tuple[str, Optional[Tuple[bytes, str]]]:
    if not item.link:
        return item.summary[:900], None

    html = await fetch_url(client, item.link)
    if not html:
        return item.summary[:900], None

    context = html_to_text(html, max_chars=1500)
    og = extract_og_image(html)
    img_bytes = None
    if og:
        img_bytes = await download_image_bytes(client, og)
    return context or item.summary[:900], img_bytes


# =========================
# Message formatting
# =========================
def format_message(item: Item, context: str) -> Tuple[str, str, Dict[str, Any]]:
    combined = f"{item.title}\n{item.summary}\n{context}\n{item.link}\n{item.source}"
    score = impact_score(item.tag, combined)
    region = detect_region(combined)

    prefix = title_prefix(item.tag, score, combined)
    tag_line = f"🟣 *Tag:* {mdv2_escape(item.tag)}"
    region_line = f"🌍 *Region:* {mdv2_escape(region)}"
    score_line = f"📊 *Impact Score:* *{score}/10*"

    risk, actions = risk_and_actions(item.tag, combined)

    # Keep context readable
    ctx = (context or "").strip()
    if len(ctx) > 1100:
        ctx = ctx[:1100].rstrip() + "..."
    ctx = mdv2_escape(ctx)

    title = mdv2_escape(item.title)
    src = mdv2_escape(item.source)
    link = mdv2_escape(item.link)
    pub = mdv2_escape(item.published)

    risk_block = "\n".join([f"• {mdv2_escape(x)}" for x in risk])
    action_block = "\n".join([f"• {mdv2_escape(x)}" for x in actions])

    # Caption must be short for photo
    caption = f"{prefix}\n{title}\n{tag_line}  |  {region_line}\n{score_line}"
    if len(caption) > 950:
        caption = caption[:950].rstrip() + "..."

    body = (
        f"{prefix}\n"
        f"*Title:* {title}\n"
        f"{tag_line}\n"
        f"{region_line}\n"
        f"{score_line}\n\n"
        f"⚠️ *Risk*\n{risk_block}\n\n"
        f"🧠 *What to do NOW*\n{action_block}\n\n"
        f"🧩 *Context*\n{ctx}\n\n"
        f"🔗 *Source:* {src}\n"
        f"👉 *Open Link:* {link}\n"
        f"🕒 *Published:* {pub}"
    )

    meta = {
        "tag": item.tag,
        "region": region,
        "impact": score,
    }
    return caption, body, meta


def split_text(text: str, limit: int = 4096) -> List[str]:
    if len(text) <= limit:
        return [text]
    parts: List[str] = []
    buf = ""
    for line in text.split("\n"):
        if len(buf) + len(line) + 1 > limit:
            if buf:
                parts.append(buf)
            buf = line
        else:
            buf = buf + ("\n" if buf else "") + line
    if buf:
        parts.append(buf)
    return parts


# =========================
# Telegram send
# =========================
async def send_alert(
    bot: Bot,
    caption: str,
    body: str,
    image: Optional[Tuple[bytes, str]] = None,
) -> List[int]:
    ids: List[int] = []
    chunks = split_text(body, 4096)

    if image:
        b, fname = image
        bio = InputFile(io.BytesIO(b), filename=fname)
        try:
            m = await bot.send_photo(
                chat_id=TELEGRAM_CHAT_ID,
                photo=bio,
                caption=caption,
                parse_mode=ParseMode.MARKDOWN_V2,
            )
            ids.append(m.message_id)
        except BadRequest:
            m = await bot.send_photo(
                chat_id=TELEGRAM_CHAT_ID,
                photo=bio,
                caption=strip_mdv2(caption),
            )
            ids.append(m.message_id)

        for c in chunks:
            try:
                m2 = await bot.send_message(
                    chat_id=TELEGRAM_CHAT_ID,
                    text=c,
                    parse_mode=ParseMode.MARKDOWN_V2,
                    disable_web_page_preview=DISABLE_WEB_PREVIEW,
                )
                ids.append(m2.message_id)
            except BadRequest:
                m2 = await bot.send_message(
                    chat_id=TELEGRAM_CHAT_ID,
                    text=strip_mdv2(c),
                    disable_web_page_preview=True,
                )
                ids.append(m2.message_id)
        return ids

    # No image
    for c in chunks:
        try:
            m = await bot.send_message(
                chat_id=TELEGRAM_CHAT_ID,
                text=c,
                parse_mode=ParseMode.MARKDOWN_V2,
                disable_web_page_preview=DISABLE_WEB_PREVIEW,
            )
            ids.append(m.message_id)
        except BadRequest:
            m = await bot.send_message(
                chat_id=TELEGRAM_CHAT_ID,
                text=strip_mdv2(c),
                disable_web_page_preview=True,
            )
            ids.append(m.message_id)
    return ids


# =========================
# RUN
# =========================
async def run_once() -> int:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        raise RuntimeError("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")

    feeds = parse_feeds_from_env() or DEFAULT_FEEDS

    mem = load_memory(MEMORY_FILE)
    bot = Bot(token=TELEGRAM_BOT_TOKEN)

    posted = 0
    async with httpx.AsyncClient() as client:
        items = await collect_items(client, feeds, max_items_per_feed=12)

        for it in items:
            if posted >= MAX_POSTS_PER_RUN:
                break

            if it.uid in mem:
                continue

            # Alert-only filter
            combined_quick = f"{it.title}\n{it.summary}\n{it.link}\n{it.source}"
            if ALERT_ONLY and not is_alert(it.tag, combined_quick):
                continue

            # Build context + image
            context, image = await build_context_and_image(client, it)

            caption, body, meta = format_message(it, context)

            # Send
            msg_ids = await send_alert(bot, caption, body, image=image)

            # Save memory with telegram message ids
            mem[it.uid] = {
                "uid": it.uid,
                "tag": it.tag,
                "region": meta["region"],
                "impact": meta["impact"],
                "title": it.title,
                "link": it.link,
                "source": it.source,
                "published": it.published,
                "telegram_message_ids": msg_ids,
                "posted_at": now_utc_iso(),
            }
            save_memory(MEMORY_FILE, mem)

            posted += 1
            await asyncio.sleep(1.1)

    print(f"[INFO] Posted {posted} alert(s). MEMORY_FILE={MEMORY_FILE} saved={len(mem)}")
    return posted


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()

    if args.once:
        asyncio.run(run_once())
    else:
        # Run once (workflow handles schedule)
        asyncio.run(run_once())


if __name__ == "__main__":
    main()