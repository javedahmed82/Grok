#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import time
import html
import hashlib
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
import feedparser

from telegram import Bot
from telegram.error import BadRequest, RetryAfter, TimedOut, NetworkError


# -------------------------
# ENV
# -------------------------
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

MEMORY_FILE = os.environ.get("MEMORY_FILE", "posted_memory.json").strip()
MAX_MEMORY = int(os.environ.get("MAX_MEMORY", "2500"))

# Post limits
MAX_POSTS_PER_RUN = int(os.environ.get("MAX_POSTS_PER_RUN", "6"))

# Modes
ALERT_ONLY = os.environ.get("ALERT_ONLY", "1").strip() == "1"     # keep alerts format
BREAKING_ONLY = os.environ.get("BREAKING_ONLY", "0").strip() == "1"  # only ransomware/mass breach

# Freshness
MAX_ITEM_AGE_HOURS = int(os.environ.get("MAX_ITEM_AGE_HOURS", "120"))  # 5 days

# RSS feeds (customizable via env)
# Separate lists help tagging better
DEFAULT_CRYPTO_FEEDS = [
    "https://slowmist.medium.com/feed",
    "https://blog.chainalysis.com/rss/",
    "https://www.trmlabs.com/blog/rss.xml",
    "https://cointelegraph.com/rss",
]

DEFAULT_CYBER_FEEDS = [
    "https://www.bleepingcomputer.com/feed/",
    "https://www.securityweek.com/feed/",
    "https://www.rapid7.com/blog/rss/",
    "https://www.cisa.gov/news.xml",
    "https://www.cert-in.org.in/rss/alerts.xml",
]

CRYPTO_FEEDS = [x.strip() for x in os.environ.get("CRYPTO_RSS_FEEDS", "").split(",") if x.strip()] or DEFAULT_CRYPTO_FEEDS
CYBER_FEEDS = [x.strip() for x in os.environ.get("CYBER_RSS_FEEDS", "").split(",") if x.strip()] or DEFAULT_CYBER_FEEDS


# -------------------------
# Helpers: text cleanup
# -------------------------
TAG_RE = re.compile(r"<[^>]+>")

def strip_html(raw: str) -> str:
    if not raw:
        return ""
    raw = html.unescape(raw)
    raw = TAG_RE.sub(" ", raw)
    raw = re.sub(r"\s+", " ", raw).strip()
    return raw

def shorten(text: str, max_len: int) -> str:
    if not text:
        return ""
    text = text.strip()
    if len(text) <= max_len:
        return text
    return text[: max_len - 1].rstrip() + "…"


# -------------------------
# Time parsing
# -------------------------
def entry_time_utc(entry: Dict[str, Any]) -> Optional[datetime]:
    # feedparser gives time.struct_time in entry.get('published_parsed') or 'updated_parsed'
    tp = entry.get("published_parsed") or entry.get("updated_parsed")
    if not tp:
        return None
    try:
        ts = time.mktime(tp)  # local; but okay for relative age; we convert to utc
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except Exception:
        return None

def format_time_utc(dt: Optional[datetime]) -> str:
    if not dt:
        return "Time: Unknown"
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%d %b %Y | %H:%M UTC")

def is_too_old(dt: Optional[datetime]) -> bool:
    if not dt:
        return False
    age_hours = (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0
    return age_hours > MAX_ITEM_AGE_HOURS


# -------------------------
# Memory (duplicate avoid)
# -------------------------
def _hash_id(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:24]

def load_memory(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {"seen_ids": []}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            # backward compatibility if file was []
            return {"seen_ids": data}
        if isinstance(data, dict) and "seen_ids" in data and isinstance(data["seen_ids"], list):
            return data
    except Exception:
        pass
    return {"seen_ids": []}

def save_memory(path: str, mem: Dict[str, Any]) -> None:
    # cap memory
    seen = mem.get("seen_ids", [])
    if len(seen) > MAX_MEMORY:
        seen = seen[-MAX_MEMORY:]
        mem["seen_ids"] = seen
    with open(path, "w", encoding="utf-8") as f:
        json.dump(mem, f, ensure_ascii=False, indent=2)

def already_seen(mem: Dict[str, Any], item_id: str) -> bool:
    return item_id in set(mem.get("seen_ids", []))

def mark_seen(mem: Dict[str, Any], item_id: str) -> None:
    mem.setdefault("seen_ids", []).append(item_id)


# -------------------------
# Classification: TAG + REGION + BREAKING
# -------------------------
CRYPTO_KEYWORDS = [
    "crypto", "cryptocurrency", "bitcoin", "btc", "ethereum", "eth", "bnb", "bsc", "solana", "xrp",
    "defi", "dex", "uniswap", "aave", "pancakeswap", "bridge", "token", "airdrop", "wallet", "web3",
    "drainer", "phishing", "rug pull", "rugpull", "exploit", "hack", "smart contract", "staking",
]
CYBER_KEYWORDS = [
    "ransomware", "breach", "data leak", "leaked", "malware", "trojan", "zero-day", "zeroday",
    "cve-", "botnet", "ddos", "phishing", "credential", "infostealer", "stealer", "spyware",
    "mass breach", "supply chain", "intrusion", "backdoor", "vulnerability", "exploit",
]

RANSOMWARE_KEYWORDS = ["ransomware", "encrypt", "decryptor", "ransom", "double extortion"]
MASS_BREACH_KEYWORDS = ["mass breach", "data breach", "breach", "leak", "leaked", "millions of", "records exposed", "exposed records"]

REGION_MAP = {
    "India": ["india", "indian", "delhi", "mumbai", "bengaluru", "bangalore", "hyderabad", "cert-in", "in.gov"],
    "US": ["usa", "u.s.", "u.s", "united states", "america", "fbi", "cisa", "doj", "sec ", "california", "new york"],
    "EU": ["eu", "europe", "european", "gdpr", "uk", "united kingdom", "london", "germany", "france", "spain", "italy", "netherlands"],
}

def detect_region(text: str) -> str:
    t = text.lower()
    for region, kws in REGION_MAP.items():
        for k in kws:
            if k in t:
                return region
    return "Global"

def detect_tag(title: str, summary: str, feed_hint: str) -> str:
    blob = f"{title} {summary} {feed_hint}".lower()
    crypto_score = sum(1 for k in CRYPTO_KEYWORDS if k in blob)
    cyber_score = sum(1 for k in CYBER_KEYWORDS if k in blob)

    # If feed belongs to cyber list -> bias CYBERCRIME
    if any(feed_hint.startswith(x.split("/")[2]) if "://" in x else False for x in CYBER_FEEDS):
        cyber_score += 2
    if any(feed_hint.startswith(x.split("/")[2]) if "://" in x else False for x in CRYPTO_FEEDS):
        crypto_score += 2

    return "CYBERCRIME" if cyber_score >= crypto_score else "CRYPTO"

def is_breaking_for_cyber(title: str, summary: str) -> bool:
    blob = f"{title} {summary}".lower()
    ransomware = any(k in blob for k in RANSOMWARE_KEYWORDS)
    mass_breach = any(k in blob for k in MASS_BREACH_KEYWORDS)
    return ransomware or mass_breach

def impact_score(tag: str, title: str, summary: str) -> int:
    """
    1..10 score tuned for cybercrime alerts.
    """
    blob = f"{title} {summary}".lower()
    score = 3

    # severity hints
    high_words = ["critical", "actively exploited", "zero-day", "zeroday", "ransomware", "mass breach", "records", "millions", "state-sponsored"]
    mid_words = ["breach", "leak", "exploit", "phishing", "malware", "botnet", "drainer", "hack", "vulnerability", "cve-"]
    low_words = ["warning", "advisory", "update", "patch"]

    score += 2 * sum(1 for w in high_words if w in blob)
    score += 1 * sum(1 for w in mid_words if w in blob)
    score -= 1 * sum(1 for w in low_words if w in blob)

    # big brand / infra amplification
    big_targets = ["binance", "coinbase", "metamask", "ledger", "trezor", "microsoft", "google", "aws", "cloudflare", "telegram", "whatsapp"]
    if any(b in blob for b in big_targets):
        score += 2

    # cybercrime tuned higher
    if tag == "CYBERCRIME":
        score += 1

    return max(1, min(10, score))


# -------------------------
# Templates (English only)
# -------------------------
def build_risk_and_actions(tag: str, title: str, summary: str) -> Tuple[List[str], List[str], str]:
    """
    Returns (risk_bullets, action_bullets, network_or_context_line)
    """
    blob = f"{title} {summary}".lower()

    if tag == "CRYPTO":
        # try detect network
        network = "Global"
        if "bsc" in blob or "bnb" in blob or "binance smart chain" in blob:
            network = "BNB (BSC)"
        elif "ethereum" in blob or "eth" in blob:
            network = "Ethereum"
        elif "solana" in blob:
            network = "Solana"
        elif "polygon" in blob:
            network = "Polygon"
        elif "arbitrum" in blob:
            network = "Arbitrum"
        elif "optimism" in blob:
            network = "Optimism"

        risk = [
            "Fake sites may drain wallets",
            "Malicious signatures can capture approvals",
            "Unauthorized transactions may be triggered",
        ]
        actions = [
            "Do NOT sign unknown transactions",
            "Revoke suspicious token approvals (revoke.cash)",
            "Disconnect wallet and remove unknown dApp connections",
            "Avoid untrusted links / DMs",
        ]
        return risk, actions, f"🏷️ Network: {network}"

    # CYBERCRIME
    ransomware = is_breaking_for_cyber(title, summary)

    if ransomware:
        risk = [
            "Ransomware encryption and data theft may be ongoing",
            "Organizations may face service outages and extortion attempts",
            "Stolen credentials can be reused for further intrusions",
        ]
        actions = [
            "Do NOT open suspicious attachments or links",
            "Isolate affected endpoints (disconnect network)",
            "Reset exposed credentials + enforce MFA",
            "Verify backups and incident response plan",
        ]
    else:
        risk = [
            "Data breach / leak may expose personal or company data",
            "Phishing campaigns may target victims using leaked info",
            "Malware or exploit chains may spread quickly",
        ]
        actions = [
            "Change passwords and enable MFA immediately",
            "Monitor accounts for suspicious login activity",
            "Apply security patches and block known IOCs",
            "Report suspicious emails / messages",
        ]

    return risk, actions, "🏷️ Type: CYBER INCIDENT"


# -------------------------
# Message builder (clean + Telegram preview link)
# -------------------------
def build_source_block(source_name: str, url: str, published_dt: Optional[datetime]) -> str:
    # EXACT style user wants: Source + "Open Link" + url + time
    t = format_time_utc(published_dt)
    lines = [f"🔗 Source: {source_name}".strip()]
    if url:
        lines.append("Open Link")
        lines.append(url)
    lines.append(f"🕒 {t}")
    return "\n".join(lines)

def build_alert_message(tag: str, region: str, breaking: bool, score: int,
                        title: str, url: str, source_name: str,
                        published_dt: Optional[datetime], summary: str) -> str:
    risk, actions, line3 = build_risk_and_actions(tag, title, summary)

    header = "🚨 BREAKING" if breaking else "🚩 ALERT"
    tag_line = f"🟣 Tag: {tag}"
    region_line = f"🌍 Region: {region}"
    impact_line = f"📊 Impact Score: {score}/10"

    # keep title shortish but readable
    title_clean = strip_html(title)
    summary_clean = strip_html(summary)

    # Context short + clean
    context = shorten(summary_clean, 700)

    msg = []
    msg.append(header)
    msg.append(f"Title: {title_clean}")
    msg.append(tag_line)
    msg.append(region_line)
    msg.append(impact_line)
    msg.append(line3)

    msg.append("")
    msg.append("⚠️ Risk")
    for r in risk[:4]:
        msg.append(f"• {r}")

    msg.append("")
    msg.append("🧠 What to do NOW")
    for a in actions[:6]:
        msg.append(f"• {a}")

    if context:
        msg.append("")
        msg.append("🧩 Context")
        msg.append(context)

    msg.append("")
    msg.append(build_source_block(source_name, url, published_dt))

    return "\n".join(msg).strip()


# -------------------------
# Telegram send (split safe)
# -------------------------
TELEGRAM_TEXT_LIMIT = 4096

def chunk_text(text: str, limit: int = TELEGRAM_TEXT_LIMIT) -> List[str]:
    parts: List[str] = []
    cur = ""
    for block in text.split("\n\n"):
        add = block if not cur else (cur + "\n\n" + block)
        if len(add) <= limit:
            cur = add
        else:
            if cur.strip():
                parts.append(cur.strip())
            cur = block
    if cur.strip():
        parts.append(cur.strip())
    return parts

async def safe_send(bot: Bot, text: str) -> None:
    for part in chunk_text(text):
        # preview ON so Open Link style shows like screenshot
        try:
            await bot.send_message(
                chat_id=TELEGRAM_CHAT_ID,
                text=part,
                disable_web_page_preview=False,
            )
        except RetryAfter as e:
            await asyncio.sleep(int(getattr(e, "retry_after", 3)) + 1)
            await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=part, disable_web_page_preview=False)
        except (TimedOut, NetworkError):
            await asyncio.sleep(2)
            await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=part, disable_web_page_preview=False)
        except BadRequest as e:
            # Fallback: remove odd chars if any parsing issue
            plain = part.replace("\u2028", " ").replace("\u2029", " ")
            await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=plain, disable_web_page_preview=False)


# -------------------------
# RSS pull
# -------------------------
def parse_feed(url: str) -> List[Dict[str, Any]]:
    d = feedparser.parse(url)
    out = []
    for e in d.entries[:50]:
        title = strip_html(e.get("title", "") or "")
        link = (e.get("link", "") or "").strip()
        summary = strip_html(e.get("summary", "") or e.get("description", "") or "")
        published = entry_time_utc(e)

        if not title or not link:
            continue
        out.append({
            "title": title,
            "link": link,
            "summary": summary,
            "published_dt": published,
            "source_name": strip_html(d.feed.get("title", "") or "Source"),
            "feed_url": url,
        })
    return out


def build_item_id(item: Dict[str, Any]) -> str:
    # stable id: link + title
    base = (item.get("link", "") + "|" + item.get("title", "")).strip()
    return _hash_id(base)


def pick_best_items(all_items: List[Dict[str, Any]], mem: Dict[str, Any]) -> List[Dict[str, Any]]:
    fresh = []
    for it in all_items:
        pid = build_item_id(it)
        it["_id"] = pid
        if already_seen(mem, pid):
            continue
        if is_too_old(it.get("published_dt")):
            continue
        fresh.append(it)

    # prioritize breaking first (cyber ransomware / mass breach)
    def rank(it: Dict[str, Any]) -> Tuple[int, int]:
        title = it["title"]
        summary = it["summary"]
        feed_hint = it.get("feed_url", "")
        tag = detect_tag(title, summary, feed_hint)
        breaking = (tag == "CYBERCRIME") and is_breaking_for_cyber(title, summary)
        score = impact_score(tag, title, summary)
        # breaking first, then higher score
        return (1 if breaking else 0, score)

    fresh.sort(key=rank, reverse=True)
    return fresh


# -------------------------
# Main cycle
# -------------------------
async def run_cycle(once: bool = True) -> int:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        raise SystemExit("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID in env")

    bot = Bot(token=TELEGRAM_BOT_TOKEN)

    mem = load_memory(MEMORY_FILE)

    all_items: List[Dict[str, Any]] = []

    # Pull both feed sets
    for f in CRYPTO_FEEDS:
        try:
            all_items.extend(parse_feed(f))
        except Exception:
            continue
    for f in CYBER_FEEDS:
        try:
            all_items.extend(parse_feed(f))
        except Exception:
            continue

    candidates = pick_best_items(all_items, mem)

    posted = 0
    for it in candidates:
        if posted >= MAX_POSTS_PER_RUN:
            break

        title = it["title"]
        summary = it["summary"]
        url = it["link"]
        source_name = it.get("source_name", "Source")
        published_dt = it.get("published_dt")
        feed_hint = it.get("feed_url", "")

        tag = detect_tag(title, summary, feed_hint)
        region = detect_region(f"{title} {summary} {source_name} {url}")

        breaking = False
        if tag == "CYBERCRIME":
            breaking = is_breaking_for_cyber(title, summary)

        # Rule: BREAKING only for ransomware & mass breaches (cyber)
        # If BREAKING_ONLY set, skip non-breaking
        if BREAKING_ONLY and not breaking:
            continue

        # If ALERT_ONLY set, do not show BREAKING header? (we still show BREAKING if breaking; user wants it)
        score = impact_score(tag, title, summary)

        msg = build_alert_message(
            tag=tag,
            region=region,
            breaking=breaking,
            score=score,
            title=title,
            url=url,
            source_name=source_name,
            published_dt=published_dt,
            summary=summary,
        )

        # Send
        await safe_send(bot, msg)

        # Mark & save memory
        mark_seen(mem, it["_id"])
        posted += 1

        # small delay to avoid flood
        await asyncio.sleep(1)

    save_memory(MEMORY_FILE, mem)
    print(f"[INFO] Posted {posted} alert(s). Memory items: {len(mem.get('seen_ids', []))}")
    return posted


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--once", action="store_true", help="Run one cycle and exit")
    args = p.parse_args()

    # For now always once in Actions; scheduler handles repeat
    asyncio.run(run_cycle(once=True))