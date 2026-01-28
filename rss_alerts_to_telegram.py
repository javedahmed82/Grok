#!/usr/bin/env python3
"""
rss_alerts_to_telegram.py
- Pulls RSS feeds (cybercrime + crypto security), filters for ALERT/BREAKING items
- Formats clean Telegram alert with:
  * Severity-based pin
  * Auto hashtags
  * Country flag detection
  * Inline URL button (no ugly link previews)
- Saves posted ids in posted_memory.json to avoid duplicates
"""

import os
import re
import json
import time
import hashlib
import asyncio
from datetime import datetime, timezone

import feedparser
from telegram import Bot, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.constants import ParseMode

# ----------------------------
# ENV CONFIG
# ----------------------------
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

# comma-separated RSS list
RSS_URLS = os.getenv(
    "RSS_URLS",
    # good defaults (you can edit anytime)
    "https://www.bleepingcomputer.com/feed/,"
    "https://krebsonsecurity.com/feed/,"
    "https://www.securityweek.com/feed/,"
    "https://thehackernews.com/feeds/posts/default?alt=rss,"
    "https://www.darkreading.com/rss.xml,"
    "https://medium.com/feed/slowmist,"
).strip()

MEMORY_FILE = os.getenv("MEMORY_FILE", "posted_memory.json").strip()

# Behavior toggles
ALERT_ONLY = os.getenv("ALERT_ONLY", "true").lower() in ("1", "true", "yes", "y", "on")
PIN_BREAKING = os.getenv("PIN_BREAKING", "true").lower() in ("1", "true", "yes", "y", "on")

# How many items per feed per run (keep small)
MAX_PER_FEED = int(os.getenv("MAX_PER_FEED", "6"))

# Telegram limits
TG_MAX = 3900  # safe split margin

# ----------------------------
# KEYWORDS / DETECTION
# ----------------------------
CYBER_KEYWORDS = [
    "ransomware", "data breach", "breach", "leaked", "leak", "extortion", "malware",
    "phishing", "zero-day", "0day", "vulnerability", "cve-", "attack", "ddos",
    "stolen", "exfiltrat", "mass breach", "credential", "infostealer", "botnet"
]

CRYPTO_KEYWORDS = [
    "crypto", "bitcoin", "ethereum", "bnb", "bsc", "solana", "wallet", "drainer",
    "defi", "bridge", "dex", "rug", "exploit", "hack", "airdrop", "seed phrase",
    "approval", "permit", "smart contract"
]

# ransomware & mass breaches => BREAKING
BREAKING_CYBER = ["ransomware", "mass breach", "breach", "extortion", "leak", "leaked", "data breach"]

# hashtags mapping
HASHTAG_RULES = [
    (["ransomware"], ["#RANSOMWARE", "#CYBERSECURITY"]),
    (["data breach", "breach", "leak", "leaked", "exfiltrat"], ["#DATA_BREACH", "#CYBERSECURITY"]),
    (["phishing"], ["#PHISHING", "#SCAM_ALERT"]),
    (["zero-day", "0day", "cve-"], ["#VULNERABILITY", "#CVE"]),
    (["wallet drainer", "drainer"], ["#WALLET_DRAINER", "#CRYPTO_SCAM"]),
    (["rug pull", "rug"], ["#RUGPULL", "#SCAM_ALERT"]),
    (["exploit", "hack"], ["#EXPLOIT", "#SECURITY_ALERT"]),
    (["malware", "infostealer"], ["#MALWARE", "#SECURITY_ALERT"]),
]

# quick region detection (very simple but works)
REGION_RULES = [
    (["india", "delhi", "mumbai", "bengaluru", "bangalore", "kolkata", "chennai", "hyderabad"], ("India", "🇮🇳")),
    (["united states", "u.s.", "usa", "american", "california", "new york", "fbi", "cisa"], ("US", "🇺🇸")),
    (["uk", "united kingdom", "london", "britain", "nca"], ("UK", "🇬🇧")),
    (["europe", "eu", "european", "gdpr", "enisa"], ("EU", "🇪🇺")),
    (["russia", "moscow"], ("Russia", "🇷🇺")),
    (["china", "beijing"], ("China", "🇨🇳")),
    (["japan", "tokyo"], ("Japan", "🇯🇵")),
    (["korea", "seoul"], ("Korea", "🇰🇷")),
]

# ----------------------------
# UTIL
# ----------------------------
def _load_memory(path: str) -> set:
    try:
        if not os.path.exists(path):
            return set()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return set(data)
        if isinstance(data, dict) and "ids" in data and isinstance(data["ids"], list):
            return set(data["ids"])
        return set()
    except Exception:
        return set()

def _save_memory(path: str, ids: set):
    # store as list for simplicity
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(sorted(list(ids))[-5000:], f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)

def _sha(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:24]

def _strip_html(s: str) -> str:
    if not s:
        return ""
    # remove tags + shrink spaces
    s = re.sub(r"<[^>]+>", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def _pick_region(text: str):
    t = text.lower()
    for keys, (name, flag) in REGION_RULES:
        if any(k in t for k in keys):
            return name, flag
    return "Global", "🌍"

def _pick_tag(text: str):
    t = text.lower()
    cyber = any(k in t for k in CYBER_KEYWORDS)
    crypto = any(k in t for k in CRYPTO_KEYWORDS)
    # both can happen, but choose by stronger signal
    if cyber and crypto:
        # prefer CYBERCRIME if ransomware/breach present
        if any(k in t for k in BREAKING_CYBER):
            return "CYBERCRIME"
        return "CRYPTO"
    if cyber:
        return "CYBERCRIME"
    if crypto:
        return "CRYPTO"
    return "CYBERCRIME"  # default for your channel vibe

def _impact_score(text: str, tag: str) -> int:
    """
    Tuned for cybercrime:
    - ransomware / mass breach -> high
    - exploit / zero-day -> medium-high
    - generic blog -> lower
    """
    t = text.lower()
    score = 1

    # cyber high impact
    if any(k in t for k in ["mass breach", "data breach", "breach", "extortion", "ransomware", "leaked", "leak"]):
        score += 6
    if any(k in t for k in ["zero-day", "0day", "cve-"]):
        score += 4
    if any(k in t for k in ["active exploitation", "actively exploited", "in the wild"]):
        score += 4
    if any(k in t for k in ["critical", "urgent", "emergency"]):
        score += 3

    # crypto risk
    if any(k in t for k in ["wallet drainer", "drainer", "seed phrase", "approval scam", "fake airdrop", "rug pull"]):
        score += 5
    if any(k in t for k in ["bridge hack", "defi exploit", "smart contract exploit", "exploit", "hack"]):
        score += 4

    # soften if looks like generic announcement
    if any(k in t for k in ["anniversary", "partnership", "event recap", "web3 leader programme"]):
        score -= 2

    # clamp
    score = max(1, min(10, score))
    return score

def _is_breaking(text: str, tag: str, score: int) -> bool:
    t = text.lower()
    if tag == "CYBERCRIME":
        # breaking only for ransomware & mass breaches
        if any(k in t for k in BREAKING_CYBER):
            return True
        return score >= 9
    # crypto breaking only when drainer/exploit big
    return score >= 9 and any(k in t for k in ["drainer", "bridge", "exploit", "hack", "rug"])

def _hashtags(text: str) -> list[str]:
    t = text.lower()
    tags = set()
    for keys, hs in HASHTAG_RULES:
        if any(k in t for k in keys):
            for h in hs:
                tags.add(h)
    # baseline
    tags.add("#ALERT")
    return sorted(tags)

def _risk_points(tag: str):
    # purely English (as you asked)
    if tag == "CYBERCRIME":
        return [
            "Stolen data may be used for extortion / fraud",
            "Victims may receive phishing and scam follow-ups",
            "Attackers may still have persistence in systems",
        ]
    # CRYPTO
    return [
        "Fake sites may drain wallets",
        "Malicious signatures can capture approvals",
        "Unauthorized transactions may be triggered",
    ]

def _what_to_do(tag: str):
    if tag == "CYBERCRIME":
        return [
            "Do NOT open unknown links / attachments",
            "Reset exposed passwords + enable MFA",
            "Monitor accounts and rotate API keys",
            "Notify users if sensitive data is involved",
        ]
    return [
        "Do NOT sign unknown transactions",
        "Revoke suspicious token approvals",
        "Disconnect wallet + remove dApp connections",
        "Avoid untrusted links / DMs",
    ]

def _format_time(entry) -> str:
    # Try RSS timestamps -> UTC string
    dt = None
    if getattr(entry, "published_parsed", None):
        dt = datetime.fromtimestamp(time.mktime(entry.published_parsed), tz=timezone.utc)
    elif getattr(entry, "updated_parsed", None):
        dt = datetime.fromtimestamp(time.mktime(entry.updated_parsed), tz=timezone.utc)
    if not dt:
        dt = datetime.now(timezone.utc)
    return dt.strftime("%d %b %Y | %H:%M UTC")

def _split_text(s: str, limit: int = TG_MAX) -> list[str]:
    if len(s) <= limit:
        return [s]
    parts, cur = [], ""
    for line in s.split("\n"):
        if len(cur) + len(line) + 1 > limit:
            parts.append(cur.rstrip())
            cur = ""
        cur += line + "\n"
    if cur.strip():
        parts.append(cur.rstrip())
    return parts

# ----------------------------
# TELEGRAM SEND
# ----------------------------
async def send_alert(bot: Bot, text: str, url: str | None, pin: bool):
    # Inline button
    markup = None
    if url:
        markup = InlineKeyboardMarkup([
            [InlineKeyboardButton("🔗 Open Source", url=url)]
        ])

    # NO link preview images/cards
    msg = await bot.send_message(
        chat_id=TELEGRAM_CHAT_ID,
        text=text,
        parse_mode=ParseMode.HTML,  # safe formatting
        disable_web_page_preview=True,
        reply_markup=markup,
    )

    if pin and PIN_BREAKING:
        try:
            await bot.pin_chat_message(chat_id=TELEGRAM_CHAT_ID, message_id=msg.message_id, disable_notification=True)
        except Exception as e:
            # if bot not admin or pin not allowed
            print(f"[WARN] pin failed: {e}")

async def run_once():
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        raise SystemExit("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")

    bot = Bot(token=TELEGRAM_BOT_TOKEN)

    posted = _load_memory(MEMORY_FILE)
    posted_before = len(posted)

    urls = [u.strip() for u in RSS_URLS.split(",") if u.strip()]
    total_posted = 0

    for feed_url in urls:
        d = feedparser.parse(feed_url)
        if not getattr(d, "entries", None):
            continue

        for entry in d.entries[:MAX_PER_FEED]:
            title = (getattr(entry, "title", "") or "").strip()
            link = (getattr(entry, "link", "") or "").strip()
            summary = _strip_html(getattr(entry, "summary", "") or getattr(entry, "description", "") or "")

            if not title and not summary:
                continue

            blob = f"{title}\n{summary}\n{link}".strip()
            uid = _sha((getattr(entry, "id", "") or link or title) + "|" + title)

            if uid in posted:
                continue

            tag = _pick_tag(blob)
            region_name, flag = _pick_region(blob)
            score = _impact_score(blob, tag)
            breaking = _is_breaking(blob, tag, score)

            # ALERT_ONLY mode: only post meaningful alerts
            if ALERT_ONLY:
                # cyber: require ransomware/breach/critical/exploit
                if tag == "CYBERCRIME":
                    must = any(k in blob.lower() for k in CYBER_KEYWORDS) and (breaking or score >= 6)
                else:
                    must = any(k in blob.lower() for k in CRYPTO_KEYWORDS) and (breaking or score >= 6)
                if not must:
                    # still mark as seen? no — let it appear later if it becomes relevant
                    continue

            header = "🚨 <b>BREAKING</b>" if breaking else "🚩 <b>ALERT</b>"
            hashtags = " ".join(_hashtags(blob))
            when = _format_time(entry)

            risk_lines = "\n".join([f"• {x}" for x in _risk_points(tag)])
            do_lines = "\n".join([f"• {x}" for x in _what_to_do(tag)])

            # Keep context short (avoid long essays)
            context = summary[:500].strip()
            if context and len(summary) > 500:
                context += "…"

            # Your requested link style (no ugly inline preview)
            # NOTE: Link will be in button; still show small "Open Link" text like your screenshot
            open_link_block = ""
            if link:
                open_link_block = f"\n\n🔗 <b>Source:</b> {getattr(d.feed, 'title', 'Open Link')}\n👉 <b>Open Link</b>\n{link}"

            msg = (
                f"{header}\n"
                f"<b>Title:</b> {title}\n"
                f"🟣 <b>Tag:</b> {tag}\n"
                f"{flag} <b>Region:</b> {region_name}\n"
                f"📊 <b>Impact Score:</b> {score}/10\n"
                f"\n⚠️ <b>Risk</b>\n{risk_lines}\n"
                f"\n🧠 <b>What to do NOW</b>\n{do_lines}\n"
                f"\n{hashtags}"
                f"{open_link_block}\n"
                f"🕒 <b>{when}</b>"
            )

            parts = _split_text(msg, TG_MAX)
            # send first part with button (best UX)
            pin_this = breaking or score >= 9

            if parts:
                await send_alert(bot, parts[0], link if link else None, pin=pin_this)
                for p in parts[1:]:
                    # follow-ups without button
                    await bot.send_message(
                        chat_id=TELEGRAM_CHAT_ID,
                        text=p,
                        parse_mode=ParseMode.HTML,
                        disable_web_page_preview=True,
                    )

            posted.add(uid)
            total_posted += 1

    if len(posted) != posted_before:
        _save_memory(MEMORY_FILE, posted)

    print(f"[INFO] Posted {total_posted} alert(s). Memory size={len(posted)}")

if __name__ == "__main__":
    asyncio.run(run_once())