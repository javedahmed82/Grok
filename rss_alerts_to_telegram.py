import os
import re
import time
import json
import hashlib
import argparse
import asyncio
from datetime import datetime, timezone
from html import escape as html_escape

import feedparser
from telegram import Bot
from telegram.error import BadRequest


# =========================
# CONFIG
# =========================
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

MEMORY_FILE = os.getenv("MEMORY_FILE", "posted_memory.json")
MAX_POSTS_PER_RUN = int(os.getenv("MAX_POSTS_PER_RUN", "5"))
DISABLE_WEB_PREVIEW = True


# =========================
# RSS FEEDS (UNLIMITED)
# =========================
RSS_FEEDS = [
    ("CertiK", "https://www.certik.com/resources/blog/feed"),
    ("SlowMist", "https://slowmist.medium.com/feed"),
    ("RevokeCash", "https://revoke.cash/blog/rss.xml"),
    ("ScamSniffer", "https://medium.com/feed/scamsniffer"),
    ("DeFiLlama", "https://blog.defillama.com/rss/"),
]


# =========================
# ALERT KEYWORDS
# =========================
ALERT_KEYWORDS = [
    "hack", "hacked", "exploit", "exploited",
    "wallet drainer", "drainer",
    "phishing", "fake site", "scam",
    "rug", "rug pull", "rugpull",
    "funds drained", "funds frozen",
    "withdrawals halted", "bridge hack",
]


# =========================
# MEMORY
# =========================
def uid(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]


def load_memory() -> set:
    if not os.path.exists(MEMORY_FILE):
        return set()
    try:
        with open(MEMORY_FILE, "r", encoding="utf-8") as f:
            return set(json.load(f))
    except Exception:
        return set()


def save_memory(mem: set):
    with open(MEMORY_FILE, "w", encoding="utf-8") as f:
        json.dump(sorted(list(mem))[-10000:], f, indent=2)


# =========================
# HELPERS
# =========================
def normalize(text: str) -> str:
    return " ".join((text or "").split())


def detect_alert(text: str) -> list:
    low = text.lower()
    hits = [k for k in ALERT_KEYWORDS if k in low]
    return list(dict.fromkeys(hits))


def detect_network(text: str) -> str:
    low = text.lower()
    if "bnb" in low or "bsc" in low:
        return "BNB (BSC)"
    if "ethereum" in low or "eth" in low:
        return "Ethereum"
    if "solana" in low:
        return "Solana"
    if "polygon" in low:
        return "Polygon"
    if "arbitrum" in low:
        return "Arbitrum"
    return "Crypto / DeFi"


def impact_and_action(hits):
    if any(h in hits for h in ["hack", "exploit", "bridge hack", "funds drained"]):
        return "🔴 VERY HIGH", "EXIT / AVOID"
    if any(h in hits for h in ["wallet drainer", "phishing", "scam", "rug"]):
        return "🔴 HIGH", "STAY AWAY"
    return "🟡 MEDIUM", "CAUTION"


def risk_and_todo(hits):
    if "wallet drainer" in hits or "phishing" in hits:
        return (
            [
                "Fake websites wallets drain kar rahi hain",
                "Malicious signatures capture ho sakte hain",
            ],
            [
                "Unknown transaction SIGN mat karo",
                "Token approvals revoke karo",
                "Unknown links avoid karo",
            ],
        )

    return (
        [
            "Exploit / scam signals detect hue hain",
            "User funds risk me ho sakte hain",
        ],
        [
            "Protocol se interact mat karo",
            "Sirf official announcements follow karo",
        ],
    )


# =========================
# FORMAT MESSAGE
# =========================
def format_alert(source, title, summary, link):
    text = normalize(f"{title} {summary}")
    hits = detect_alert(text)
    network = detect_network(text)
    impact, action = impact_and_action(hits)
    risk, todo = risk_and_todo(hits)

    context = normalize(summary)
    if len(context) > 260:
        context = context[:260] + "…"

    now = datetime.now(timezone.utc).strftime("%d %b %Y | %H:%M UTC")

    msg = (
        f"🚨 <b>ALERT:</b> {html_escape(title)}\n"
        f"🏷️ <b>Network:</b> {html_escape(network)}\n\n"
        f"⚠️ <b>Risk:</b>\n"
        + "\n".join([f"• {html_escape(x)}" for x in risk])
        + "\n\n"
        f"🧠 <b>What to do NOW:</b>\n"
        + "\n".join([f"• {html_escape(x)}" for x in todo])
        + "\n\n"
        f"📊 <b>Impact:</b> {impact}\n"
        f"🔥 <b>Action:</b> {action}\n\n"
        f"🧾 <b>Context:</b> {html_escape(context)}\n\n"
        f"🔗 <b>Source:</b> {html_escape(source)}\n"
        f"<a href='{html_escape(link)}'>{html_escape(link)}</a>\n\n"
        f"🕒 <i>{now}</i>"
    )

    return msg[:3800]


# =========================
# SEND (ASYNC SAFE)
# =========================
async def send(bot, msg):
    try:
        await bot.send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text=msg,
            parse_mode="HTML",
            disable_web_page_preview=DISABLE_WEB_PREVIEW,
        )
    except BadRequest:
        await bot.send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text=re.sub(r"<[^>]+>", "", msg),
            disable_web_page_preview=True,
        )


# =========================
# MAIN
# =========================
async def run_once():
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        raise RuntimeError("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")

    bot = Bot(TELEGRAM_BOT_TOKEN)
    memory = load_memory()
    posted = 0

    for source, url in RSS_FEEDS:
        feed = feedparser.parse(url)
        for entry in feed.entries:
            if posted >= MAX_POSTS_PER_RUN:
                break

            title = entry.get("title", "") or ""
            summary = entry.get("summary", "") or ""
            link = entry.get("link", "") or ""

            hits = detect_alert(f"{title} {summary}")
            if not hits:
                continue

            key = uid(link or title)
            if key in memory:
                continue

            msg = format_alert(source, title, summary, link)
            await send(bot, msg)

            memory.add(key)
            posted += 1
            await asyncio.sleep(1)

    save_memory(memory)
    print(f"[INFO] Posted {posted} alert(s).")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    if args.once:
        asyncio.run(run_once())
    else:
        while True:
            asyncio.run(run_once())
            time.sleep(1800)