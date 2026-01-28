import os
import re
import time
import json
import hashlib
import argparse
import asyncio
from datetime import datetime, timezone
from html import unescape as html_unescape
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
# RSS FEEDS
# =========================
RSS_FEEDS = [
    ("CertiK", "https://www.certik.com/resources/blog/feed"),
    ("SlowMist", "https://slowmist.medium.com/feed"),
    ("RevokeCash", "https://revoke.cash/blog/rss.xml"),
    ("ScamSniffer", "https://medium.com/feed/scamsniffer"),
    ("DeFiLlama", "https://blog.defillama.com/rss/"),
]


# =========================
# ALERT KEYWORDS (strong signals)
# =========================
STRONG_ALERT_KEYWORDS = [
    "wallet drainer", "drainer", "phishing", "fake website", "fake site",
    "exploit", "exploited", "hacked", "hack",
    "rugpull", "rug pull", "exit scam", "honeypot",
    "funds drained", "stolen", "drained",
    "withdrawals halted", "funds frozen",
    "bridge hack", "compromised", "private key leaked",
]

# Words that often mean “report/analysis” rather than a breaking incident
SOFT_REPORT_WORDS = [
    "annual report", "q4", "report", "analysis", "overview", "whitepaper",
    "study", "research", "statistics", "recap", "year in review"
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
    # keep last 10k ids (enough)
    with open(MEMORY_FILE, "w", encoding="utf-8") as f:
        json.dump(sorted(list(mem))[-10000:], f, indent=2)


# =========================
# CLEANING (removes Medium HTML junk)
# =========================
TAG_RE = re.compile(r"<[^>]+>")
URL_RE = re.compile(r"https?://\S+")
WHITESPACE_RE = re.compile(r"\s+")


def strip_html(raw: str) -> str:
    raw = raw or ""
    raw = html_unescape(raw)

    # Remove common Medium embeds/figures/images
    raw = re.sub(r"<figure.*?>.*?</figure>", " ", raw, flags=re.IGNORECASE | re.DOTALL)
    raw = re.sub(r"<img.*?>", " ", raw, flags=re.IGNORECASE | re.DOTALL)

    # Remove remaining tags
    raw = TAG_RE.sub(" ", raw)

    # Remove URLs from context (prevents network false triggers from links)
    raw = URL_RE.sub(" ", raw)

    # Normalize whitespace
    raw = WHITESPACE_RE.sub(" ", raw).strip()
    return raw


def normalize(text: str) -> str:
    return WHITESPACE_RE.sub(" ", (text or "")).strip()


def strong_hits(text: str) -> list:
    low = (text or "").lower()
    hits = [k for k in STRONG_ALERT_KEYWORDS if k in low]
    out = []
    for h in hits:
        if h not in out:
            out.append(h)
        if len(out) >= 4:
            break
    return out


def is_soft_report(title: str, summary: str) -> bool:
    low = f"{title} {summary}".lower()
    return any(w in low for w in SOFT_REPORT_WORDS)


# =========================
# NETWORK DETECTION (word boundary based)
# =========================
def detect_network(clean_text: str) -> str:
    t = (clean_text or "").lower()

    if re.search(r"\b(bsc|bnb chain|bnb smart chain)\b", t):
        return "BNB (BSC)"
    if re.search(r"\b(ethereum|eth|erc20|erc-20)\b", t):
        return "Ethereum"
    if re.search(r"\b(solana|sol)\b", t):
        return "Solana"
    if re.search(r"\b(bitcoin|btc)\b", t):
        return "Bitcoin"
    if re.search(r"\b(polygon|matic)\b", t):
        return "Polygon"
    if re.search(r"\b(arbitrum|arb)\b", t):
        return "Arbitrum"
    if re.search(r"\b(optimism|op)\b", t):
        return "Optimism"
    if re.search(r"\b(avalanche|avax)\b", t):
        return "Avalanche"

    return "Crypto / DeFi"


def classify(hits: list[str]) -> str:
    low = " ".join(hits)
    if any(x in low for x in ["drainer", "phishing", "fake website", "fake site"]):
        return "drainer"
    if any(x in low for x in ["exploit", "hacked", "hack", "drained", "bridge hack", "compromised"]):
        return "hack"
    if any(x in low for x in ["rugpull", "rug pull", "exit scam", "honeypot"]):
        return "scam"
    return "alert"


def impact_and_action(kind: str) -> tuple[str, str]:
    if kind == "hack":
        return "🔴🔴 VERY HIGH", "EXIT / AVOID"
    if kind in ("drainer", "scam"):
        return "🔴 HIGH", "STAY AWAY"
    return "🟡 MEDIUM", "CAUTION"


def risk_and_todo(kind: str):
    # PURE ENGLISH (as requested)
    if kind == "drainer":
        return (
            [
                "Fake websites may drain wallets",
                "Malicious signatures can capture approvals",
                "Unauthorized transactions may be triggered",
            ],
            [
                "Do NOT sign unknown transactions",
                "Revoke suspicious token approvals",
                "Avoid untrusted links and dApps",
                "Disconnect your wallet from unknown sites",
            ],
        )

    if kind == "hack":
        return (
            [
                "Exploit/Hack indicators detected — funds may be at risk",
                "Interacting with the affected protocol/contract may be unsafe",
            ],
            [
                "Do NOT interact with the affected protocol",
                "Follow official security updates only",
                "Move funds to safety if you are exposed (when possible)",
            ],
        )

    if kind == "scam":
        return (
            [
                "Scam/Rug signals detected — high probability of fund loss",
                "Liquidity drain or honeypot behavior is possible",
            ],
            [
                "Avoid trading/interacting with the token",
                "Check and revoke wallet approvals",
                "Use only verified official links",
            ],
        )

    return (
        ["Suspicious activity detected", "Stay cautious"],
        ["Avoid unknown links/transactions", "Follow official updates"],
    )


# =========================
# FORMAT MESSAGE (Telegram HTML)
# =========================
def format_alert(source: str, title: str, summary: str, link: str) -> str:
    title = normalize(title)[:120]
    clean_summary = strip_html(summary)

    combined_for_detect = f"{title} {clean_summary}"
    hits = strong_hits(combined_for_detect)
    kind = classify(hits)
    network = detect_network(combined_for_detect)
    impact, action = impact_and_action(kind)
    risk, todo = risk_and_todo(kind)

    context = clean_summary
    if len(context) > 380:
        context = context[:380].rstrip() + "…"

    now = datetime.now(timezone.utc).strftime("%d %b %Y | %H:%M UTC")

    msg = (
        f"🚨 <b>ALERT</b>\n"
        f"🧾 <b>Title:</b> {html_escape(title)}\n"
        f"🏷️ <b>Network:</b> {html_escape(network)}\n\n"
        f"⚠️ <b>Risk</b>\n"
        + "\n".join([f"• {html_escape(x)}" for x in risk])
        + "\n\n"
        f"🧠 <b>What to do NOW</b>\n"
        + "\n".join([f"• {html_escape(x)}" for x in todo])
        + "\n\n"
        f"📊 <b>Impact:</b> {impact}\n"
        f"🔥 <b>Action:</b> {html_escape(action)}\n\n"
        f"🧩 <b>Context</b>\n{html_escape(context)}\n\n"
        f"🔗 <b>Source:</b> {html_escape(source)}\n"
        f"<a href='{html_escape(link)}'>Open Link</a>\n"
        f"🕒 <i>{now}</i>"
    )

    # Telegram safe limit (messages)
    return msg[:3800]


# =========================
# SEND (ASYNC SAFE)
# =========================
async def send(bot: Bot, msg: str):
    try:
        await bot.send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text=msg,
            parse_mode="HTML",
            disable_web_page_preview=DISABLE_WEB_PREVIEW,
        )
    except BadRequest:
        plain = re.sub(r"<[^>]+>", "", msg)
        await bot.send_message(
            chat_id=TELEGRAM_CHAT_ID,
            text=plain,
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

            clean_summary = strip_html(summary)
            combined = f"{title} {clean_summary}"

            hits = strong_hits(combined)
            if not hits:
                continue

            # Reduce report spam unless it's strongly alerting
            if is_soft_report(title, clean_summary) and len(hits) < 2:
                continue

            key = uid(link or title)
            if key in memory:
                continue

            msg = format_alert(source, title, summary, link)
            await send(bot, msg)

            memory.add(key)
            posted += 1
            await asyncio.sleep(1.1)

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