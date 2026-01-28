import os
import json
import hashlib
import argparse
import asyncio
import re
from datetime import datetime
from html import escape as html_escape

import requests
from telegram import Bot
from telegram.error import BadRequest
from grokipedia_api import GrokipediaClient

# ======================================================
# BASIC SETTINGS
# ======================================================
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

RAW_QUERIES = os.getenv("GROKIPEDIA_QUERIES", "").strip()
if RAW_QUERIES:
    QUERIES = [q.strip() for q in RAW_QUERIES.split(",") if q.strip()]
else:
    QUERIES = [
        "bitcoin cryptocurrency",
        "ethereum blockchain",
        "bnb smart chain",
        "solana blockchain",
        "xrp ripple ledger",
        "polygon blockchain",
        "avalanche blockchain",
        "arbitrum layer 2",
        "optimism layer 2",
        "chainlink oracle",
        "uniswap defi",
        "aave defi",
        "makerdao stablecoin",
        "toncoin blockchain",
        "injective protocol"
    ]

RESULTS_PER_QUERY = int(os.getenv("RESULTS_PER_QUERY", "3"))
MEMORY_FILE = os.getenv("MEMORY_FILE", "posted_memory.json")

TG_MAX = 4096
PHOTO_CAPTION_MAX = 900
MAX_POSTS_PER_RUN = 6

# ======================================================
# FILTER KEYWORDS
# ======================================================
STRONG_CRYPTO = [
    "bitcoin","ethereum","blockchain","crypto","token","coin",
    "defi","web3","smart chain","bsc","layer 2","l2",
    "validator","staking","on-chain","exchange","wallet"
]

NOISE = [
    "railway","locomotive","engine","built in","factory",
    "austria","bohemia","church","religion","islam",
    "judaism","christian","ramadan","empire","king",
    "190","km/h","meters","tons","steam"
]

RISK_TERMS = [
    "hack","hacked","exploit","drained","rug","scam",
    "sec","lawsuit","charged","indictment","arrested",
    "frozen","seized","bankrupt"
]

BREAKING_TERMS = [
    "breaking","urgent","just in","hack","exploit",
    "approved","etf","charges","lawsuit","halted"
]

# ======================================================
# MEMORY
# ======================================================
def load_memory():
    if os.path.exists(MEMORY_FILE):
        try:
            with open(MEMORY_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            return set()
    return set()

def save_memory(mem):
    with open(MEMORY_FILE, "w", encoding="utf-8") as f:
        json.dump(list(mem)[-5000:], f, indent=2)

def uid(text):
    return hashlib.sha256(text.encode()).hexdigest()[:24]

# ======================================================
# HELPERS
# ======================================================
def clean_text(t):
    t = re.sub(r"<!--.*?-->", "", t, flags=re.DOTALL)
    t = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", t)
    return " ".join(t.split())

def sentences(t):
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", t) if len(s.strip()) > 30]

def is_crypto_relevant(title, content):
    blob = (title + " " + content).lower()
    score = 0
    for k in STRONG_CRYPTO:
        if k in blob:
            score += 2
    for n in NOISE:
        if n in blob:
            score -= 3
    return score >= 3

def detect_risk(blob):
    hits = [r for r in RISK_TERMS if r in blob]
    return hits[:3]

def impact_score(blob):
    score = 10
    if any(x in blob for x in ["etf","approved","listing","launch"]):
        score += 30
    if any(x in blob for x in ["hack","exploit","sec","lawsuit"]):
        score += 40
    return min(score, 100)

def is_breaking(blob, score):
    return score >= 75 or any(x in blob for x in BREAKING_TERMS)

# ======================================================
# FORMAT POST
# ======================================================
def format_post(title, slug, content, topic):
    url = f"https://grokipedia.com/{slug}"
    now = datetime.utcnow().strftime("%d %b %Y | %H:%M UTC")

    cleaned = clean_text(content)
    sents = sentences(cleaned)

    summary = " ".join(sents[:2])
    highlights = sents[2:7]
    why = " ".join(sents[7:9]) if len(sents) > 7 else "This development may impact market sentiment and on-chain activity."

    blob = cleaned.lower()
    risks = detect_risk(blob)
    score = impact_score(blob)
    breaking = is_breaking(blob, score)

    badge = "🚨 <b>BREAKING</b>" if breaking else "📰 <b>CRYPTO NEWS</b>"
    risk_line = f"\n🚫 <b>Risk Alert:</b> {', '.join(risks)}" if risks else ""

    msg = (
        f"{badge}\n"
        f"🧠 <b>{html_escape(title)}</b>\n"
        f"🔎 <i>Topic:</i> {html_escape(topic)}{risk_line}\n\n"
        f"🧠 <b>AI Quick Summary</b>\n"
        f"{html_escape(summary)}\n\n"
        f"🧩 <b>What happened?</b>\n"
        f"{html_escape(summary)}\n\n"
        f"📌 <b>Key Highlights</b>\n"
        + "\n".join([f"• {html_escape(h)}" for h in highlights])
        + "\n\n"
        f"⚠️ <b>Why it matters</b>\n"
        f"{html_escape(why)}\n\n"
        f"📊 <b>Market Impact:</b> {score}/100\n\n"
        f"🔗 <a href='{url}'>Read full article</a>\n"
        f"🕒 <i>{now}</i>\n"
        "#Crypto #Bitcoin #Ethereum #BNB #Solana #DeFi #Web3"
    )

    return msg[:3900]

# ======================================================
# SAFE SEND
# ======================================================
async def safe_send(bot, text):
    try:
        await bot.send_message(
            chat_id=CHAT_ID,
            text=text,
            parse_mode="HTML",
            disable_web_page_preview=False
        )
    except BadRequest:
        plain = re.sub(r"<[^>]+>", "", text)
        await bot.send_message(chat_id=CHAT_ID, text=plain)

# ======================================================
# MAIN LOOP
# ======================================================
async def run_cycle():
    bot = Bot(BOT_TOKEN)
    client = GrokipediaClient()
    memory = load_memory()
    posted = 0

    print(f"[INFO] Running for topics: {QUERIES}")

    for topic in QUERIES:
        if posted >= MAX_POSTS_PER_RUN:
            break

        results = client.search(topic, limit=RESULTS_PER_QUERY).get("results", [])
        for r in results:
            slug = r.get("slug")
            title = r.get("title") or slug
            if not slug:
                continue

            key = uid(slug)
            if key in memory:
                continue

            page = client.get_page(slug, include_content=True)
            content = page.get("page", {}).get("content", "")

            if not is_crypto_relevant(title, content):
                memory.add(key)
                save_memory(memory)
                continue

            msg = format_post(title, slug, content, topic)
            await safe_send(bot, msg)

            memory.add(key)
            save_memory(memory)
            posted += 1
            await asyncio.sleep(2)

    print(f"[INFO] Posted {posted} messages")

# ======================================================
# ENTRY
# ======================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    if args.once:
        asyncio.run(run_cycle())
    else:
        while True:
            asyncio.run(run_cycle())
            asyncio.sleep(1800)