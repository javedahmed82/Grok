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


# -----------------------------
# ENV / SETTINGS
# -----------------------------
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()

RAW_QUERIES = os.getenv("GROKIPEDIA_QUERIES", "").strip()
if RAW_QUERIES:
    QUERIES = [q.strip() for q in RAW_QUERIES.split(",") if q.strip()]
else:
    QUERIES = ["bitcoin", "ethereum", "defi", "altcoin", "token", "blockchain", "web3", "binance"]

RESULTS_PER_QUERY = int(os.getenv("RESULTS_PER_QUERY", "3"))
MEMORY_FILE = os.getenv("MEMORY_FILE", "posted_memory.json")

# Telegram limits
TG_MAX = 4096
PHOTO_CAPTION_MAX = 900  # keep safely under 1024

# Avoid flooding per action run
MAX_POSTS_PER_RUN = int(os.getenv("MAX_POSTS_PER_RUN", "6"))

# AI Summary (optional)
AI_ENABLED = os.getenv("AI_ENABLED", "0").strip() == "1"
AI_PROVIDER = os.getenv("AI_PROVIDER", "none").strip().lower()  # "none" | "openai_compatible"
AI_API_URL = os.getenv("AI_API_URL", "").strip()
AI_API_KEY = os.getenv("AI_API_KEY", "").strip()
AI_MODEL = os.getenv("AI_MODEL", "gpt-4o-mini").strip()
AI_TIMEOUT = int(os.getenv("AI_TIMEOUT", "25"))

# Breaking threshold
BREAKING_SCORE_THRESHOLD = int(os.getenv("BREAKING_SCORE_THRESHOLD", "75"))

# Sources count
MAX_SOURCES = int(os.getenv("MAX_SOURCES", "3"))

# Hashtags
DEFAULT_HASHTAGS = os.getenv(
    "HASHTAGS",
    "#Crypto #Bitcoin #Ethereum #Altcoins #Blockchain #DeFi #Web3"
).strip()


# -----------------------------
# FILTERS / HEURISTICS
# -----------------------------
OFFTOPIC_KEYWORDS = {
    "religion", "islam", "judaism", "christian", "moriscos", "granada", "inquisition",
    "ottoman", "baptized", "spain", "iberian", "faith", "ramadan", "circumcision"
}

CRYPTO_CONTEXT_KEYWORDS = {
    "bitcoin", "ethereum", "crypto", "token", "blockchain", "defi", "web3",
    "exchange", "binance", "coinbase", "wallet", "airdrop", "staking", "nft"
}

RISK_KEYWORDS = {
    "scam", "rug pull", "rugpull", "ponzi", "fraud", "hack", "exploited", "exploit", "drained",
    "phishing", "malware", "laundering", "indictment", "charged", "sec", "lawsuit",
    "sanction", "shutdown", "exit scam", "frozen", "seized", "arrested", "bankrupt"
}

BREAKING_KEYWORDS = {
    "breaking", "urgent", "just in", "alert", "hacked", "hack", "exploit", "sec", "approved",
    "etf", "lawsuit", "charges", "indictment", "massive", "surge", "plunge", "halted", "bankrupt"
}


# -----------------------------
# MEMORY
# -----------------------------
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
        json.dump(sorted(list(mem))[-5000:], f, indent=2, ensure_ascii=False)

def uid(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]


# -----------------------------
# TEXT HELPERS
# -----------------------------
def normalize_ws(text: str) -> str:
    return " ".join((text or "").split())

def strip_markup(text: str) -> str:
    """
    Grokipedia content can contain:
    - HTML comments <!--infobox ... -->
    - internal links [Text](/page/X)
    - markdown links [Text](https://...)
    """
    t = text or ""
    t = re.sub(r"<!--.*?-->", "", t, flags=re.DOTALL)
    t = re.sub(r"\[([^\]]+)\]\(/page/[^\)]+\)", r"\1", t)
    t = re.sub(r"\(/page/[^\)]+\)", "", t)
    t = re.sub(r"\[([^\]]+)\]\((https?://[^\)]+)\)", r"\1", t)
    return normalize_ws(t)

def split_sentences(text: str):
    parts = re.split(r"(?<=[.!?])\s+", text or "")
    parts = [p.strip() for p in parts if p.strip()]
    return parts

def safe_html(s: str) -> str:
    return html_escape(s or "")

def clamp(s: str, n: int) -> str:
    if len(s) <= n:
        return s
    return s[: max(0, n - 1)] + "…"


# -----------------------------
# TOPIC FILTER
# -----------------------------
def is_offtopic(title: str, content: str) -> bool:
    blob = (title + " " + content).lower()
    if any(k in blob for k in OFFTOPIC_KEYWORDS):
        if sum(1 for k in CRYPTO_CONTEXT_KEYWORDS if k in blob) < 2:
            return True
    return False


# -----------------------------
# RISK / IMPACT / BREAKING
# -----------------------------
def risk_detect(title: str, content: str):
    blob = (title + " " + content).lower()
    hits = [k for k in RISK_KEYWORDS if k in blob]
    if hits:
        uniq = []
        for h in hits:
            if h not in uniq:
                uniq.append(h)
            if len(uniq) == 3:
                break
        return True, uniq
    return False, []

def impact_score(title: str, content: str, sources_count: int) -> int:
    blob = (title + " " + content).lower()
    score = 10

    positives = {
        "etf": 25, "approved": 18, "approval": 18, "partnership": 10, "listing": 12,
        "launch": 10, "upgrade": 10, "mainnet": 12, "adoption": 10, "record high": 18,
        "surge": 12
    }
    negatives = {
        "hack": 25, "hacked": 25, "exploit": 25, "sec": 22, "lawsuit": 15, "charges": 18,
        "indictment": 18, "arrested": 18, "plunge": 14, "halted": 16, "bankrupt": 22,
        "frozen": 15, "seized": 18, "shutdown": 18
    }

    for k, w in positives.items():
        if k in blob:
            score += w
    for k, w in negatives.items():
        if k in blob:
            score += w

    risky, _ = risk_detect(title, content)
    if risky:
        score += 18

    score += min(10, max(0, sources_count - 1) * 3)
    return max(0, min(100, score))

def is_breaking(title: str, content: str, score: int) -> bool:
    blob = (title + " " + content).lower()
    if score >= BREAKING_SCORE_THRESHOLD:
        return True
    if any(k in blob for k in BREAKING_KEYWORDS):
        return True
    return False


# -----------------------------
# AI SUMMARY (OPTIONAL)
# -----------------------------
def heuristic_short_summary(cleaned: str) -> str:
    sents = split_sentences(cleaned)
    if not sents:
        return ""
    s1 = sents[0]
    s2 = sents[1] if len(sents) > 1 else ""
    out = s1
    if s2 and len(out) < 140:
        out = out + " " + s2
    return clamp(out, 240)

def ai_summarize_short(title: str, content: str) -> str:
    cleaned = strip_markup(content)
    fallback = heuristic_short_summary(cleaned)

    if not AI_ENABLED or AI_PROVIDER == "none":
        return fallback

    if AI_PROVIDER == "openai_compatible":
        if not AI_API_URL or not AI_API_KEY:
            return fallback

        prompt = (
            "You are a crypto news editor. Produce a short summary in 2-3 lines.\n"
            "Rules:\n"
            "- No markdown.\n"
            "- No URLs.\n"
            "- Keep it concise and news-like.\n\n"
            f"Title: {title}\n"
            f"Article: {cleaned[:4000]}"
        )

        try:
            headers = {
                "Authorization": f"Bearer {AI_API_KEY}",
                "Content-Type": "application/json"
            }
            payload = {
                "model": AI_MODEL,
                "messages": [
                    {"role": "system", "content": "You summarize text for Telegram crypto news."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.3,
                "max_tokens": 120
            }
            r = requests.post(AI_API_URL, headers=headers, json=payload, timeout=AI_TIMEOUT)
            r.raise_for_status()
            data = r.json()
            text = (data.get("choices") or [{}])[0].get("message", {}).get("content", "")
            text = normalize_ws(text)
            return text if text else fallback
        except Exception:
            return fallback

    return fallback


# -----------------------------
# LONG NEWS BODY
# -----------------------------
def build_news_sections(content: str):
    cleaned = strip_markup(content)
    sents = [s for s in split_sentences(cleaned) if len(s) >= 35]

    if not sents:
        return "", [], ""

    what = " ".join(sents[:3])
    highlights = sents[3:10]
    why = " ".join(sents[10:13]) if len(sents) > 10 else (" ".join(sents[6:8]) if len(sents) > 6 else "")

    bullets = []
    for s in highlights:
        s = normalize_ws(s)
        if 50 <= len(s) <= 220:
            bullets.append(s)
        if len(bullets) >= 6:
            break

    if not bullets:
        bullets = [normalize_ws(s) for s in sents[3:7]][:5]

    return what, bullets, why


# -----------------------------
# IMAGE PICK
# -----------------------------
def pick_image_url(citations):
    if not citations:
        return None
    preferred_domains = [
        "reuters.com", "coindesk.com", "cointelegraph.com", "theblock.co",
        "time.com", "businessinsider.com", "bloomberg.com", "wsj.com",
        "okx.com", "binance.com", "coinbase.com"
    ]
    for c in citations:
        u = (c.get("url") or "").strip()
        if any(d in u for d in preferred_domains):
            return u
    return (citations[0].get("url") or "").strip() or None


# -----------------------------
# FORMAT LONG POST
# -----------------------------
def format_post(title: str, slug: str, content: str, citations: list, topic: str) -> str:
    url = f"https://grokipedia.com/{slug}"
    time_now = datetime.utcnow().strftime("%d %b %Y | %H:%M UTC")

    what, bullets, why = build_news_sections(content)

    risky, risk_hits = risk_detect(title, content)
    score = impact_score(title, content, sources_count=len(citations or []))
    breaking = is_breaking(title, content, score)

    short_ai = ai_summarize_short(title, content)

    badge = "🚨 <b>BREAKING</b>" if breaking else "📰 <b>NEWS UPDATE</b>"
    impact_bar = "🟢" if score < 40 else ("🟡" if score < 70 else "🔴")

    risk_line = ""
    if risky:
        tags = ", ".join([safe_html(x) for x in risk_hits])
        risk_line = f"\n🚫 <b>Risk Alert:</b> <i>{tags}</i>"

    sources_block = ""
    if citations:
        rows = []
        for c in (citations[:MAX_SOURCES]):
            t = (c.get("title") or "").strip()
            u = (c.get("url") or "").strip()
            if t and u:
                rows.append(f"• <a href='{safe_html(u)}'>{safe_html(t)}</a>")
        if rows:
            sources_block = "\n\n📚 <b>Sources</b>\n" + "\n".join(rows)

    msg = (
        f"{badge}\n"
        f"🧠 <b>{safe_html(title)}</b>\n"
        f"🔎 <i>Topic:</i> {safe_html(topic)}{risk_line}\n\n"
        f"🧠 <b>AI Quick Summary</b>\n"
        f"{safe_html(short_ai)}\n\n"
        f"🧩 <b>What happened?</b>\n"
        f"{safe_html(what)}\n\n"
        f"📌 <b>Key Highlights</b>\n"
        + "\n".join([f"• {safe_html(b)}" for b in bullets[:6]])
        + "\n\n"
        f"⚠️ <b>Why it matters</b>\n"
        f"{safe_html(why) if why else safe_html('This could affect sentiment, liquidity, and market confidence—keep an eye on updates.')}\n\n"
        f"📊 <b>Market Impact Score:</b> {impact_bar} <b>{score}/100</b>\n\n"
        f"🔗 <b>Read full article</b>\n"
        f"<a href='{safe_html(url)}'>{safe_html(url)}</a>"
        f"{sources_block}\n\n"
        f"🕒 <i>{time_now}</i>\n"
        f"{safe_html(DEFAULT_HASHTAGS)}"
    )

    return clamp(msg, 3900)


# -----------------------------
# PHOTO CAPTION SPLIT (FIX)
# -----------------------------
def split_for_photo_and_text(full_html: str) -> tuple[str, str]:
    if not full_html:
        return "", ""
    if len(full_html) <= PHOTO_CAPTION_MAX:
        return full_html, ""

    caption = full_html[:PHOTO_CAPTION_MAX]
    cut = max(caption.rfind("\n"), caption.rfind(" "))
    if cut > 200:
        caption = caption[:cut]
    caption = caption.strip() + "…"
    return caption, full_html


# -----------------------------
# SAFE SEND (PHOTO + LONG MESSAGE)
# -----------------------------
async def safe_send(bot: Bot, text: str, image_url: str | None):
    caption_html, long_html = split_for_photo_and_text(text)

    try:
        if image_url:
            # 1) Photo with short caption
            await bot.send_photo(
                chat_id=CHAT_ID,
                photo=image_url,
                caption=caption_html,
                parse_mode="HTML",
            )
            # 2) Full long post as separate message
            if long_html:
                await bot.send_message(
                    chat_id=CHAT_ID,
                    text=clamp(long_html, TG_MAX),
                    parse_mode="HTML",
                    disable_web_page_preview=False
                )
        else:
            await bot.send_message(
                chat_id=CHAT_ID,
                text=clamp(text, TG_MAX),
                parse_mode="HTML",
                disable_web_page_preview=False
            )
        return

    except BadRequest:
        # fallback plain text
        plain = normalize_ws(text)
        plain = re.sub(r"<[^>]+>", "", plain)
        plain = clamp(plain, TG_MAX)

        if image_url:
            cap_plain = clamp(plain, PHOTO_CAPTION_MAX)
            await bot.send_photo(chat_id=CHAT_ID, photo=image_url, caption=cap_plain)
            if len(plain) > PHOTO_CAPTION_MAX:
                await bot.send_message(chat_id=CHAT_ID, text=plain, disable_web_page_preview=False)
        else:
            await bot.send_message(chat_id=CHAT_ID, text=plain, disable_web_page_preview=False)


# -----------------------------
# MAIN CYCLE
# -----------------------------
async def run_cycle():
    if not BOT_TOKEN or not CHAT_ID:
        raise RuntimeError("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")

    print(f"[INFO] QUERIES={QUERIES} RESULTS_PER_QUERY={RESULTS_PER_QUERY} AI_ENABLED={AI_ENABLED}")

    bot = Bot(BOT_TOKEN)
    client = GrokipediaClient()
    memory = load_memory()

    posted = 0

    for topic in QUERIES:
        if posted >= MAX_POSTS_PER_RUN:
            break

        results = client.search(topic, limit=RESULTS_PER_QUERY)
        items = results.get("results", []) or []

        for item in items:
            if posted >= MAX_POSTS_PER_RUN:
                break

            slug = item.get("slug")
            title = item.get("title") or slug
            if not slug:
                continue

            key = uid(f"{slug}|{title}")
            if key in memory:
                continue

            page = client.get_page(slug, include_content=True)
            p = page.get("page", {}) or {}
            content = p.get("content", "") or ""
            citations = p.get("citations", []) or []

            if is_offtopic(title or "", content or ""):
                memory.add(key)
                save_memory(memory)
                continue

            msg = format_post(title, slug, content, citations, topic)
            image_url = pick_image_url(citations)

            await safe_send(bot, msg, image_url=image_url)

            memory.add(key)
            save_memory(memory)
            posted += 1
            await asyncio.sleep(2)

    print(f"[INFO] Posted {posted} post(s).")


async def main_loop():
    while True:
        await run_cycle()
        await asyncio.sleep(1800)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    args = parser.parse_args()

    if args.once:
        asyncio.run(run_cycle())
    else:
        asyncio.run(main_loop())