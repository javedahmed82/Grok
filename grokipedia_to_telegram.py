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
    # safer defaults than "crypto"
    QUERIES = ["bitcoin", "ethereum", "defi", "altcoin", "token", "blockchain", "web3", "binance"]

RESULTS_PER_QUERY = int(os.getenv("RESULTS_PER_QUERY", "3"))
MEMORY_FILE = os.getenv("MEMORY_FILE", "posted_memory.json")

# Telegram hard limit: 4096 chars
TG_MAX = 4096

# How many posts max per run (to avoid flooding)
MAX_POSTS_PER_RUN = int(os.getenv("MAX_POSTS_PER_RUN", "6"))

# AI Summary toggle (optional)
AI_ENABLED = os.getenv("AI_ENABLED", "0").strip() == "1"
AI_PROVIDER = os.getenv("AI_PROVIDER", "none").strip().lower()  # "none" | "openai_compatible"
AI_API_URL = os.getenv("AI_API_URL", "").strip()  # e.g. https://api.openai.com/v1/chat/completions or any compatible
AI_API_KEY = os.getenv("AI_API_KEY", "").strip()
AI_MODEL = os.getenv("AI_MODEL", "gpt-4o-mini").strip()  # any compatible model name
AI_TIMEOUT = int(os.getenv("AI_TIMEOUT", "25"))

# Breaking threshold
BREAKING_SCORE_THRESHOLD = int(os.getenv("BREAKING_SCORE_THRESHOLD", "75"))

# Keep sources count
MAX_SOURCES = int(os.getenv("MAX_SOURCES", "3"))

# Hashtags (edit as you like)
DEFAULT_HASHTAGS = os.getenv(
    "HASHTAGS",
    "#Crypto #Bitcoin #Ethereum #Altcoins #Blockchain #DeFi #Web3"
).strip()


# -----------------------------
# FILTERS (avoid off-topic)
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
    "scam", "rug pull", "rugpull", "ponzi", "fraud", "hack", "exploit", "drained",
    "phishing", "malware", "laundering", "indictment", "charged", "sec", "lawsuit",
    "sanction", "shutdown", "exit scam", "frozen", "seized", "arrested"
}

BREAKING_KEYWORDS = {
    "breaking", "urgent", "just in", "alert", "hacked", "exploit", "sec", "approved",
    "etf", "lawsuit", "charges", "indictment", "massive", "surge", "plunge", "halted"
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
    t = re.sub(r"\[([^\]]+)\]\(/page/[^\)]+\)", r"\1", t)          # internal links
    t = re.sub(r"\(/page/[^\)]+\)", "", t)                        # leftovers
    t = re.sub(r"\[([^\]]+)\]\((https?://[^\)]+)\)", r"\1", t)    # external markdown links
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
# OFFTOPIC / CRYPTO RELEVANCE
# -----------------------------
def is_offtopic(title: str, content: str) -> bool:
    blob = (title + " " + content).lower()
    if any(k in blob for k in OFFTOPIC_KEYWORDS):
        # only treat off-topic if crypto context is weak
        if sum(1 for k in CRYPTO_CONTEXT_KEYWORDS if k in blob) < 2:
            return True
    return False


# -----------------------------
# RISK TAG + IMPACT SCORE + BREAKING
# -----------------------------
def risk_detect(title: str, content: str):
    blob = (title + " " + content).lower()
    hits = [k for k in RISK_KEYWORDS if k in blob]
    if hits:
        # pick top 3 keywords for display
        uniq = []
        for h in hits:
            if h not in uniq:
                uniq.append(h)
            if len(uniq) == 3:
                break
        return True, uniq
    return False, []

def impact_score(title: str, content: str, sources_count: int) -> int:
    """
    Heuristic score 0..100 based on "market-moving" terms + risk + major events.
    """
    blob = (title + " " + content).lower()
    score = 10

    # positive movers
    positives = {
        "etf": 25, "approved": 18, "approval": 18, "partnership": 10, "listing": 12,
        "launch": 10, "upgrade": 10, "mainnet": 12, "adoption": 10, "record high": 18,
        "surge": 12
    }
    # negative movers
    negatives = {
        "hack": 25, "exploit": 25, "sec": 22, "lawsuit": 15, "charges": 18,
        "indictment": 18, "arrested": 18, "plunge": 14, "halted": 16, "bankrupt": 22
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

    # more sources => more credible => slightly higher impact
    score += min(10, max(0, sources_count - 1) * 3)

    # cap
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
def ai_summarize_short(title: str, content: str) -> str:
    """
    Returns a short AI summary (2-3 lines).
    If AI disabled or not configured, fallback to heuristic summary.
    """
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


def heuristic_short_summary(cleaned: str) -> str:
    sents = split_sentences(cleaned)
    if not sents:
        return ""
    # Pick 1-2 best first lines
    s1 = sents[0]
    s2 = sents[1] if len(sents) > 1 else ""
    out = s1
    if s2 and len(out) < 140:
        out = out + " " + s2
    return clamp(out, 240)


# -----------------------------
# LONG NEWS BODY (WITH EMOJIS)
# -----------------------------
def build_news_sections(content: str):
    cleaned = strip_markup(content)
    sents = split_sentences(cleaned)

    # Keep only meaningful sentences
    sents = [s for s in sents if len(s) >= 35]

    if not sents:
        return "", [], ""

    what = " ".join(sents[:3])
    highlights = sents[3:10]
    why = " ".join(sents[10:13]) if len(sents) > 10 else (" ".join(sents[6:8]) if len(sents) > 6 else "")

    # bullet tightening
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
    """
    Prefer major publishers for rich preview (Telegram will fetch preview).
    If direct image isn't available, we use a good source URL and send as photo,
    Telegram still shows preview.
    """
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
    # fallback first source URL
    return (citations[0].get("url") or "").strip() or None


# -----------------------------
# FORMAT TELEGRAM POST (LONG + AI SHORT)
# -----------------------------
def format_post(title: str, slug: str, content: str, citations: list, topic: str) -> str:
    url = f"https://grokipedia.com/{slug}"
    time_now = datetime.utcnow().strftime("%d %b %Y | %H:%M UTC")

    what, bullets, why = build_news_sections(content)

    risky, risk_hits = risk_detect(title, content)
    score = impact_score(title, content, sources_count=len(citations or []))
    breaking = is_breaking(title, content, score)

    # AI short summary (or fallback)
    short_ai = ai_summarize_short(title, content)

    # Escape for HTML parse mode
    title_h = safe_html(title)
    topic_h = safe_html(topic)

    what_h = safe_html(what)
    bullets_h = [safe_html(b) for b in bullets]
    why_h = safe_html(why)
    short_ai_h = safe_html(short_ai)

    badge = "🚨 <b>BREAKING</b>" if breaking else "📰 <b>NEWS UPDATE</b>"
    risk_line = ""
    if risky:
        tags = ", ".join([safe_html(x) for x in risk_hits])
        risk_line = f"\n🚫 <b>Risk Alert:</b> <i>{tags}</i>"

    impact_bar = "🟢" if score < 40 else ("🟡" if score < 70 else "🔴")

    # Sources block
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
        f"🧠 <b>{title_h}</b>\n"
        f"🔎 <i>Topic:</i> {topic_h}{risk_line}\n\n"
        f"🧠 <b>AI Quick Summary</b>\n"
        f"{short_ai_h}\n\n"
        f"🧩 <b>What happened?</b>\n"
        f"{what_h}\n\n"
        f"📌 <b>Key Highlights</b>\n"
        + "\n".join([f"• {b}" for b in bullets_h[:6]])
        + "\n\n"
        f"⚠️ <b>Why it matters</b>\n"
        f"{why_h if why_h else safe_html('This could affect sentiment, liquidity, and market confidence—keep an eye on updates.')}\n\n"
        f"📊 <b>Market Impact Score:</b> {impact_bar} <b>{score}/100</b>\n\n"
        f"🔗 <b>Read full article</b>\n"
        f"<a href='{safe_html(url)}'>{safe_html(url)}</a>"
        f"{sources_block}\n\n"
        f"🕒 <i>{time_now}</i>\n"
        f"{safe_html(DEFAULT_HASHTAGS)}"
    )

    # Keep safe under Telegram limit
    msg = clamp(msg, 3900)
    return msg


# -----------------------------
# SAFE SEND (HTML + FALLBACK)
# -----------------------------
async def safe_send(bot: Bot, text: str, image_url: str | None):
    """
    Try photo with caption (best news feel). If fails, fallback to message.
    If HTML fails, fallback to plain text.
    """
    try:
        if image_url:
            await bot.send_photo(
                chat_id=CHAT_ID,
                photo=image_url,
                caption=text,
                parse_mode="HTML"
            )
        else:
            await bot.send_message(
                chat_id=CHAT_ID,
                text=text,
                parse_mode="HTML",
                disable_web_page_preview=False
            )
        return
    except BadRequest:
        # fallback: plain text (strip basic tags)
        plain = normalize_ws(text)
        plain = re.sub(r"<[^>]+>", "", plain)  # remove html tags
        plain = clamp(plain, TG_MAX)
        if image_url:
            await bot.send_photo(chat_id=CHAT_ID, photo=image_url, caption=plain)
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

            # stronger dedupe: include slug + title
            key = uid(f"{slug}|{title}")
            if key in memory:
                continue

            page = client.get_page(slug, include_content=True)
            p = page.get("page", {}) or {}
            content = p.get("content", "") or ""
            citations = p.get("citations", []) or []

            # Off-topic filter
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