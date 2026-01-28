import os
import json
import hashlib
import argparse
import asyncio
from datetime import datetime
from html import escape as html_escape

from telegram import Bot
from telegram.error import BadRequest
from grokipedia_api import GrokipediaClient

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

_raw = os.getenv("GROKIPEDIA_QUERIES", "").strip()
if _raw:
    QUERIES = [q.strip() for q in _raw.split(",") if q.strip()]
else:
    QUERIES = ["bitcoin", "BNB", "PancakeSwap"]

RESULTS_PER_QUERY = int(os.getenv("RESULTS_PER_QUERY", "3"))
MEMORY_FILE = os.getenv("MEMORY_FILE", "posted_memory.json")

# Telegram hard limit is 4096 chars for a message
TG_MAX = 4096

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

def normalize_ws(text: str) -> str:
    return " ".join((text or "").split())

def clean_summary(raw: str, limit: int = 1200) -> str:
    """
    Grokipedia content might contain HTML/markup/comments like <!--infobox-->.
    We escape it to make it safe under Telegram HTML parse_mode.
    """
    raw = normalize_ws(raw)
    safe = html_escape(raw)  # converts < > & etc. to entities
    if len(safe) <= limit:
        return safe
    return safe[:limit] + "…"

def format_post(title: str, slug: str, summary_raw: str, citations: list, topic: str) -> str:
    url = f"https://grokipedia.com/{slug}"
    time_now = datetime.utcnow().strftime("%d %b %Y | %H:%M UTC")

    # Escape title/topic too (just in case)
    title_safe = html_escape(title or "")
    topic_safe = html_escape(topic or "")

    summary_safe = clean_summary(summary_raw, limit=1400)

    src = ""
    if citations:
        rows = []
        for c in citations[:2]:
            t = (c.get("title") or "").strip()
            u = (c.get("url") or "").strip()
            if t and u:
                rows.append(f"• <a href='{html_escape(u, quote=True)}'>{html_escape(t)}</a>")
        if rows:
            src = "\n\n<b>Sources</b>\n" + "\n".join(rows)

    msg = (
        f"🧠 <b>{title_safe}</b>\n"
        f"🔍 <i>Topic:</i> {topic_safe}\n\n"
        f"{summary_safe}\n\n"
        f"🔗 <a href='{html_escape(url, quote=True)}'>Read on Grokipedia</a>\n"
        f"🕒 {time_now}"
        f"{src}"
    )

    # Ensure within Telegram limit (keep ending + links if possible)
    if len(msg) > TG_MAX:
        # Hard trim from summary section
        overhead = len(msg) - len(summary_safe)
        allowed_summary = max(300, TG_MAX - overhead - 10)
        summary_safe2 = clean_summary(summary_raw, limit=allowed_summary)
        msg = (
            f"🧠 <b>{title_safe}</b>\n"
            f"🔍 <i>Topic:</i> {topic_safe}\n\n"
            f"{summary_safe2}\n\n"
            f"🔗 <a href='{html_escape(url, quote=True)}'>Read on Grokipedia</a>\n"
            f"🕒 {time_now}"
            f"{src}"
        )
        if len(msg) > TG_MAX:
            msg = msg[:TG_MAX - 1] + "…"
    return msg

async def safe_send(bot: Bot, text: str):
    """
    Try HTML mode; if still fails for any reason, fallback to plain text.
    """
    try:
        await bot.send_message(
            chat_id=CHAT_ID,
            text=text,
            parse_mode="HTML",
            disable_web_page_preview=False,
        )
        return
    except BadRequest as e:
        # fallback: plain text
        plain = normalize_ws(text)
        # remove any remaining HTML tags (very simple)
        plain = plain.replace("<b>", "").replace("</b>", "").replace("<i>", "").replace("</i>", "")
        plain = plain.replace("<a href='", "").replace("'>", " ").replace("</a>", "")
        await bot.send_message(
            chat_id=CHAT_ID,
            text=plain[:TG_MAX],
            disable_web_page_preview=False,
        )

async def run_cycle():
    if not BOT_TOKEN or not CHAT_ID:
        raise RuntimeError("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")

    print(f"[INFO] QUERIES={QUERIES} RESULTS_PER_QUERY={RESULTS_PER_QUERY}")

    bot = Bot(BOT_TOKEN)
    client = GrokipediaClient()
    memory = load_memory()

    posted = 0

    for topic in QUERIES:
        results = client.search(topic, limit=RESULTS_PER_QUERY)
        for item in results.get("results", []):
            slug = item.get("slug")
            title = item.get("title") or slug
            if not slug:
                continue

            key = uid(slug)
            if key in memory:
                continue

            page = client.get_page(slug, include_content=True)
            p = page.get("page", {})
            content = p.get("content", "") or ""
            citations = p.get("citations", []) or []

            msg = format_post(title, slug, content, citations, topic)
            await safe_send(bot, msg)

            memory.add(key)
            save_memory(memory)
            posted += 1
            await asyncio.sleep(2)

    print(f"[INFO] Posted {posted} message(s).")

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