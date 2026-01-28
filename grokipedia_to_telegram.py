import os
import json
import time
import hashlib
import argparse
import asyncio
from datetime import datetime

from telegram import Bot
from grokipedia_api import GrokipediaClient

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
QUERIES = [q.strip() for q in os.getenv("GROKIPEDIA_QUERIES", "bitcoin,BNB,PancakeSwap").split(",") if q.strip()]
RESULTS_PER_QUERY = int(os.getenv("RESULTS_PER_QUERY", "3"))
MEMORY_FILE = os.getenv("MEMORY_FILE", "posted_memory.json")


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


def uid(text):
    return hashlib.sha256(text.encode()).hexdigest()[:24]


def clean(text, limit=900):
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[:limit] + "…"


def format_post(title, slug, summary, citations, topic):
    url = f"https://grokipedia.com/{slug}"
    time_now = datetime.utcnow().strftime("%d %b %Y | %H:%M UTC")

    src = ""
    if citations:
        rows = []
        for c in citations[:2]:
            if c.get("title") and c.get("url"):
                rows.append(f"• <a href='{c['url']}'>{c['title']}</a>")
        if rows:
            src = "\n\n<b>Sources</b>\n" + "\n".join(rows)

    return (
        f"🧠 <b>{title}</b>\n"
        f"🔍 <i>Topic:</i> {topic}\n\n"
        f"{clean(summary)}\n\n"
        f"🔗 <a href='{url}'>Read on Grokipedia</a>\n"
        f"🕒 {time_now}"
        f"{src}"
    )


async def run_cycle():
    if not BOT_TOKEN or not CHAT_ID:
        raise RuntimeError("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")

    bot = Bot(BOT_TOKEN)
    client = GrokipediaClient()
    memory = load_memory()

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
            content = p.get("content", "")
            citations = p.get("citations", [])

            message = format_post(title, slug, content, citations, topic)

            await bot.send_message(
                chat_id=CHAT_ID,
                text=message,
                parse_mode="HTML",
                disable_web_page_preview=False
            )

            memory.add(key)
            save_memory(memory)
            await asyncio.sleep(3)


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