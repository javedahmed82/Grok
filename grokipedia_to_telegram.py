import os
import json
import time
import hashlib
import argparse
from datetime import datetime

from telegram import Bot
from grokipedia_api import GrokipediaClient

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
QUERIES = [q.strip() for q in os.getenv("GROKIPEDIA_QUERIES", "bitcoin,BNB,PancakeSwap").split(",")]
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
        srcs = []
        for c in citations[:2]:
            if c.get("title") and c.get("url"):
                srcs.append(f"• <a href='{c['url']}'>{c['title']}</a>")
        if srcs:
            src = "\n\n<b>Sources</b>\n" + "\n".join(srcs)

    return (
        f"🧠 <b>{title}</b>\n"
        f"🔍 <i>Topic:</i> {topic}\n\n"
        f"{clean(summary)}\n\n"
        f"🔗 <a href='{url}'>Read on Grokipedia</a>\n"
        f"🕒 {time_now}"
        f"{src}"
    )

def run_cycle():
    if not BOT_TOKEN or not CHAT_ID:
        raise RuntimeError("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")

    bot = Bot(BOT_TOKEN)
    client = GrokipediaClient()
    memory = load_memory()

    for topic in QUERIES:
        res = client.search(topic, limit=RESULTS_PER_QUERY)
        for r in res.get("results", []):
            slug = r.get("slug")
            title = r.get("title") or slug
            if not slug:
                continue

            key = uid(slug)
            if key in memory:
                continue

            page = client.get_page(slug, include_content=True)
            p = page.get("page", {})
            content = p.get("content", "")
            citations = p.get("citations", [])

            msg = format_post(title, slug, content, citations, topic)

            bot.send_message(
                chat_id=CHAT_ID,
                text=msg,
                parse_mode="HTML",
                disable_web_page_preview=False
            )

            memory.add(key)
            save_memory(memory)
            time.sleep(3)

def main_loop():
    while True:
        run_cycle()
        time.sleep(1800)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    args = parser.parse_args()

    if args.once:
        run_cycle()
    else:
        main_loop()
