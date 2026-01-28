import os
import re
import json
import hashlib
import argparse
import asyncio
from datetime import datetime
from html import escape as html_escape

from telegram import Bot
from telegram.error import BadRequest
from grokipedia_api import GrokipediaClient


# =========================
# CONFIG
# =========================
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "").strip()
MEMORY_FILE = os.getenv("MEMORY_FILE", "posted_memory.json")

RESULTS_PER_QUERY = int(os.getenv("RESULTS_PER_QUERY", "3"))
MAX_POSTS_PER_RUN = int(os.getenv("MAX_POSTS_PER_RUN", "8"))

# For alerts, keep previews OFF to avoid ugly PDF previews
DISABLE_PREVIEW = os.getenv("DISABLE_WEB_PREVIEW", "1").strip() == "1"

# Safer / disambiguated default queries
RAW_QUERIES = os.getenv("GROKIPEDIA_QUERIES", "").strip()
if RAW_QUERIES:
    QUERIES = [q.strip() for q in RAW_QUERIES.split(",") if q.strip()]
else:
    QUERIES = [
        "wallet drainer crypto",
        "phishing crypto wallet",
        "bridge hack crypto",
        "defi exploit hack",
        "rug pull scam token",
        "malware crypto wallet",
        "SEC crypto lawsuit",
        "exchange hack crypto",
        "airdrop scam crypto",
        "approval scam token",
    ]


# =========================
# KEYWORDS (ALERT-ONLY)
# =========================
# Anything that looks like a real risk signal
ALERT_TRIGGERS = [
    "wallet drainer", "drainer", "drain", "drained",
    "phishing", "fake site", "fake website", "impersonat",
    "hack", "hacked", "exploit", "exploited",
    "rug pull", "rugpull", "exit scam", "scam",
    "malware", "trojan", "keylogger",
    "bridge hack", "bridge exploited",
    "funds frozen", "withdrawals halted", "halted withdrawals",
    "sec", "lawsuit", "charged", "indictment", "arrested",
    "seized", "sanction"
]

# Words that usually indicate non-crypto garbage content
NOISE = [
    "railway", "locomotive", "steam", "factory", "built in",
    "austria", "bohemia", "inquisition", "religion", "islam",
    "judaism", "christian", "ramadan", "empire", "king",
    "km/h", "tons", "meters"
]

# =========================
# MEMORY
# =========================
def uid(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]

def load_memory() -> set[str]:
    if os.path.exists(MEMORY_FILE):
        try:
            with open(MEMORY_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            return set()
    return set()

def save_memory(mem: set[str]) -> None:
    with open(MEMORY_FILE, "w", encoding="utf-8") as f:
        json.dump(sorted(list(mem))[-8000:], f, indent=2, ensure_ascii=False)


# =========================
# TEXT CLEANING
# =========================
def normalize_ws(text: str) -> str:
    return " ".join((text or "").split())

def strip_markup(text: str) -> str:
    """
    Remove:
    - HTML comments
    - markdown/internal links
    - URLs in body
    """
    t = text or ""
    t = re.sub(r"<!--.*?-->", "", t, flags=re.DOTALL)
    t = re.sub(r"\[([^\]]+)\]\(/page/[^\)]+\)", r"\1", t)          # internal links
    t = re.sub(r"\(/page/[^\)]+\)", "", t)                        # leftovers
    t = re.sub(r"\[([^\]]+)\]\((https?://[^\)]+)\)", r"\1", t)    # markdown links
    t = re.sub(r"https?://\S+", "", t)                            # bare URLs
    return normalize_ws(t)

def first_sentences(text: str, n: int = 2) -> str:
    parts = re.split(r"(?<=[.!?])\s+", text or "")
    parts = [p.strip() for p in parts if len(p.strip()) > 25]
    return " ".join(parts[:n])


# =========================
# ALERT DETECTION / SCORING
# =========================
def is_noise(title: str, content: str) -> bool:
    low = (title + " " + content).lower()
    return any(w in low for w in NOISE)

def find_triggers(title: str, content: str) -> list[str]:
    low = (title + " " + content).lower()

    hits = []
    for k in ALERT_TRIGGERS:
        if k == "sec":
            # avoid "sec" meaning seconds/section
            if re.search(r"\bSEC\b", title + " " + content) or re.search(r"\bsec\b", low):
                if "section" not in low and not re.search(r"\bseconds?\b", low):
                    hits.append("sec")
            continue

        if k in low:
            hits.append(k)

    # de-dup
    uniq = []
    for h in hits:
        if h not in uniq:
            uniq.append(h)
        if len(uniq) >= 4:
            break
    return uniq

def detect_network(title: str, content: str) -> str:
    low = (title + " " + content).lower()

    tags = []
    # Networks / ecosystems
    if any(x in low for x in ["bnb", "bsc", "bnb chain", "smart chain"]):
        tags.append("BNB (BSC)")
    if any(x in low for x in ["ethereum", "eth", "erc-20", "erc20"]):
        tags.append("ETH")
    if any(x in low for x in ["solana", "sol"]):
        tags.append("SOL")
    if any(x in low for x in ["bitcoin", "btc"]):
        tags.append("BTC")
    if any(x in low for x in ["polygon", "matic"]):
        tags.append("Polygon")
    if any(x in low for x in ["arbitrum", "arb"]):
        tags.append("Arbitrum")
    if any(x in low for x in ["optimism", "op"]):
        tags.append("Optimism")
    if any(x in low for x in ["avalanche", "avax"]):
        tags.append("Avalanche")
    if any(x in low for x in ["tron", "trx"]):
        tags.append("TRON")

    if not tags:
        # generic EVM if wallet drainer / approvals mentioned
        if any(x in low for x in ["approval", "revoke", "wallet", "token", "transaction"]):
            tags.append("EVM")
        else:
            tags.append("Crypto")

    # limit
    return " / ".join(tags[:2])

def impact_and_action(triggers: list[str], title: str, content: str):
    low = (title + " " + content).lower()

    # Very high events
    if any(t in triggers for t in ["bridge hack", "exploit", "hacked", "drained", "funds frozen", "withdrawals halted", "halted withdrawals"]):
        return "🔴🔴 VERY HIGH (Funds Drained / Locked)", "EXIT / AVOID"

    # High events
    if any(t in triggers for t in ["wallet drainer", "drainer", "phishing", "rug pull", "rugpull", "exit scam", "malware", "scam"]):
        return "🔴 HIGH (Funds Loss Possible)", "STAY AWAY"

    # Medium legal/regulatory
    if "sec" in triggers or any(t in triggers for t in ["lawsuit", "charged", "indictment", "arrested", "seized", "sanction"]):
        return "🟡 MEDIUM (Legal/Regulatory Risk)", "CAUTION"

    # Default
    if triggers:
        return "🟡 MEDIUM", "CAUTION"

    return "🟢 LOW", "SAFE"

def build_risk_lines(triggers: list[str], title: str, content: str):
    low = (title + " " + content).lower()
    risk = []
    todo = []

    # Wallet drainer / phishing
    if any(t in triggers for t in ["wallet drainer", "drainer", "phishing", "fake site", "fake website", "impersonat"]):
        risk = [
            "Fake sites wallets drain kar sakti hain",
            "EVM users (BSC/ETH) zyada target hote hain",
        ]
        todo = [
            "Koi bhi unknown transaction SIGN mat karo",
            "Turant token approvals revoke karo",
            "Airdrop / free mint links se door raho",
        ]
        return risk, todo

    # Hack / exploit
    if any(t in triggers for t in ["hack", "hacked", "exploit", "exploited", "bridge hack", "drained"]):
        risk = [
            "Smart contract/bridge exploit detect hua",
            "User funds risk me ho sakte hain",
        ]
        todo = [
            "Agar funds hain to withdraw try karo",
            "Protocol/app se interact mat karo",
            "Sirf official updates follow karo",
        ]
        return risk, todo

    # Rug pull / scam
    if any(t in triggers for t in ["rug pull", "rugpull", "exit scam", "scam"]):
        risk = [
            "Project me rug/exit scam signals",
            "Liquidity drain / dev dump ka risk",
        ]
        todo = [
            "Token buy/sell avoid karo",
            "Wallet approvals check & revoke karo",
            "Only verified sources se confirm karo",
        ]
        return risk, todo

    # Legal / SEC
    if "sec" in triggers or any(t in triggers for t in ["lawsuit", "charged", "indictment", "arrested"]):
        risk = [
            "Legal/regulatory action ki possibility",
            "Market volatility aur delisting risk",
        ]
        todo = [
            "Over-leverage avoid karo",
            "Official filings/news cross-check karo",
            "Risk manage karo (stop-loss / small size)",
        ]
        return risk, todo

    # Generic
    risk = ["Potential threat detected"]
    todo = ["Official updates follow karo", "Unknown links/tx avoid karo"]
    return risk, todo


# =========================
# FORMAT ALERT MESSAGE (PREVIEW STYLE)
# =========================
def format_alert(title: str, slug: str, content: str, topic: str, triggers: list[str]) -> str:
    url = f"https://grokipedia.com/{slug}"
    time_now = datetime.utcnow().strftime("%d %b %Y | %H:%M UTC")

    network = detect_network(title, content)
    impact, action = impact_and_action(triggers, title, content)
    risk_lines, todo_lines = build_risk_lines(triggers, title, content)

    # Clean + short “context”
    cleaned = strip_markup(content)
    context = first_sentences(cleaned, n=2)
    context = normalize_ws(context)

    # Title polish (short)
    t = title.strip()
    if len(t) > 70:
        t = t[:67] + "..."

    msg = (
        f"🚨 <b>ALERT:</b> {html_escape(t)}\n"
        f"🏷️ <b>Network:</b> {html_escape(network)}\n\n"
        f"⚠️ <b>Risk:</b>\n"
        + "\n".join([f"• {html_escape(x)}" for x in risk_lines])
        + "\n\n"
        f"🧠 <b>What to do NOW:</b>\n"
        + "\n".join([f"• {html_escape(x)}" for x in todo_lines])
        + "\n\n"
        f"📊 <b>Impact:</b> {html_escape(impact)}\n"
        f"🔥 <b>Action:</b> {html_escape(action)}\n\n"
        f"🧾 <b>Context:</b> {html_escape(context)}\n\n"
        f"🔗 <b>Read on Grokipedia</b>\n"
        f"<a href='{html_escape(url)}'>{html_escape(url)}</a>\n\n"
        f"🕒 <i>{html_escape(time_now)}</i>"
    )

    # Safety clamp
    return msg[:3800]


# =========================
# SEND
# =========================
async def send_message(bot: Bot, text: str):
    try:
        await bot.send_message(
            chat_id=CHAT_ID,
            text=text,
            parse_mode="HTML",
            disable_web_page_preview=DISABLE_PREVIEW
        )
    except BadRequest:
        plain = re.sub(r"<[^>]+>", "", text)
        await bot.send_message(chat_id=CHAT_ID, text=plain, disable_web_page_preview=True)


# =========================
# MAIN
# =========================
async def run_cycle():
    if not BOT_TOKEN or not CHAT_ID:
        raise RuntimeError("Missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID")

    print(f"[INFO] ALERT-ONLY mode ON")
    print(f"[INFO] QUERIES={QUERIES} RESULTS_PER_QUERY={RESULTS_PER_QUERY}")

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

            slug = (item.get("slug") or "").strip()
            title = (item.get("title") or slug).strip()
            if not slug:
                continue

            key = uid(slug)
            if key in memory:
                continue

            page = client.get_page(slug, include_content=True)
            content = ((page.get("page", {}) or {}).get("content", "")) or ""

            # 1) quick noise block
            if is_noise(title, content):
                memory.add(key)
                save_memory(memory)
                continue

            # 2) ALERT triggers only
            triggers = find_triggers(title, content)
            if not triggers:
                # Not an alert -> skip silently
                memory.add(key)
                save_memory(memory)
                continue

            # 3) Build and send alert
            msg = format_alert(title, slug, content, topic, triggers)
            await send_message(bot, msg)

            memory.add(key)
            save_memory(memory)
            posted += 1
            await asyncio.sleep(2)

    print(f"[INFO] Posted {posted} alert(s).")


async def main_loop():
    while True:
        await run_cycle()
        await asyncio.sleep(1800)  # 30 min


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    args = parser.parse_args()

    if args.once:
        asyncio.run(run_cycle())
    else:
        asyncio.run(main_loop())