# ===============================================
# CRONUS BIN CHECKER 2024 - HTML EDITION + NEUTRINO
# ===============================================

import re
import time
import random
import string
import sqlite3
import requests
import html
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
from collections import Counter
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from telegram.constants import ChatAction

# ===============================================
# CONFIG
# ===============================================
BOT_TOKEN = '8325790958:AAEZW-WNzGc6JavPomAcF7DdlFiGhgjl1J4'
ADMIN_ID = 5878052332
SALES_LINK = 't.me/cronusxxx'

# Neutrino API (provided)
NEUTRINO_USER_ID = 'cronusxxx'
NEUTRINO_API_KEY = 'dzB55DN8poBfQFeoI7F007YpkF4YF55j44qU1t12hCiBOqJ6'  # Testing key

# ===============================================
# DATABASE
# ===============================================
DB_FILE = 'keys.db'
conn = sqlite3.connect(DB_FILE, check_same_thread=False)
c = conn.cursor()
c.execute('''
    CREATE TABLE IF NOT EXISTS keys (
        key TEXT PRIMARY KEY,
        user_id INTEGER,
        activated_at TEXT,
        expires_at TEXT,
        duration_minutes INTEGER DEFAULT 2880
    )
''')
try:
    c.execute("ALTER TABLE keys ADD COLUMN duration_minutes INTEGER DEFAULT 2880")
    conn.commit()
except sqlite3.OperationalError:
    pass
conn.commit()

# ===============================================
# KEY SYSTEM
# ===============================================
def generate_custom_key():
    return 'CRONUSKEY-' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

def is_key_valid(user_id):
    c.execute("SELECT expires_at FROM keys WHERE user_id=?", (user_id,))
    r = c.fetchone()
    if r:
        if datetime.now() >= datetime.fromisoformat(r[0]):
            c.execute("DELETE FROM keys WHERE user_id=?", (user_id,))
            conn.commit()
            return False
        return True
    return False

def activate_key(key, user_id):
    if not re.match(r'^CRONUSKEY-[A-Z0-9]{6}$', key):
        return False, "Invalid key format!"
    c.execute("SELECT user_id, duration_minutes FROM keys WHERE key=?", (key,))
    r = c.fetchone()
    if not r:
        return False, "Key not found!"
    if r[0]:
        return False, "Already activated!"
    if is_key_valid(user_id):
        return False, "You have an active key!"
    c.execute("DELETE FROM keys WHERE user_id=?", (user_id,))
    conn.commit()
    duration = r[1] or 2880
    activated_at = datetime.now().isoformat()
    expires = (datetime.now() + timedelta(minutes=duration)).isoformat()
    c.execute("UPDATE keys SET user_id=?, activated_at=?, expires_at=? WHERE key=?", (user_id, activated_at, expires, key))
    conn.commit()
    return True, "Activated! Use /bin 000000"

# ===============================================
# LIVE NEUTRINO LOOKUP
# ===============================================
def neutrino_lookup(bin_num: str):
    try:
        resp = requests.post(
            "https://neutrinoapi.net/bin-lookup",
            data={
                "user-id": NEUTRINO_USER_ID,
                "api-key": NEUTRINO_API_KEY,
                "bin-number": bin_num
            },
            timeout=12
        )
        if resp.status_code != 200:
            return None
        d = resp.json()
        result = {
            "brand": (d.get("card-brand") or "").upper() or None,
            "type": (d.get("card-type") or "").upper() or None,
            "level": (d.get("card-category") or "").upper() or None,
            "issuer": d.get("issuer") or None,
            "country": (d.get("country") or "").upper() or None,
            "supports_3ds": d.get("is-3d-secure") if d.get("is-3d-secure") is not None else d.get("supports-3d-secure")
        }
        return result
    except Exception:
        return None

# ===============================================
# SCRAPE FALLBACK SOURCES
# ===============================================
def get_bin_info(bin_num):
    time.sleep(1)
    info = {
        'brand': 'UNKNOWN', 'type': 'DEBIT', 'level': 'CLASSIC',
        'issuer': 'Generic Bank', 'country': 'Unknown', 'vbv_votes': []
    }
    brands, types, levels, issuers, countries = [], [], [], [], []

    # 1. binlist.net
    try:
        r = requests.get(f"https://lookup.binlist.net/{bin_num}", timeout=8,
                         headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code == 200:
            d = r.json()
            scheme = d.get('scheme')
            if scheme and scheme.lower() not in ['unknown']:
                brands.append(scheme.upper())
            card_type = d.get('type')
            if card_type and card_type.lower() not in ['unknown']:
                types.append('CREDIT' if card_type == 'credit' else 'DEBIT')
            level = d.get('brand')
            if level and level.lower() not in ['unknown', '']:
                levels.append(level.upper())
            bank = d.get('bank', {}).get('name')
            if bank and bank.lower() not in ['unknown', '']:
                issuers.append(bank)
            country_name = d.get('country', {}).get('name')
            if country_name and country_name.lower() not in ['unknown']:
                countries.append(country_name)
    except:
        pass

    # 2. handyapi.com
    try:
        r = requests.get(f"https://data.handyapi.com/bin/{bin_num}", timeout=8,
                         headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code == 200:
            d = r.json()
            if d.get('Status') == 'SUCCESS':
                scheme = d.get('Scheme')
                if scheme and scheme.lower() not in ['unknown']:
                    brands.append(scheme.upper())
                card_type = d.get('Type')
                if card_type and card_type.lower() not in ['unknown']:
                    types.append(card_type.upper())
                card_tier = d.get('CardTier')
                if card_tier and card_tier.lower() not in ['unknown', '']:
                    levels.append(card_tier.upper())
                issuer = d.get('Issuer')
                if issuer and issuer.lower() not in ['unknown', '']:
                    issuers.append(issuer)
                country_name = d.get('Country', {}).get('Name')
                if country_name and country_name.lower() not in ['unknown']:
                    countries.append(country_name)
    except:
        pass

    # 3. bincodes.com
    try:
        r = requests.get(f"https://www.bincodes.com/bin/{bin_num}", timeout=8,
                         headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')

            vbv = soup.find('td', string=re.compile('3D Secure|VBV', re.I))
            if vbv:
                txt = vbv.find_next_sibling('td').text.strip().upper()
                info['vbv_votes'].append('YES' if any(x in txt for x in ['YES','ENABLED','SECURE']) else 'NO')

            issuer_td = soup.find('td', string=re.compile('Issuer|Bank', re.I))
            if issuer_td:
                txt = issuer_td.find_next_sibling('td').text.strip()
                if txt and txt.lower() not in ['unknown', '']:
                    issuers.append(txt)

            card_type_td = soup.find('td', string=re.compile('Card Type', re.I))
            if card_type_td:
                txt = card_type_td.find_next_sibling('td').text.strip().upper()
                if txt and txt not in ['UNKNOWN']:
                    types.append(txt)

            brand_td = soup.find('td', string=re.compile('Card Scheme', re.I))
            if brand_td:
                txt = brand_td.find_next_sibling('td').text.strip().upper()
                if txt and txt not in ['UNKNOWN']:
                    brands.append(txt)

            level_td = soup.find('td', string=re.compile('Card Level', re.I))
            if level_td:
                txt = level_td.find_next_sibling('td').text.strip().upper()
                if txt and txt not in ['UNKNOWN']:
                    levels.append(txt)

            country_td = soup.find('td', string=re.compile('Country', re.I))
            if country_td:
                txt = country_td.find_next_sibling('td').text.strip()
                if txt and txt.lower() not in ['unknown']:
                    countries.append(txt)
    except:
        pass

    # 4. bincheck.io
    try:
        r = requests.get(f"https://bincheck.io/bin/{bin_num}", timeout=8,
                         headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, 'html.parser')
            data = {}
            for row in soup.select('table tr'):
                tds = row.find_all('td')
                if len(tds) == 2:
                    key = tds[0].text.strip().lower().replace(' ', '*').replace('/', '*')
                    data[key] = tds[1].text.strip()

            issuer = data.get('issuer_name_/_bank')
            if issuer and issuer.lower() not in ['unknown', '']:
                issuers.append(issuer)

            if '3d_secure' in data:
                vbv = data['3d_secure'].upper()
                info['vbv_votes'].append('YES' if 'YES' in vbv or 'ENABLED' in vbv else 'NO')

            card_brand = data.get('card_brand')
            if card_brand and card_brand.lower() not in ['unknown']:
                brands.append(card_brand.upper())

            card_type = data.get('card_type')
            if card_type and card_type.lower() not in ['unknown']:
                types.append('CREDIT' if 'credit' in card_type.lower() else 'DEBIT')

            level = data.get('card_level')
            if level and level.lower() not in ['unknown', '']:
                levels.append(level.upper())

            country = data.get('iso_country_name')
            if country and country.lower() not in ['unknown']:
                countries.append(country)
    except:
        pass

    if brands: info['brand'] = Counter(brands).most_common(1)[0][0]
    if types: info['type'] = Counter(types).most_common(1)[0][0]
    if levels: info['level'] = Counter(levels).most_common(1)[0][0]
    if issuers: info['issuer'] = Counter(issuers).most_common(1)[0][0]
    if countries: info['country'] = Counter(countries).most_common(1)[0][0]
    return info

# ===============================================
# VBV VOTES → LABEL
# ===============================================
def calculate_vbv_confidence(votes):
    if not votes:
        return 50, "Unknown"
    yes = votes.count('YES')
    total = len(votes)
    if total == 0:
        return 50, "Unknown"
    conf = int(yes / total * 100)
    if conf >= 75:
        return conf, "VBV"
    if conf <= 25:
        return 100 - conf, "NON-VBV"
    return conf, "PARTIAL"

# ===============================================
# SCORE COMPUTATION
# ===============================================
def compute_non_vbv_score(neut_supports_3ds, info, vbv_status):
    if neut_supports_3ds is True:
        base = 35
    elif neut_supports_3ds is False:
        base = 85
    else:
        base = 60

    country = info['country'].upper()
    issuer = info['issuer'].upper()
    level = info['level'].upper()
    ctype = info['type'].upper()
    brand = info['brand'].upper()

    if any(x in country for x in ['GERMANY','FRANCE','UK','NETHERLANDS','SWEDEN','ITALY','NORWAY','DENMARK','FINLAND','SPAIN']):
        base -= 12
    elif 'CANADA' in country:
        base -= 6
    elif 'UNITED STATES' in country or 'USA' in country:
        base += 6

    if any(x in issuer for x in ['CREDIT UNION','FEDERAL','NAVY','COMMUNITY']):
        base += 8
    elif any(x in issuer for x in ['CHASE','JPMORGAN','CAPITAL ONE','BANK OF AMERICA','CITI','BARCLAYS']):
        base += 5
    elif 'WELLS FARGO' in issuer:
        base -= 4

    if 'INFINITE' in level or 'BLACK' in level or 'ELITE' in level:
        base += 3
    elif 'PLATINUM' in level or 'SIGNATURE' in level:
        base += 2
    elif 'CLASSIC' in level or 'STANDARD' in level:
        base -= 2

    if ctype == 'DEBIT':
        base -= 10
    elif ctype == 'CREDIT':
        base += 3

    if 'AMEX' in brand:
        base = min(base, 35)
    elif 'DISCOVER' in brand:
        base -= 6

    if vbv_status == "NON-VBV":
        base += 10
    elif vbv_status == "VBV":
        base -= 15

    base = max(15, min(92, base))
    rounded = int(round(base / 5.0) * 5)
    return max(15, min(92, rounded))

# ===============================================
# Formatting helpers (mobile/desktop-safe, bold, fixed width)
# ===============================================
NBSP = "\u2007"
BOX_WIDTH = 25  # Match the example width (25 dashes)
HEADER_BOX_WIDTH = 20  # Title box is smaller (20 dashes)

TAG_RE = re.compile(r"<[^>]+>")

def strip_tags(s: str) -> str:
    return TAG_RE.sub("", s or "")

def visual_len(s: str) -> int:
    length = 0
    for ch in s:
        length += 1 if ch.isascii() else 2
    return length

def trim_to_width(s: str, max_width: int) -> str:
    out = []
    width = 0
    for ch in s:
        ch_w = 1 if ch.isascii() else 2
        if width + ch_w > max_width:
            break
        out.append(ch)
        width += ch_w
    return "".join(out)

def draw_top(width: int = None) -> str:
    w = width if width is not None else BOX_WIDTH
    return f"<b>┌{'─'*w}┐</b>"

def draw_sep(width: int = None) -> str:
    w = width if width is not None else BOX_WIDTH
    return f"<b>├{'─'*w}┤</b>"

def draw_bot(width: int = None) -> str:
    w = width if width is not None else BOX_WIDTH
    return f"<b>└{'─'*w}┘</b>"

def clamp_and_pad_text(text: str) -> str:
    # Center text dynamically based on visual length, wrap entire line in bold
    # Check if text already contains HTML links - preserve them
    if '<a href=' in text or '<b>' in text:
        # Text has HTML, calculate visual length of plain text part
        plain_text = strip_tags(text)
        vis_len = visual_len(plain_text)
        left_pad = (BOX_WIDTH - vis_len) // 2
        return f"<b>│{' ' * left_pad}{text}</b>"
    # Plain text, wrap in bold and center
    plain_text = html.escape(text)
    vis_len = visual_len(plain_text)
    left_pad = (BOX_WIDTH - vis_len) // 2
    return f"<b>│{' ' * left_pad}<b>{plain_text}</b></b>"

def header_block() -> str:
    # Title as bold/italic/underlined plain text (no box), centered just above the box
    title_text = "CRONUS CHECKER BOT 🔍"
    title_len = visual_len(title_text)
    total_width = BOX_WIDTH + 2  # Borders: │ and │
    left_spaces = (total_width - title_len) // 2
    centered_title = f"{' ' * left_spaces}<b><i><u>{title_text}</u></i></b>\n"  # No extra newline
   
    checked_text = 'Checked by <a href="https://t.me/cronuscheckerbot"><b><u>CronusChecker</u></b></a>'
    created_text = 'Created by <a href="https://t.me/cronusxxx"><b><u>Cronusxxx</u></b></a>'
   
    # Center both lines in the box and align them
    # Strip HTML tags to get plain text for length calculation
    checked_plain = strip_tags(checked_text)
    checked_len = visual_len(checked_plain)
    created_plain = strip_tags(created_text)
    created_len = visual_len(created_plain)
    
    # Find the maximum length and calculate padding to center it
    # Use the same padding for both lines so they align while appearing centered
    max_len = max(checked_len, created_len)
    # Calculate padding to center: (box width - text width) / 2
    # This naturally centers shorter text with more padding, longer text with less
    common_pad = (BOX_WIDTH - max_len) // 2
    # Ensure we have at least a small amount of padding for visual spacing
    if common_pad < 1:
        common_pad = (BOX_WIDTH - max_len + 1) // 2
    # Final safeguard: minimum 1 space
    common_pad = max(1, common_pad)
    
    return centered_title + "\n".join([
        draw_top(),
        f"<b>│{' ' * common_pad}{checked_text}</b>",
        f"<b>│{' ' * common_pad}{created_text}</b>",
        draw_sep()
    ])

def escape_angle_brackets(s: str) -> str:
    # Don't escape angle brackets - let them show naturally in commands
    # Only escape if it's not part of command syntax like <num> or <key>
    return s

def format_command_line(line: str) -> str:
    """
    Format a command line with — separator.
    Expects format: "icon command — description"
    """
    # Return as-is, we'll handle formatting in clamp_and_pad_command
    return line

def clamp_and_pad_command(text: str) -> str:
    """
    Format command lines - EXACT match to provided format.
    """
    # Helper to escape angle brackets EXCEPT in valid HTML tags
    def escape_angle_brackets_safe(s: str) -> str:
        import re
        # Protect HTML tags by temporarily replacing them
        html_pattern = r'<a\s+href="[^"]*">.*?</a>|<b>.*?</b>'
        placeholders = []
        counter = 0
        
        def replace_html(match):
            nonlocal counter
            placeholder = f"__HTML_PLACEHOLDER_{counter}__"
            placeholders.append(match.group(0))
            counter += 1
            return placeholder
        
        # Replace HTML tags with placeholders
        protected = re.sub(html_pattern, replace_html, s, flags=re.DOTALL)
        
        # Escape angle brackets in the protected string
        escaped = protected.replace('<', '&lt;').replace('>', '&gt;')
        
        # Restore HTML tags
        for i, placeholder in enumerate([f"__HTML_PLACEHOLDER_{j}__" for j in range(counter)]):
            if placeholder in escaped:
                escaped = escaped.replace(placeholder, placeholders[i])
        
        return escaped
    
    # Check if it has " — " separator
    if " — " in text:
        parts = text.split(" — ", 1)
        command_part = parts[0].strip()
        description = parts[1].strip()
        
        # Escape angle brackets but preserve HTML links
        command_escaped = escape_angle_brackets_safe(command_part)
        description_escaped = html.escape(description)
        
        # EXACT spacing: two spaces around — separator, wrap entire line in bold
        # No space before │ to align borders properly
        formatted = f"{command_escaped}  —  {description_escaped}"
        return f"<b>│ <b>{formatted}</b></b>"
    
    # Fallback, wrap entire line in bold, no space before │
    escaped_text = escape_angle_brackets_safe(text)
    return f"<b>│ <b>{escaped_text}</b></b>"

def box_rows_after_header(rows: list[str]) -> str:
    lines = []
    for i, row in enumerate(rows):
        # Add separator before each row except first
        if i > 0:
            lines.append(draw_sep())
        
        # Check if it's a command line format
        if " — " in row:
            formatted = clamp_and_pad_command(row)
            # Check if it's multi-line (wrapped description)
            formatted_lines = formatted.split('\n')
            for line in formatted_lines:
                lines.append(line)  # Already wrapped in bold by clamp_and_pad_command
        else:
            formatted_row = clamp_and_pad_text(row)
            lines.append(formatted_row)  # Already wrapped in bold by clamp_and_pad_text
    
    # Append bottom border instead of overwriting last content
    if not lines:
        lines = [draw_bot()]
    else:
        lines.append(draw_bot())
    return "\n".join(lines)

def box_list_full(rows: list[str]) -> str:
    parts = [draw_top()]
    for i, row in enumerate(rows):
        # Add separator before each row except first
        if i > 0:
            parts.append(draw_sep())
        
        # Handle empty rows (for spacing)
        if not row.strip():
            parts.append(clamp_and_pad_text(""))
        # Check if it's "Admin" header or "Key Status" or "All Keys" - center it
        elif ("Admin" in row or "Key Status" in row or "/allkeys" in row or 
            row.strip().startswith("📋") or row.strip().startswith("📈")):
            # Center the admin header with dynamic padding, wrap in bold
            admin_text = row.strip().replace("🛠️", "🛠")  # Remove extra characters
            if admin_text == "🛠 Admin":
                admin_vis_len = visual_len(admin_text)
                left_pad = (BOX_WIDTH - admin_vis_len) // 2
            else:
                admin_vis_len = visual_len(admin_text)
                left_pad = (BOX_WIDTH - admin_vis_len) // 2 + 3  # +3 for emoji offset for other titles
            parts.append(f"<b>│{' ' * left_pad}{html.escape(admin_text)}</b>")
        elif " — " in row:
            formatted = clamp_and_pad_command(row)
            # Handle multi-line wrapped commands
            formatted_lines = formatted.split('\n')
            for line in formatted_lines:
                parts.append(line)  # Already wrapped in bold by clamp_and_pad_command
        else:
            # For non-title rows, use centered clamp_and_pad_text (already wraps in bold)
            parts.append(clamp_and_pad_text(row))
    
    # Append bottom border instead of overwriting last content
    parts.append(draw_bot())
    return "\n".join(parts)

# For BIN details table lines - using ➠ separator
def make_line(label_text: str, value_html: str, col_start: int) -> str:
    # Simple format: ┣ label ➠ value, left border only, no truncation
    return f"┣ <b>{html.escape(label_text)}</b> ➠ {value_html}"

# ===============================================
# COMMANDS (HTML)
# ===============================================
async def start_command(update: Update, context):
    text = header_block() + "\n" + box_rows_after_header(["🏁 /start — Show header"])
    await update.effective_message.reply_text(
        text, parse_mode='HTML', disable_web_page_preview=True,
        reply_to_message_id=update.effective_message.message_id
    )

async def help_command(update: Update, context):
    user_id = update.effective_user.id
    header = header_block()

    user_rows = [
        "🏁 /start — Show header",
        "📖 /help — Show all commands",
        "💳 /bin — Check BIN/IIN",
        "📈 /stats — Check key time left",
        "🔑 /key — Activate a key",
        "🛒 /buy — Purchase a key",
    ]
    user_section = box_rows_after_header(user_rows)
    user_section = "\n" + user_section

    admin_section = ""
    if user_id == ADMIN_ID:
        admin_rows = [
            "🛠 Admin",
            "🧩 /generate — Create keys",
            "⛔ /revoke <key> — Revoke a key",
            "📋 /allkeys — Show all keys",
        ]
        admin_section = "\n" + box_list_full(admin_rows)

    await update.effective_message.reply_text(
        header + user_section + admin_section,
        parse_mode='HTML', disable_web_page_preview=True,
        reply_to_message_id=update.effective_message.message_id
    )

async def buy_command(update: Update, context):
    rows = ['🛒 Message for price: <a href="https://t.me/cronusxxx">here</a>']
    text = header_block() + "\n" + box_rows_after_header(rows)
    await update.effective_message.reply_text(
        text, parse_mode='HTML', disable_web_page_preview=True,
        reply_to_message_id=update.effective_message.message_id
    )

async def key_command(update: Update, context):
    if not context.args:
        rows = ["🔑 /key CRONUSKEY-XXXXX"]
        text = header_block() + "\n" + box_rows_after_header(rows)
        await update.effective_message.reply_text(
            text, parse_mode='HTML', disable_web_page_preview=True,
            reply_to_message_id=update.effective_message.message_id
        )
        return
    key = context.args[0].strip()
    success, msg = activate_key(key, update.effective_user.id)
    rows = [f"🔑 ACTIVATED!  /stats"]
    text = header_block() + "\n" + box_rows_after_header(rows)
    await update.effective_message.reply_text(
        text, parse_mode='HTML', disable_web_page_preview=True,
        reply_to_message_id=update.effective_message.message_id
    )

async def allkeys_command(update: Update, context):
    if update.effective_user.id != ADMIN_ID:
        return
    # Don't delete expired keys here - show them in the list
    # c.execute("DELETE FROM keys WHERE expires_at < ?", (datetime.now().isoformat(),))
    c.execute("SELECT key, user_id, expires_at, duration_minutes FROM keys")
    rows_db = c.fetchall()

    header = header_block()
    rows_out = []
    now = datetime.now()
    
    if not rows_db:
        rows_out.append("📋 All Keys")
        rows_out.append("None")
    else:
        rows_out.append("📋 All Keys")
        for row in rows_db:
            key, user_id, expires_at, duration_minutes = row
            if user_id is None:
                # Calculate duration display like in /generate
                if duration_minutes < 60:
                    dur = f"{duration_minutes}m"
                elif duration_minutes < 1440:
                    dur = f"{duration_minutes // 60}h"
                else:
                    dur = f"{duration_minutes // 1440}d"
                status = f"Not activated ({dur})"
            else:
                exp = datetime.fromisoformat(expires_at)
                if exp > now:
                    tl = exp - now
                    days = tl.days
                    hours, rem = divmod(tl.seconds, 3600)
                    minutes, _ = divmod(rem, 60)
                    status = f"{days}d {hours}h {minutes}m left (user: {user_id})"
                else:
                    status = f"Expired (user: {user_id})"
            rows_out.append(f"{html.escape(key)} — {status}")

    await update.effective_message.reply_text(
        header + "\n" + box_list_full(rows_out),
        parse_mode='HTML', disable_web_page_preview=True,
        reply_to_message_id=update.effective_message.message_id
    )

async def stats_command(update: Update, context):
    c.execute("DELETE FROM keys WHERE expires_at < ?", (datetime.now().isoformat(),))
    conn.commit()
    c.execute("SELECT key, expires_at FROM keys WHERE user_id=?", (update.effective_user.id,))
    r = c.fetchone()
    if not r:
        rows = ["📈 Key Status", "NO ACTIVE KEY!"]
        text = header_block() + "\n" + box_list_full(rows)
        await update.effective_message.reply_text(
            text, parse_mode='HTML', disable_web_page_preview=True,
            reply_to_message_id=update.effective_message.message_id
        )
        return
    key, expires_at = r
    now = datetime.now()
    exp = datetime.fromisoformat(expires_at)
    if exp > now:
        tl = exp - now
        days = tl.days
        hours, rem = divmod(tl.seconds, 3600)
        minutes, _ = divmod(rem, 60)
        time_left = f"{days}d {hours}h {minutes}m"
    else:
        time_left = "Expired"
    rows = [
        "📈 Key Status",
        f"Active Key: {html.escape(key)}",
        f"Time Left: {time_left}"
    ]
    text = header_block() + "\n" + box_list_full(rows)
    await update.effective_message.reply_text(
        text, parse_mode='HTML', disable_web_page_preview=True,
        reply_to_message_id=update.effective_message.message_id
    )

async def revoke_command(update: Update, context):
    if update.effective_user.id != ADMIN_ID:
        return
    if not context.args:
        text = header_block() + "\n" + box_rows_after_header(["⛔ " + escape_angle_brackets("/revoke <key> — Revoke a key")])
        await update.effective_message.reply_text(
            text, parse_mode='HTML', disable_web_page_preview=True,
            reply_to_message_id=update.effective_message.message_id
        )
        return
    key = context.args[0]
    c.execute("DELETE FROM keys WHERE key=?", (key,))
    desc = "Revoked." if c.rowcount else "Key not found."
    if c.rowcount:
        conn.commit()
    text = header_block() + "\n" + box_rows_after_header([f"⛔ {desc}"])
    await update.effective_message.reply_text(
        text, parse_mode='HTML', disable_web_page_preview=True,
        reply_to_message_id=update.effective_message.message_id
    )

async def generate_command(update: Update, context):
    if update.effective_user.id != ADMIN_ID:
        return
    if not context.args:
        text = header_block() + "\n" + box_rows_after_header([
            "🧩 " + escape_angle_brackets("/generate <num> [duration]"),
            "Example: /generate 5 2d"
        ])
        await update.effective_message.reply_text(
            text, parse_mode='HTML', disable_web_page_preview=True,
            reply_to_message_id=update.effective_message.message_id
        )
        return
    try:
        num = int(context.args[0]); assert 1 <= num <= 50
    except:
        text = header_block() + "\n" + box_rows_after_header(["🧩 Error — Num: 1-50"])
        await update.effective_message.reply_text(
            text, parse_mode='HTML', disable_web_page_preview=True,
            reply_to_message_id=update.effective_message.message_id
        )
        return
    dur_str = context.args[1] if len(context.args) > 1 else "2d"
    try:
        if dur_str.endswith('d'):
            mins = int(dur_str[:-1]) * 1440
        elif dur_str.endswith('m'):
            mins = int(dur_str[:-1])
        else:
            mins = int(dur_str)
        assert 1 <= mins <= 43200
    except:
        text = header_block() + "\n" + box_rows_after_header(["🧩 Error — Duration: 1m-30d"])
        await update.effective_message.reply_text(
            text, parse_mode='HTML', disable_web_page_preview=True,
            reply_to_message_id=update.effective_message.message_id
        )
        return
    keys = []
    for _ in range(num):
        k = generate_custom_key()
        c.execute("INSERT INTO keys (key, duration_minutes) VALUES (?, ?)", (k, mins))
        keys.append(k)
    conn.commit()

    # Format duration display
    if mins < 60:
        dur_display = f"{mins}m"
    elif mins < 1440:
        dur_display = f"{mins // 60}h"
    else:
        dur_display = f"{mins // 1440}d"
    
    rows = [f"🧩 Generated {num} keys ({dur_display})"]
    for k in keys:
        rows.append(html.escape(k))
    
    await update.effective_message.reply_text(
        header_block() + "\n" + box_rows_after_header(rows),
        parse_mode='HTML', disable_web_page_preview=True,
        reply_to_message_id=update.effective_message.message_id
    )

# ===============================================
# BIN COMMAND (detailed view; separators match bold width)
# ===============================================
async def bin_command(update: Update, context):
    if not is_key_valid(update.effective_user.id):
        text = header_block() + "\n" + box_rows_after_header(["🔒 " + escape_angle_brackets("No active key. Use /key <your_key>")])
        await update.effective_message.reply_text(
            text, parse_mode='HTML', disable_web_page_preview=True,
            reply_to_message_id=update.effective_message.message_id
        )
        return

    if not context.args:
        text = header_block() + "\n" + box_rows_after_header(["💳 /bin — Check BIN/IIN"])
        await update.effective_message.reply_text(
            text, parse_mode='HTML', disable_web_page_preview=True,
            reply_to_message_id=update.effective_message.message_id
        )
        return

    bin_num = context.args[0].strip()
    if not re.fullmatch(r'\d{6,8}', bin_num):
        text = header_block() + "\n" + box_rows_after_header(["💳 Error — Invalid BIN! Use 6–8 digits."])
        await update.effective_message.reply_text(
            text, parse_mode='HTML', disable_web_page_preview=True,
            reply_to_message_id=update.effective_message.message_id
        )
        return

    await context.bot.send_chat_action(chat_id=update.effective_chat.id, action=ChatAction.TYPING)

    neut = neutrino_lookup(bin_num)
    info = get_bin_info(bin_num)

    if neut:
        if neut.get("brand"): info['brand'] = neut["brand"]
        if neut.get("type"): info['type'] = neut["type"]
        if neut.get("level"): info['level'] = neut["level"]
        if neut.get("issuer"): info['issuer'] = neut["issuer"]
        if neut.get("country"): info['country'] = neut["country"]

    vbv_conf, vbv_status = calculate_vbv_confidence(info['vbv_votes'])
    neut_supports_3ds = neut.get("supports_3ds") if neut else None
    if neut_supports_3ds is not None:
        vbv_status = "VBV" if bool(neut_supports_3ds) else "NON-VBV"

    non_vbv = compute_non_vbv_score(neut_supports_3ds, info, vbv_status)
    hit_rate = non_vbv

    if vbv_status == "NON-VBV":
        status_phrase = "authenticate_attempt_successful" if not neut_supports_3ds else "challenge_required"
    elif vbv_status == "VBV":
        status_phrase = "challenge_required"
    else:
        status_phrase = "authenticate_attempt_successful" if non_vbv >= 70 else "challenge_required"

    status_good = (status_phrase == "authenticate_attempt_successful")

    MAX_ISSUER_LEN = 30
    issuer_clean = info['issuer']
    if len(issuer_clean) > MAX_ISSUER_LEN:
        issuer_clean = issuer_clean[:MAX_ISSUER_LEN] + "..."

    country_clean = info['country'] \
        .replace('United States of America (the)', 'United States') \
        .replace('United Kingdom of Great Britain and Northern Ireland (the)', 'United Kingdom') \
        .upper()

    bin_num_html   = f"<b>{html.escape(bin_num)}</b>"
    brand_html     = f"<b>{html.escape(info['brand'])}</b>"
    card_type_html = f"<b>{html.escape(info['type'])}</b>"
    level_html     = f"<b>{html.escape(info['level'])}</b>"
    issuer_html    = f"<b>{html.escape(issuer_clean)}</b>"
    country_html   = f"<b>{html.escape(country_clean)}</b>"

    non_vbv_display = f"[<b>{non_vbv}% {'✅' if status_good else '❌'}</b>]"
    hit_rate_display = f"[<b>{hit_rate}% {'✅' if status_good else '❌'}</b>]"
    status_display   = f"[<b>{html.escape(status_phrase)}</b>]"

    # Format: "Bin Information" header
    header_lines = [
        draw_top(),
        f"│ <b>Bin Information</b>",
        draw_sep()
    ]
    
    top_block = [
        make_line("BIN", bin_num_html, 0),
        make_line("Card Brand", brand_html, 0),
        make_line("Card Type", card_type_html, 0),
        make_line("Card Level", level_html, 0),
        make_line("Bank Issuer", issuer_html, 0),
        make_line("Country", country_html, 0),
    ]

    sep_mid = draw_sep()
    bottom_block = [
        make_line("NON-VBV", non_vbv_display, 0),
        make_line("HITRATE", hit_rate_display, 0),
        make_line("STATUS", status_display, 0),
    ]

    output_html = (
        "\n".join(header_lines) + "\n"
        + "\n".join(top_block) + "\n"
        + sep_mid + "\n"
        + "\n".join(bottom_block) + "\n"
        + draw_bot()
    )

    await update.effective_message.reply_text(
        output_html, parse_mode='HTML', disable_web_page_preview=True,
        reply_to_message_id=update.effective_message.message_id
    )

# ===============================================
# Error handler
# ===============================================
async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    try:
        await context.bot.send_message(
            chat_id=update.effective_chat.id if hasattr(update, "effective_chat") and update.effective_chat else ADMIN_ID,
            text="An unexpected error occurred. Please try again.",
            disable_web_page_preview=True
        )
    except Exception:
        pass
    print("ERROR:", context.error)

# ===============================================
# RUN BOT
# ===============================================
app = Application.builder().token(BOT_TOKEN).build()
app.add_handler(CommandHandler("start", start_command))
app.add_handler(CommandHandler("help", help_command))
app.add_handler(CommandHandler("buy", buy_command))
app.add_handler(CommandHandler("key", key_command))
app.add_handler(CommandHandler("bin", bin_command))
app.add_handler(CommandHandler("allkeys", allkeys_command))
app.add_handler(CommandHandler("stats", stats_command))
app.add_handler(CommandHandler("revoke", revoke_command))
app.add_handler(CommandHandler("generate", generate_command))
app.add_error_handler(error_handler)

print("CRONUS BIN CHECKER BOT IS LIVE!")
try:
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)
except Exception as e:
    print(f"ERROR starting bot: {e}")
    print("\nTroubleshooting tips:")
    print("1. Check your internet connection")
    print("2. Verify Telegram API is accessible (not blocked by firewall)")
    print("3. Check if you're behind a proxy (configure if needed)")
    print("4. Try running: ping api.telegram.org")
    print("5. Check Windows Firewall settings")
    input("\nPress Enter to exit...")
