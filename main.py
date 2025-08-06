import os
import socket
import re
import base64
import hashlib
import phonenumbers
from phonenumbers import geocoder, carrier
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Updater, CommandHandler, CallbackQueryHandler, MessageHandler, Filters, CallbackContext
from dotenv import load_dotenv

load_dotenv()

BOT_TOKEN = "8470880626:AAGPTa4ZglWDLgWx9C4PRGOTpkfEqos76Lo"
CHANNEL_USERNAME = "SL_TooL_HuB"  # চ্যানেল ইউজারনেম (বিনা @)

# Helper: Channel subscription check
def user_is_subscribed(bot, user_id):
    try:
        member = bot.get_chat_member(chat_id=f"@{CHANNEL_USERNAME}", user_id=user_id)
        return member.status in ["member", "administrator", "creator"]
    except:
        return False

# Start & Menu
def start(update: Update, context: CallbackContext):
    user = update.effective_user
    if not user_is_subscribed(context.bot, user.id):
        update.message.reply_text(f"🔐 Please join our channel first:\n👉 https://t.me/{CHANNEL_USERNAME}")
        return

    keyboard = [
        [InlineKeyboardButton("🌐 IP Info & Geo", callback_data="ip_info")],
        [InlineKeyboardButton("🛠️ Port Scanner", callback_data="port_scan")],
        [InlineKeyboardButton("📧 Email Validator", callback_data="email_validate")],
        [InlineKeyboardButton("🔐 Password Strength", callback_data="password_strength")],
        [InlineKeyboardButton("🧑 Username Checker", callback_data="username_check")],
        [InlineKeyboardButton("🔒 Encrypt/Decrypt Text", callback_data="text_encrypt")],
        [InlineKeyboardButton("🧮 Hash Generator", callback_data="hash_generator")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    welcome_text = (
        f"👋 Hi {user.first_name or 'Agent'}!\n\n"
        f"🎯 *Recon & Scan Toolkit*\n"
        f"Choose a module from below to start scanning:\n\n"
        f"_This bot is channel locked. Please join @{CHANNEL_USERNAME}_"
    )
    update.message.reply_text(welcome_text, reply_markup=reply_markup, parse_mode="Markdown")

# Show menu helper
def show_menu(update: Update, context: CallbackContext):
    keyboard = [
        [InlineKeyboardButton("🌐 IP Info & Geo", callback_data="ip_info")],
        [InlineKeyboardButton("🛠️ Port Scanner", callback_data="port_scan")],
        [InlineKeyboardButton("📧 Email Validator", callback_data="email_validate")],
        [InlineKeyboardButton("🔐 Password Strength", callback_data="password_strength")],
        [InlineKeyboardButton("🧑 Username Checker", callback_data="username_check")],
        [InlineKeyboardButton("🔒 Encrypt/Decrypt Text", callback_data="text_encrypt")],
        [InlineKeyboardButton("🧮 Hash Generator", callback_data="hash_generator")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    if update.callback_query:
        update.callback_query.message.reply_text("🔄 Select another module:", reply_markup=reply_markup)
    else:
        update.message.reply_text("🔄 Select another module:", reply_markup=reply_markup)

# Callback query handler for buttons
def button_handler(update: Update, context: CallbackContext):
    query = update.callback_query
    user = update.effective_user
    if not user_is_subscribed(context.bot, user.id):
        query.answer()
        query.edit_message_text(f"🔐 Please join our channel first:\n👉 https://t.me/{CHANNEL_USERNAME}")
        return

    query.answer()
    module = query.data
    context.user_data["module"] = module

    prompts = {
        "ip_info": "🌐 Send an IP address (e.g. 8.8.8.8):",
        "port_scan": "🛠️ Send an IP address to scan common ports (e.g. 8.8.8.8):",
        "email_validate": "📧 Send an email address to validate:",
        "password_strength": "🔐 Send a password to check its strength:",
        "username_check": "🧑 Send a username to check on GitHub, Twitter, Instagram:",
        "text_encrypt": "🔒 Send text to encrypt/decrypt. Format:\n`enc your_text` or `dec your_text`",
        "hash_generator": "🧮 Send text to generate hashes (MD5, SHA1, SHA256):"
    }

    query.edit_message_text(prompts.get(module, "Send input:"))

# Message handler for inputs
def message_handler(update: Update, context: CallbackContext):
    user = update.effective_user
    if not user_is_subscribed(context.bot, user.id):
        update.message.reply_text(f"🔐 Please join our channel first:\n👉 https://t.me/{CHANNEL_USERNAME}")
        return

    module = context.user_data.get("module")
    text = update.message.text.strip()

    if not module:
        update.message.reply_text("❌ Please select a module first by using /start")
        return

    if module == "ip_info":
        result = ip_info(text)
    elif module == "port_scan":
        result = port_scanner(text)
    elif module == "email_validate":
        result = email_validator(text)
    elif module == "password_strength":
        result = password_strength_checker(text)
    elif module == "username_check":
        result = username_checker(text)
    elif module == "text_encrypt":
        result = text_encrypt_decrypt(text)
    elif module == "hash_generator":
        result = hash_generator(text)
    else:
        result = "❌ Unknown module."

    update.message.reply_text(result, parse_mode="Markdown")
    context.user_data.clear()
    show_menu(update, context)

# --- MODULE IMPLEMENTATIONS --- #

def ip_info(ip):
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        ip_version = "IPv4" if ip_obj.version == 4 else "IPv6"
        # Basic country detection with dummy data, replace with local DB if want
        # Here we use a simple check (for demo only)
        country = "Unknown"
        if ip.startswith("8.8.8.8"):
            country = "United States"
        elif ip.startswith("1.1.1.1"):
            country = "Australia"
        return (
            f"🌐 IP Info:\n"
            f"• IP: `{ip}`\n"
            f"• Version: {ip_version}\n"
            f"• Country: {country}\n"
            f"_(Note: For full geo info add local IP DB)_"
        )
    except ValueError:
        return "❌ Invalid IP address."

def port_scanner(ip):
    common_ports = [21,22,23,25,53,80,110,143,443,445,3389,8080]
    open_ports = []
    try:
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        if open_ports:
            ports_str = ", ".join(str(p) for p in open_ports)
            return f"🛠️ Open ports on `{ip}`:\n{ports_str}"
        else:
            return f"ℹ️ No common open ports found on `{ip}`."
    except Exception as e:
        return f"❌ Error scanning ports: {str(e)}"

def email_validator(email):
    pattern = r'^[\\w\\.-]+@[\\w\\.-]+\\.\\w+$'
    if re.match(pattern, email):
        return f"📧 Email `{email}` is *valid* format."
    else:
        return f"❌ Email `{email}` is *invalid* format."

def password_strength_checker(password):
    length = len(password)
    conditions = {
        "length": length >= 8,
        "upper": bool(re.search(r"[A-Z]", password)),
        "lower": bool(re.search(r"[a-z]", password)),
        "digit": bool(re.search(r"\\d", password)),
        "special": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    }
    score = sum(conditions.values())
    strength = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"][score-1 if score>0 else 0]
    details = "\n".join([f"• {k.capitalize()}: {'✅' if v else '❌'}" for k,v in conditions.items()])
    return f"🔐 Password Strength: *{strength}*\n{details}"

def username_checker(username):
    platforms = {
        "GitHub": f"https://github.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "Instagram": f"https://instagram.com/{username}"
    }
    results = []
    import requests
    for name, url in platforms.items():
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                results.append(f"✅ {name}: Found")
            elif r.status_code == 404:
                results.append(f"❌ {name}: Not Found")
            else:
                results.append(f"⚠️ {name}: Unknown status {r.status_code}")
        except Exception:
            results.append(f"⚠️ {name}: Request Failed")
    return "\n".join(results)

def text_encrypt_decrypt(text):
    # Expected input: enc your_text OR dec your_text
    if text.lower().startswith("enc "):
        plain = text[4:]
        encoded = base64.b64encode(plain.encode()).decode()
        return f"🔒 Encoded Text:\n`{encoded}`"
    elif text.lower().startswith("dec "):
        encoded = text[4:]
        try:
            decoded = base64.b64decode(encoded).decode()
            return f"🔓 Decoded Text:\n`{decoded}`"
        except Exception:
            return "❌ Invalid Base64 encoded text."
    else:
        return "⚠️ Use format:\n`enc your_text`\nor\n`dec your_text`"

def hash_generator(text):
    md5 = hashlib.md5(text.encode()).hexdigest()
    sha1 = hashlib.sha1(text.encode()).hexdigest()
    sha256 = hashlib.sha256(text.encode()).hexdigest()
    return (
        f"🧮 Hashes for:\n`{text}`\n\n"
        f"MD5: `{md5}`\n"
        f"SHA1: `{sha1}`\n"
        f"SHA256: `{sha256}`"
    )

def main():
    updater = Updater(BOT_TOKEN, use_context=True)
    dp = updater.dispatcher

    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CallbackQueryHandler(button_handler))
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, message_handler))

    print("Bot is running...")
    updater.start_polling()
    updater.idle()

if __name__ == "__main__":
    main()
