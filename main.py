import os
import phonenumbers
import whois
from ipwhois import IPWhois
from validate_email import validate_email
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Updater, CommandHandler, CallbackQueryHandler, MessageHandler, Filters, CallbackContext

BOT_TOKEN = "8470880626:AAGPTa4ZglWDLgWx9C4PRGOTpkfEqos76Lo"
CHANNEL_USERNAME = "@SL_TooL_HuB"

user_state = {}

def start(update: Update, context: CallbackContext):
    user = update.effective_user
    chat_id = update.effective_chat.id
    member = context.bot.get_chat_member(CHANNEL_USERNAME, chat_id)
    
    if member.status not in ['member', 'creator', 'administrator']:
        update.message.reply_text(
            f"🚫 Please join our channel first:\n👉 {CHANNEL_USERNAME}"
        )
        return

    keyboard = [
        [InlineKeyboardButton("📱 Phone Info", callback_data='phone')],
        [InlineKeyboardButton("🌐 IP Info", callback_data='ip')],
        [InlineKeyboardButton("📧 Email Validator", callback_data='email')],
        [InlineKeyboardButton("🕵️ Username Check", callback_data='username')],
        [InlineKeyboardButton("🌍 Domain Whois", callback_data='domain')],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    update.message.reply_text(
        "🎯 *OSINT Sniper Menu*\n\nChoose an option:",
        reply_markup=reply_markup,
        parse_mode='Markdown'
    )

def button(update: Update, context: CallbackContext):
    query = update.callback_query
    query.answer()
    user_id = query.from_user.id

    user_state[user_id] = query.data
    query.edit_message_text(f"✅ Now send me the {query.data} you want to scan...")

def process(update: Update, context: CallbackContext):
    user_id = update.effective_user.id
    text = update.message.text

    if user_id not in user_state:
        update.message.reply_text("ℹ️ Use /start to begin.")
        return

    action = user_state[user_id]

    try:
        if action == 'phone':
            number = phonenumbers.parse(text)
            response = f"📱 Country: {phonenumbers.region_code_for_number(number)}\n📍 Valid: {phonenumbers.is_valid_number(number)}"

        elif action == 'ip':
            obj = IPWhois(text)
            result = obj.lookup_rdap()
            response = f"🌐 Network: {result['network']['name']}\n📍 Country: {result['network']['country']}"

        elif action == 'email':
            is_valid = validate_email(email_address=text, check_format=True)
            response = f"📧 Email format valid: {is_valid}"

        elif action == 'domain':
            domain_info = whois.whois(text)
            response = f"🌍 Registrar: {domain_info.registrar}\n📅 Created: {domain_info.creation_date}"

        elif action == 'username':
            response = f"🔍 Username search not implemented yet.\nUse @usersearch_bot for better results."

        else:
            response = "❌ Invalid action."

        update.message.reply_text(response)

    except Exception as e:
        update.message.reply_text(f"⚠️ Error: {str(e)}")

    del user_state[user_id]
    start(update, context)

def main():
    updater = Updater(BOT_TOKEN, use_context=True)
    dp = updater.dispatcher

    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(CallbackQueryHandler(button))
    dp.add_handler(MessageHandler(Filters.text & ~Filters.command, process))

    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    main()
