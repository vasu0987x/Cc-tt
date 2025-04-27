import socket
import ipaddress
import re
import concurrent.futures
import requests
import time
import os
import asyncio
import logging
import traceback
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, MessageHandler, ContextTypes, filters
from telegram.error import NetworkError, BadRequest, Conflict, TimedOut
from aiohttp import web

# Set up logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Hardcoded bot token
BOT_TOKEN = "8049406807:AAGhuUh9fOm5wt7OvTobuRngqY0ZNBMxlHE"
# Placeholder group ID
GROUP_ID = "-1002522049841"  # Replace with actual group ID
# Admin chat ID for notifications
ADMIN_CHAT_ID = "6972264549"  # Replace with your Telegram chat ID

# Global data storage
scan_results = {}
scan_locks = {}
message_ids = {}
scan_stop = {}
last_message_state = {}
awaiting_input = {}
recent_scans = []
start_time = time.time()
scan_expiry = {}
scan_queue = asyncio.Queue(maxsize=20)  # Max 20 queued scans
scan_semaphore = asyncio.Semaphore(5)  # Max 5 concurrent scans
lock_timeouts = {}  # Track lock start time for timeout
cidr_results = {}  # Store CIDR scan results

# Common CCTV ports
CCTV_PORTS = [80, 554, 8000, 8080, 8443]
UDP_PORTS = [37020]

# Port to service mapping
SERVICE_MAP = {
    80: "http", 554: "rtsp", 8000: "http-alt",  view individual IP results
async def display_cidr_results(chat_id, context, cidr, scan_type):
    if chat_id not in cidr_results or cidr not in cidr_results[chat_id]:
        await context.bot.send_message(
            chat_id=chat_id,
            text="⚠️ No CIDR scan results found. Please start a new scan.",
            parse_mode="Markdown"
        )
        return

    results = cidr_results[chat_id][cidr]
    keyboard = [
        [InlineKeyboardButton(f"IP: {ip} ({len(data['open'])} open)", callback_data=f"cidr_ip_{chat_id}_{ip}")]
        for ip, data in sorted(results.items())
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await context.bot.send_message(
        chat_id=chat_id,
        text=f"**{scan_type.upper()} Scan Results for {cidr}**\nSelect an IP to view details:",
        parse_mode="Markdown",
        reply_markup=reply_markup
    )

# Button click handler
async def button_click(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat_id

    logger.info(f"Button clicked: chat_id={chat_id}, data={query.data}")

    try:
        if query.data.startswith("ip_scan_"):
            awaiting_input[chat_id] = "ip_scan"
            await query.message.reply_text(
                "🌐 Enter an IP or CIDR range for full 65,535 port scan (e.g., `192.168.1.1` or `192.168.1.0/24`):",
                parse_mode="Markdown"
            )
        elif query.data.startswith("cctv_hack_"):
            awaiting_input[chat_id] = "cctv_hack"
            await query.message.reply_text(
                "🎥 Enter an IP or CIDR range for CCTV hacking (e.g., `192.168.1.1` or `192.168.1.0/24`):",
                parse_mode="Markdown"
            )
        elif query.data.startswith("cidr_ip_"):
            _, _, button_chat_id, ip = query.data.split("_", 3)
            if button_chat_id != str(chat_id):
                await query.message.reply_text("⚠️ Chat ID mismatch. Please start a new scan.")
                return

            # Find the CIDR that contains this IP
            cidr = None
            for c in cidr_results.get(chat_id, {}):
                if ip in cidr_results[chat_id][c]:
                    cidr = c
                    break

            if not cidr or ip not in cidr_results[chat_id][cidr]:
                await query.message.reply_text("⚠️ Scan data not found. Please start a new scan.")
                return

            data = cidr_results[chat_id][cidr][ip]
            open_ports = data.get("open", [])
            if not open_ports:
                await query.message.reply_text(
                    f"**CCTV Scan: {ip}**\n🟢 No open ports found.",
                    parse_mode="Markdown"
                )
            else:
                ports_text = []
                for port, protocol in sorted(open_ports):
                    port_info = f"✅ Port {port} ({protocol.upper()}): {SERVICE_MAP.get(port, 'unknown')} (open)"
                    if (port, protocol) in data["details"]:
                        details = data["details"][(port, protocol)]
                        if "model" in details:
                            port_info += f"\n  - Model: {details['model']}"
                        if "creds" in details:
                            port_info += f"\n  - HTTP Credentials: {', '.join(details['creds'])}"
                        if "rtsp" in details:
                            port_info += f"\n  - RTSP Brute: {', '.join(details['rtsp'])}"
                        if "onvif" in details:
                            port_info += f"\n  - ONVIF: {details['onvif']}"
                    if port in VULN_ALERTS:
                        port_info += f"\n  - ⚠️ {VULN_ALERTS[port]}"
                    ports_text.append(port_info)
                mac = data.get("mac", "N/A")
                await query.message.reply_text(
                    f"**CCTV Scan: {ip}**\n" + "\n".join(ports_text) + f"\n\n**MAC Address**: {mac}",
                    parse_mode="Markdown"
                )
        elif query.data.startswith(("open_", "closed_")):
            action, button_chat_id = query.data.split("_", 1)
            logger.info(f"Action: {action}, Button chat_id: {button_chat_id}")

            if button_chat_id != str(chat_id):
                await query.message.reply_text("⚠️ Chat ID mismatch. Please start a new scan.")
                return

            if chat_id not in scan_results or time.time() > scan_expiry.get(chat_id, 0):
                await query.message.reply_text("⚠️ Scan data expired or not found. Please start a new scan.")
                return

            if action == "open":
                open_ports = scan_results[chat_id].get("open", [])
                if not open_ports:
                    await query.message.reply_text("🟢 No Open Ports Found!")
                else:
                    ports_text = []
                    for port, protocol in sorted(open_ports):
                        port_info = f"✅ Port {port} ({protocol.upper()}): {SERVICE_MAP.get(port, 'unknown')} (open)"
                        if (port, protocol) in scan_results[chat_id]["details"]:
                            details = scan_results[chat_id]["details"][(port, protocol)]
                            if "model" in details:
                                port_info += f"\n  - Model: {details['model']}"
                            if "creds" in details:
                                port_info += f"\n  - HTTP Credentials: {', '.join(details['creds'])}"
                            if "rtsp" in details:
                                port_info += f"\n  - RTSP Brute: {', '.join(details['rtsp'])}"
                            if "onvif" in details:
                                port_info += f"\n  - ONVIF: {details['onvif']}"
                        if port in VULN_ALERTS:
                            port_info += f"\n  - ⚠️ {VULN_ALERTS[port]}"
                        ports_text.append(port_info)
                    mac = scan_results[chat_id].get("mac", "N/A")
                    await query.message.reply_text(
                        f"**🟢 Open Ports:**\n" + "\n".join(ports_text) + f"\n\n**MAC Address**: {mac}",
                        parse_mode="Markdown"
                    )

            elif action == "closed":
                closed_count = scan_results[chat_id].get("closed_count", 0)
                if closed_count == 0:
                    await query.message.reply_text("🔴 No Closed Ports Found!")
                else:
                    await query.message.reply_text(
                        f"**🔴 Closed Ports:** {closed_count}\n(Too many to list individually)", parse_mode="Markdown"
                    )

    except Exception as e:
        logger.error(f"Error in button_click: {e}")
        await query.message.reply_text(f"⚠️ Error processing button: {str(e)}")
        try:
            await context.bot.send_message(
                chat_id=ADMIN_CHAT_ID,
                text=f"⚠️ Bot error: {str(e)}"
            )
        except Exception as admin_e:
            logger.error(f"Failed to notify admin: {admin_e}")

# Handle user input
async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id

    # Check lock timeout
    current_time = time.time()
    if chat_id in lock_timeouts and current_time > lock_timeouts[chat_id]:
        logger.info(f"Clearing timed out lock for chat_id {chat_id}")
        scan_locks.pop(chat_id, None)
        scan_stop.pop(chat_id, None)
        message_ids.pop(chat_id, None)
        last_message_state.pop(chat_id, None)
        awaiting_input.pop(chat_id, None)
        lock_timeouts.pop(chat_id, None)

    # Cancel any ongoing scan for this chat_id
    if scan_locks.get(chat_id, False):
        logger.info(f"Canceling previous scan for chat_id {chat_id}")
        scan_stop[chat_id] = True
        scan_locks.pop(chat_id, None)
        message_ids.pop(chat_id, None)
        last_message_state.pop(chat_id, None)
        lock_timeouts.pop(chat_id, None)
        await update.message.reply_text("🛑 Previous scan stopped. Starting new scan...")
        await asyncio.sleep(1)  # Brief delay to ensure old scan stops

    if chat_id not in awaiting_input:
        await update.message.reply_text("⚠️ Please use /start to choose an option.")
        return

    target = update.message.text.strip()
    mode = awaiting_input[chat_id]

    # Start new scan instantly
    logger.info(f"Starting new scan: mode={mode}, ip={target}, chat_id={chat_id}")
    try:
        if mode == "ip_scan":
            if "/" in target:
                await scan_cidr(target, chat_id, update, context, is_cctv=False)
            else:
                await scan_single_ip(target, chat_id, update, context, is_cctv=False)
        elif mode == "cctv_hack":
            if "/" in target:
                await scan_cidr(target, chat_id, update, context, is_cctv=True)
            else:
                await scan_single_ip(target, chat_id, update, context, is_cctv=True)
    except Exception as e:
        logger.error(f"Error starting new scan for chat_id {chat_id}: {str(e)}")
        await update.message.reply_text(f"⚠️ Scan failed: {str(e)}")
        try:
            await context.bot.send_message(
                chat_id=ADMIN_CHAT_ID,
                text=f"⚠️ Scan error for chat {chat_id}: {str(e)}"
            )
        except Exception as admin_e:
            logger.error(f"Failed to notify admin: {admin_e}")

async def process_scan_queue(app):
    logger.info("Starting scan queue processor")
    while True:
        try:
            async with asyncio.timeout(1200):  # 20 min timeout per scan
                mode, target, chat_id, update, context = await scan_queue.get()
                logger.info(f"Processing scan queue task: mode={mode}, ip={target}, chat_id={chat_id}")
                try:
                    if mode == "ip_scan":
                        if "/" in target:
                            await scan_cidr(target, chat_id, update, context, is_cctv=False)
                        else:
                            await scan_single_ip(target, chat_id, update, context, is_cctv=False)
                    elif mode == "cctv_hack":
                        if "/" in target:
                            await scan_cidr(target, chat_id, update, context, is_cctv=True)
                        else:
                            await scan_single_ip(target, chat_id, update, context, is_cctv=True)
                finally:
                    scan_queue.task_done()
                    logger.info(f"Completed scan queue task for chat_id {chat_id}")
                await asyncio.sleep(1)
        except asyncio.TimeoutError:
            logger.error(f"Scan queue task timed out for chat_id {chat_id}")
            try:
                await app.bot.send_message(
                    chat_id=chat_id,
                    text="⚠️ Scan timed out. Please try again."
                )
                await app.bot.send_message(
                    chat_id=ADMIN_CHAT_ID,
                    text=f"⚠️ Scan queue timeout for chat {chat_id}"
                )
            except Exception as admin_e:
                logger.error(f"Failed to notify: {admin_e}")
            scan_queue.task_done()
        except Exception as e:
            logger.error(f"Error processing scan queue: {e}")
            try:
                await app.bot.send_message(
                    chat_id=chat_id,
                    text=f"⚠️ Scan failed: {str(e)}"
                )
                await app.bot.send_message(
                    chat_id=ADMIN_CHAT_ID,
                    text=f"⚠️ Scan queue error for chat {chat_id}: {str(e)}"
                )
            except Exception as admin_e:
                logger.error(f"Failed to notify: {admin_e}")
            scan_queue.task_done()
        await asyncio.sleep(1)

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Error: {context.error}")
    if isinstance(context.error, (NetworkError, TimedOut)):
        await asyncio.sleep(5)
    elif isinstance(context.error, BadRequest):
        logger.error(f"BadRequest: {context.error}")
    elif isinstance(context.error, Conflict):
        logger.error(f"Conflict error: {context.error}")
        try:
            await context.bot.delete_webhook(drop_pending_updates=True)
            logger.info("Webhook cleared due to conflict")
        except Exception as e:
            logger.error(f"Failed to clear webhook: {str(e)}")
    elif str(context.error).startswith("TooManyRequests"):
        logger.warning("Telegram rate limit hit, applying backoff")
        await asyncio.sleep(2 ** len(str(context.error)))
    try:
        if update:
            await update.message.reply_text("⚠️ An error occurred, please try again later.")
        await context.bot.send_message(
            chat_id=ADMIN_CHAT_ID,
            text=f"⚠️ Bot error: {str(context.error)}"
        )
    except Exception as admin_e:
        logger.error(f"Failed to notify admin: {admin_e}")

async def main():
    logger.info("Bot starting...")
    try:
        app = ApplicationBuilder().token(BOT_TOKEN).build()
        logger.info(f"Bot initialized with token: {BOT_TOKEN[:10]}...")
    except Exception as e:
        logger.error(f"Error initializing bot: {str(e)}")
        raise

    try:
        await app.bot.delete_webhook(drop_pending_updates=True)
        logger.info("Webhook cleared at startup")
    except Exception as e:
        logger.error(f"Failed to clear webhook at startup: {str(e)}")

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("cancel", cancel))
    app.add_handler(CommandHandler("getports", get_ports))
    app.add_handler(CommandHandler("info", info))
    app.add_handler(CommandHandler("status", status))
    app.add_handler(CommandHandler("clearlocks", clear_locks))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan))
    app.add_handler(CallbackQueryHandler(button_click))
    app.add_error_handler(error_handler)

    http_runner = await start_http_server()

    max_retries = 10
    retry_delay = 10
    for attempt in range(max_retries):
        try:
            await app.initialize()
            await app.start()
            await app.updater.start_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)
            logger.info("Bot polling started")
            asyncio.create_task(process_scan_queue(app))
            break
        except Exception as e:
            logger.error(f"Error starting Telegram bot (attempt {attempt + 1}/{max_retries}): {str(e)}")
            if attempt < max_retries - 1:
                logger.info(f"Retrying in {retry_delay} seconds...")
                await asyncio.sleep(retry_delay)
            else:
                logger.error("Max retries reached, shutting down...")
                await http_runner.cleanup()
                raise

    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, SystemExit):
        logger.info("Shutting down...")
        await app.updater.stop()
        await app.stop()
        await app.shutdown()
        await http_runner.cleanup()
        logger.info("Shutdown complete")

if __name__ == "__main__":
    asyncio.run(main())
