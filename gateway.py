#!/usr/bin/env python3
"""Authenticated public gateway for a loopback-only ttyd terminal.

The gateway owns the public HTTP/WebSocket surface; ttyd stays bound to
127.0.0.1. Access requires a Microsoft Authenticator (TOTP) code, sessions
survive restarts, and enrollment QR codes are only handed out from the LAN.

The terminal itself runs inside tmux, so the shell never dies when the browser
drops the WebSocket. A small script injected into ttyd's page reconnects after
app switches, tab freezes, and bfcache restores instead of stranding the user
on ttyd's "Press Enter to Reconnect" overlay.
"""

import base64
import gzip
import hashlib
import hmac
import html
import http.client
import ipaddress
import json
import os
import re
import secrets
import select
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HOST = os.environ.get("GATEWAY_HOST", "0.0.0.0")
PORT = int(os.environ.get("GATEWAY_PORT", "8787"))
TTYD_HOST = os.environ.get("TTYD_HOST", "127.0.0.1")
TTYD_PORT = int(os.environ.get("TTYD_PORT", "7682"))
TERMINAL_BASE = "/" + os.environ.get("TERMINAL_BASE", "/terminal/ui").strip("/")
STATE_DIR = Path(os.environ.get("STATE_DIR", "/var/lib/web-terminal-gateway"))
SECRET_PATH = STATE_DIR / "totp-secret"
SESSIONS_PATH = STATE_DIR / "sessions.json"
PASSWORD_PATH = STATE_DIR / "admin-password"
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
TTL_DAYS = int(os.environ.get("SESSION_TTL_DAYS", "400"))
SESSION_TTL = TTL_DAYS * 24 * 3600
ADMIN_TTL = 12 * 3600

COOKIE = "webterm_session"
ADMIN_COOKIE = "webterm_admin"
ISSUER = os.environ.get("TOTP_ISSUER", "web-terminal")
ACCOUNT = os.environ.get("TOTP_ACCOUNT", os.environ.get("USER", "admin"))

# A request carrying any of these arrived through a tunnel or reverse proxy.
# The peer address is then the local connector, so it must not grant LAN rights.
PUBLIC_HEADERS = (
    "cf-connecting-ip",
    "cf-ray",
    "cdn-loop",
    "x-forwarded-for",
    "x-real-ip",
    "true-client-ip",
    "forwarded",
)
LAN_NETS = [
    ipaddress.ip_network(net)
    for net in (
        "127.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
]

RESUME_SCRIPT = b"""<script>
(function () {
  var HIDDEN_MS = 15000;
  var CLOSE_GRACE_MS = 2500;
  var RELOAD_KEY = 'webtermReloads';
  var hiddenAt = 0;
  var sawSocket = false;

  function clearReloads() {
    try { sessionStorage.removeItem(RELOAD_KEY); } catch (e) {}
  }
  function reload() {
    try {
      var now = Date.now();
      var stamps = JSON.parse(sessionStorage.getItem(RELOAD_KEY) || '[]');
      if (!Array.isArray(stamps)) { stamps = []; }
      stamps = stamps.filter(function (t) { return now - t < 60000; });
      if (stamps.length >= 5) { return; }
      stamps.push(now);
      sessionStorage.setItem(RELOAD_KEY, JSON.stringify(stamps));
    } catch (e) {}
    location.reload();
  }
  function current() { return window.__webtermSocket; }
  function dead() {
    var sock = current();
    return sawSocket && (!sock || sock.readyState === 3);
  }
  function wantReconnect(idle) {
    if (!sawSocket) { return; }
    if (dead() || idle > HIDDEN_MS) { reload(); }
  }

  var Native = window.WebSocket;
  if (Native && !Native.__webtermWrapped) {
    var Wrapped = function (url, protocols) {
      var sock = protocols === undefined ? new Native(url) : new Native(url, protocols);
      window.__webtermSocket = sock;
      sawSocket = true;
      sock.addEventListener('open', clearReloads);
      sock.addEventListener('close', function () {
        // ttyd gives up and shows "Press Enter to Reconnect" when the close code
        // is 1000 or the socket errored. Rejoin automatically instead of leaving
        // the page stranded; the tmux session keeps the shell running.
        setTimeout(function () {
          if (current() === sock && sock.readyState === 3) { reload(); }
        }, CLOSE_GRACE_MS);
      });
      return sock;
    };
    Wrapped.prototype = Native.prototype;
    Wrapped.CONNECTING = Native.CONNECTING;
    Wrapped.OPEN = Native.OPEN;
    Wrapped.CLOSING = Native.CLOSING;
    Wrapped.CLOSED = Native.CLOSED;
    Wrapped.__webtermWrapped = true;
    window.WebSocket = Wrapped;
  }

  document.addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'hidden') { hiddenAt = Date.now(); return; }
    var idle = hiddenAt ? Date.now() - hiddenAt : 0;
    hiddenAt = 0;
    wantReconnect(idle);
  });
  window.addEventListener('focus', function () {
    var idle = hiddenAt ? Date.now() - hiddenAt : 0;
    wantReconnect(idle);
  });
  window.addEventListener('pageshow', function (event) {
    if (event.persisted) { reload(); }
  });
  window.addEventListener('online', function () {
    if (dead()) { reload(); }
  });
})();
</script>"""

LOCK = threading.Lock()
SESSIONS = {}
ADMINS = {}
FAILS = {}


def log(message):
    print(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {message}", file=sys.stderr, flush=True)


# --- state -----------------------------------------------------------------

def load_sessions():
    try:
        data = json.loads(SESSIONS_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return
    if not isinstance(data, dict):
        return
    now = time.time()
    with LOCK:
        for token, expiry in data.items():
            if isinstance(token, str) and isinstance(expiry, (int, float)) and expiry > now:
                SESSIONS[token] = float(expiry)


def save_sessions():
    payload = json.dumps(SESSIONS, separators=(",", ":"))
    tmp = SESSIONS_PATH.with_name(SESSIONS_PATH.name + ".tmp")
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        tmp.write_text(payload, encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, SESSIONS_PATH)
    except OSError as exc:
        log(f"could not persist sessions: {exc}")


def load_password():
    env = (os.environ.get("GATEWAY_PASSWORD") or "").strip()
    if env:
        return env
    try:
        return PASSWORD_PATH.read_text(encoding="utf-8").strip()
    except OSError:
        pass
    password = secrets.token_urlsafe(15)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    PASSWORD_PATH.write_text(password + "\n", encoding="utf-8")
    os.chmod(PASSWORD_PATH, 0o600)
    log(f"generated enrollment password: {PASSWORD_PATH}")
    return password


PASSWORD = load_password()


def read_secret():
    try:
        return SECRET_PATH.read_text(encoding="ascii").strip().upper()
    except OSError:
        return ""


def write_secret(secret):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    SECRET_PATH.write_text(secret.upper() + "\n", encoding="ascii")
    os.chmod(SECRET_PATH, 0o600)


def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def reset_secret():
    try:
        SECRET_PATH.unlink()
    except OSError:
        pass


# --- auth ------------------------------------------------------------------

def totp_code(secret, counter=None, step=30):
    counter = int(time.time()) // step if counter is None else int(counter)
    key = base64.b32decode(secret.upper() + "=" * ((8 - len(secret) % 8) % 8))
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{value % 1000000:06d}"


def verify_code(secret, code):
    code = re.sub(r"\s+", "", str(code or ""))
    if not re.fullmatch(r"\d{6}", code):
        return False
    now = int(time.time()) // 30
    return any(hmac.compare_digest(totp_code(secret, now + drift), code) for drift in (-1, 0, 1))


def otp_uri(secret):
    label = urllib.parse.quote(f"{ISSUER}:{ACCOUNT}", safe="")
    issuer = urllib.parse.quote(ISSUER, safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={issuer}"
        "&algorithm=SHA1&digits=6&period=30"
    )


def qr_svg(secret):
    try:
        proc = subprocess.run(
            ["qrencode", "-t", "SVG", "-o", "-", otp_uri(secret)],
            capture_output=True, timeout=10,
        )
        if proc.returncode == 0 and b"<svg" in proc.stdout:
            return proc.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        pass
    return ""


def cookie_value(handler, name):
    cookie = SimpleCookie()
    try:
        cookie.load(handler.headers.get("Cookie", ""))
    except Exception:
        return ""
    morsel = cookie.get(name)
    return morsel.value if morsel else ""


def set_cookie(handler, name, value, ttl, path="/"):
    parts = [
        f"{name}={value}",
        f"Path={path}",
        "HttpOnly",
        "SameSite=Strict",
        f"Max-Age={ttl}",
    ]
    if COOKIE_SECURE:
        parts.append("Secure")
    handler.send_header("Set-Cookie", "; ".join(parts))


def new_session():
    token = secrets.token_urlsafe(32)
    now = time.time()
    with LOCK:
        for key, expiry in list(SESSIONS.items()):
            if expiry <= now:
                SESSIONS.pop(key, None)
        SESSIONS[token] = now + SESSION_TTL
        save_sessions()
    return token


def session_valid(handler):
    token = cookie_value(handler, COOKIE)
    if not token:
        return False
    now = time.time()
    with LOCK:
        expiry = SESSIONS.get(token)
        if not expiry or expiry <= now:
            if SESSIONS.pop(token, None) is not None:
                save_sessions()
            return False
        return True


def admin_valid(handler):
    token = cookie_value(handler, ADMIN_COOKIE)
    if not token:
        return False
    with LOCK:
        expiry = ADMINS.get(token)
        if not expiry or expiry <= time.time():
            ADMINS.pop(token, None)
            return False
        return True


def new_admin_session():
    token = secrets.token_urlsafe(32)
    with LOCK:
        ADMINS[token] = time.time() + ADMIN_TTL
    return token


def login_blocked(ip):
    now = time.time()
    with LOCK:
        attempts = [stamp for stamp in FAILS.get(ip, []) if now - stamp < 300]
        FAILS[ip] = attempts
        return len(attempts) >= 8


def record_failure(ip):
    with LOCK:
        FAILS.setdefault(ip, []).append(time.time())


def clear_failures(ip):
    with LOCK:
        FAILS.pop(ip, None)


def lan_client(handler):
    """True only for a direct private-network request, never for tunneled ones."""
    if any(handler.headers.get(key) for key in PUBLIC_HEADERS):
        return False
    peer = getattr(handler, "client_address", None)
    if not peer:
        return False
    try:
        addr = ipaddress.ip_address(str(peer[0]).split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in net for net in LAN_NETS)


# --- pages -----------------------------------------------------------------

CSS = """
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center;
    background: #0b0f14; color: #e6edf3;
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }
  main { width: min(560px, calc(100vw - 32px)); padding: 28px;
    background: #121922; border: 1px solid #243040; border-radius: 14px;
    box-shadow: 0 18px 60px #0008; }
  h1 { font-size: 23px; margin: 0 0 10px; }
  .sub { color: #8ea0b5; font-size: 12px; letter-spacing: .12em;
    text-transform: uppercase; margin: 0 0 12px; }
  .qr { background: #fff; padding: 12px; border-radius: 10px;
    width: max-content; max-width: 100%; margin: 14px 0; }
  .qr svg { display: block; width: 240px; height: 240px; max-width: 100%; height: auto; }
  label { display: block; margin: 14px 0 6px; color: #a9b7c6; font-size: 13px; }
  input { width: 100%; padding: 12px; border-radius: 9px; border: 1px solid #2b394b;
    background: #0b1118; color: #e6edf3; font: 20px/1 ui-monospace, monospace;
    letter-spacing: .2em; text-align: center; }
  button, .button { display: inline-block; margin-top: 14px; padding: 11px 15px;
    border: 0; border-radius: 9px; background: #3b82f6; color: #fff;
    font: inherit; font-weight: 600; text-decoration: none; cursor: pointer; }
  .danger { background: #b91c1c; }
  .err { color: #ff9aa2; margin: 12px 0 0; min-height: 20px; }
  .hint { color: #7d8ea3; font-size: 12px; overflow-wrap: anywhere; }
  code { color: #9ecbff; } a { color: #7db4ff; }
  ul { padding-left: 20px; } li { margin: 6px 0; }
"""


def page(title, body):
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>{CSS}</style></head><body><main>
{body}
</main></body></html>""".encode("utf-8")


def login_page(error="", note="", can_enroll=True):
    secret = bool(read_secret())
    if not secret:
        button = (
            '<p><a class="button" href="/enroll">Open LAN enrollment</a></p>'
            if can_enroll
            else ""
        )
        return page("web terminal access", f"""
  <div class="sub">SECURE TERMINAL</div>
  <h1>Microsoft Authenticator</h1>
  <p>This terminal has no Authenticator enrollment yet. Enrollment is
     only available from the LAN.</p>
  {button}
  <p class="err">{html.escape(error)}</p>
""")
    return page("web terminal access", f"""
  <div class="sub">SECURE TERMINAL</div>
  <h1>Microsoft Authenticator</h1>
  <p>Enter the current code from Microsoft Authenticator.</p>
  {note}
  <form method="post" action="/terminal" autocomplete="off">
    <label for="code">Authenticator code</label>
    <input id="code" name="code" inputmode="numeric" autocomplete="one-time-code"
      pattern="[0-9]{{6}}" maxlength="6" placeholder="000000" required>
    <button type="submit">Open terminal</button>
  </form>
  <p class="err">{html.escape(error)}</p>
  <p class="hint">Sign-in lasts {TTL_DAYS} days. The shell runs in a persistent
    tmux session, so closing the tab or switching apps does not stop running work.</p>
""")


def password_page(error=""):
    return page("enrollment", f"""
  <div class="sub">LAN ENROLLMENT</div>
  <h1>Admin password</h1>
  <p>Enrollment is restricted to the local network and requires the gateway
     password from <code>{html.escape(str(PASSWORD_PATH))}</code>.</p>
  <form method="post" action="/enroll" autocomplete="off">
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Continue</button>
  </form>
  <p class="err">{html.escape(error)}</p>
""")


def enroll_page(error=""):
    secret = read_secret()
    if not secret:
        secret = new_secret()
        write_secret(secret)
    qr = qr_svg(secret)
    qr_html = f'<div class="qr">{qr}</div>' if qr else ""
    return page("enroll authenticator", f"""
  <div class="sub">LAN ENROLLMENT</div>
  <h1>Microsoft Authenticator</h1>
  <p>Scan this QR code with Microsoft Authenticator, then enter the current
     6-digit code on the terminal page.</p>
  {qr_html}
  <p class="hint">Manual key: <code>{html.escape(secret)}</code></p>
  <p class="hint">This page is only reachable from the LAN and after the admin
     password. Anyone who scans it can open a shell, so keep it private.</p>
  <form method="post" action="/enroll/reset">
    <button class="danger" type="submit">Reset enrollment</button>
  </form>
  <p class="err">{html.escape(error)}</p>
  <p><a class="button" href="/terminal">Back to terminal login</a></p>
""")


def enroll_blocked_page():
    return page("enrollment unavailable", """
  <div class="sub">LAN ENROLLMENT</div>
  <h1>Enrollment is LAN-only</h1>
  <p>This request did not come from the local network. Enrollment and QR code
     generation are disabled here; connect to the same network as the gateway
     and open <code>/enroll</code> directly.</p>
  <p><a class="button" href="/terminal">Terminal login</a></p>
""")


# --- proxy -----------------------------------------------------------------

def inject_resume(raw):
    if b"</head>" in raw:
        return raw.replace(b"</head>", RESUME_SCRIPT + b"</head>", 1)
    return raw + RESUME_SCRIPT


def proxy_http(handler):
    handler.protocol_version = "HTTP/1.0"
    try:
        length = int(handler.headers.get("Content-Length") or 0)
    except ValueError:
        length = 0
    body = handler.rfile.read(length) if length > 0 else None
    forward = {}
    for key, value in handler.headers.items():
        if key.lower() not in ("host", "connection", "content-length", "transfer-encoding",
                               "origin", "accept-encoding"):
            forward[key] = value
    if body is not None:
        forward["Content-Length"] = str(len(body))
    client_gzip = "gzip" in (handler.headers.get("Accept-Encoding") or "").lower()
    conn = http.client.HTTPConnection(TTYD_HOST, TTYD_PORT, timeout=300)
    started = False
    try:
        conn.request(handler.command, handler.path, body=body, headers=forward)
        resp = conn.getresponse()
        handler.send_response(resp.status, resp.reason)
        started = True
        ctype = (resp.getheader("Content-Type") or "").lower()
        inject = resp.status == 200 and ctype.startswith("text/html")
        for key, value in resp.getheaders():
            if key.lower() in ("transfer-encoding", "connection", "content-length", "content-encoding"):
                continue
            handler.send_header(key, value)
        payload = inject_resume(resp.read()) if inject else None
        if payload is not None:
            if client_gzip:
                payload = gzip.compress(payload, 6)
                handler.send_header("Content-Encoding", "gzip")
            handler.send_header("Content-Length", str(len(payload)))
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Connection", "close")
        handler.end_headers()
        if payload is not None:
            handler.wfile.write(payload)
            handler.wfile.flush()
        else:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                handler.wfile.write(chunk)
                handler.wfile.flush()
    except (BrokenPipeError, ConnectionResetError):
        pass
    except Exception as exc:
        if not started:
            payload = json.dumps({"error": "terminal unavailable", "detail": str(exc)[:200]}).encode()
            handler.send_response(502)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(payload)))
            handler.end_headers()
            try:
                handler.wfile.write(payload)
            except OSError:
                pass
    finally:
        conn.close()
        handler.close_connection = True


def proxy_ws(handler):
    upstream = None
    try:
        upstream = socket.create_connection((TTYD_HOST, TTYD_PORT), timeout=10)
        lines = [
            f"GET {handler.path} HTTP/1.1",
            f"Host: {TTYD_HOST}:{TTYD_PORT}",
            "Upgrade: websocket",
            "Connection: Upgrade",
        ]
        for key in ("Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Protocol",
                    "Sec-WebSocket-Extensions", "Cookie", "User-Agent", "Origin"):
            value = handler.headers.get(key)
            if value:
                lines.append(f"{key}: {value}")
        upstream.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = upstream.recv(4096)
            if not chunk:
                break
            response += chunk
        handler.wfile.write(response)
        handler.wfile.flush()
        if b" 101 " not in response.split(b"\r\n", 1)[0]:
            return
        while True:
            readable, _, _ = select.select([handler.connection, upstream], [], [])
            for source in readable:
                data = source.recv(65536)
                if not data:
                    return
                target = upstream if source is handler.connection else handler.connection
                target.sendall(data)
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass
    finally:
        try:
            if upstream is not None:
                upstream.close()
        except OSError:
            pass
        handler.close_connection = True


# --- routing ---------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "web-terminal-gateway/1.0"

    def log_message(self, fmt, *args):
        log(f"{self.client_address[0]} {fmt % args}")

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def send_body(self, payload, status=200, ctype="text/html; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(payload)
        except OSError:
            pass

    def redirect(self, location, cookies=()):
        self.send_response(303)
        self.send_header("Location", location)
        for name, value, ttl, path in cookies:
            set_cookie(self, name, value, ttl, path)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def route(self, method):
        split = urllib.parse.urlsplit(self.path)
        path = split.path
        try:
            if path in ("/", "/index.html"):
                self.redirect("/terminal")
            elif path == "/terminal":
                self.handle_terminal(method)
            elif path == "/enroll":
                self.handle_enroll(method)
            elif path == "/enroll/reset":
                self.handle_reset(method)
            elif path == "/logout":
                self.redirect("/terminal", ((COOKIE, "", 0, "/"),))
            elif path == "/healthz":
                self.send_body(b"ok\n", ctype="text/plain; charset=utf-8")
            elif path == TERMINAL_BASE or path.startswith(TERMINAL_BASE + "/"):
                self.handle_proxy()
            else:
                self.send_body(b"not found\n", 404, "text/plain; charset=utf-8")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def form(self):
        try:
            length = min(int(self.headers.get("Content-Length") or 0), 65536)
            raw = self.rfile.read(length).decode("utf-8", "replace")
            return urllib.parse.parse_qs(raw)
        except (ValueError, OSError):
            return {}

    def handle_terminal(self, method):
        if session_valid(self):
            self.redirect(TERMINAL_BASE + "/")
            return
        can_enroll = lan_client(self)
        if method == "GET":
            self.send_body(login_page(can_enroll=can_enroll))
            return
        ip = self.client_address[0]
        if login_blocked(ip):
            self.send_body(login_page("Too many attempts. Try again later.", can_enroll=can_enroll))
            return
        code = (self.form().get("code") or [""])[0]
        secret = read_secret()
        if not secret or not verify_code(secret, code):
            record_failure(ip)
            self.send_body(login_page("Invalid or expired code.", can_enroll=can_enroll))
            return
        clear_failures(ip)
        self.redirect(TERMINAL_BASE + "/", ((COOKIE, new_session(), SESSION_TTL, "/"),))

    def handle_enroll(self, method):
        if not lan_client(self):
            self.send_body(enroll_blocked_page(), 403)
            return
        if method == "POST":
            ip = self.client_address[0]
            if login_blocked(ip):
                self.send_body(password_page("Too many attempts. Try again later."), 429)
                return
            password = (self.form().get("password") or [""])[0]
            if not hmac.compare_digest(password, PASSWORD):
                record_failure(ip)
                self.send_body(password_page("Incorrect password."), 401)
                return
            clear_failures(ip)
            self.redirect("/enroll", ((ADMIN_COOKIE, new_admin_session(), ADMIN_TTL, "/"),))
            return
        if not admin_valid(self):
            self.send_body(password_page())
            return
        self.send_body(enroll_page())

    def handle_reset(self, method):
        if method != "POST" or not lan_client(self) or not admin_valid(self):
            self.send_body(b"forbidden\n", 403, "text/plain; charset=utf-8")
            return
        reset_secret()
        self.redirect("/enroll")

    def handle_proxy(self):
        if not session_valid(self):
            if self.headers.get("Upgrade", "").lower() == "websocket":
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "30")
                self.end_headers()
                self.wfile.write(b'{"error":"terminal login required"}')
            else:
                self.redirect("/terminal")
            return
        if self.headers.get("Upgrade", "").lower() == "websocket":
            proxy_ws(self)
        else:
            proxy_http(self)


def main():
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    load_sessions()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    log(f"listening on http://{HOST}:{PORT} -> ttyd {TTYD_HOST}:{TTYD_PORT}{TERMINAL_BASE}")
    if not read_secret():
        log(f"no TOTP secret yet; enroll from the LAN at http://<lan-ip>:{PORT}/enroll")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
