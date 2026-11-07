#!/usr/bin/env python3
"""Phone media remote for this Mac. HTTPS + secret token, stdlib only.

Run:        python3 remote.py            (prints the one-time pairing URL)
Pair:       python3 remote.py --qr        (scan the QR with your phone; needs: brew install qrencode)
Self-check: python3 remote.py --selftest
Revoke:     delete ~/.mac-remote/token and restart (phone must re-pair).
"""
import ctypes, hmac, math, http.server, json, os, secrets, socket, ssl, subprocess, sys
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse

PORT = int(os.environ.get("MAC_REMOTE_PORT", 8765))
DIR = os.path.expanduser(os.environ.get("MAC_REMOTE_DIR", "~/.mac-remote"))
SE = 'tell application "System Events" to '
VOL = "set volume output volume ((output volume of (get volume settings)) %s 6)"

# Fixed allowlist: action name -> AppleScript. Nothing from the client is ever spliced in.
ACTIONS = {
    "play": SE + "key code 49",                      # space
    "full": SE + 'keystroke "f"',
    "rew": SE + "key code 123",                      # left arrow
    "ffw": SE + "key code 124",                      # right arrow
    "esc": SE + "key code 53",
    "enter": SE + "key code 36",
    "back": SE + "key code 33 using command down",   # cmd+[
    "nexttab": SE + "key code 48 using control down",
    "prevtab": SE + "key code 48 using {control down, shift down}",
    "up": SE + "key code 126",                       # D-pad
    "down": SE + "key code 125",
    "left": SE + "key code 123",
    "right": SE + "key code 124",
    "tab": SE + "key code 48",                       # next link/field
    "shtab": SE + "key code 48 using shift down",    # previous link/field
    "bksp": SE + "key code 51",                      # keyboard mode
    "space": SE + "key code 49",
    "volup": VOL % "+",
    "voldown": VOL % "-",
    "mute": "set volume output muted not (output muted of (get volume settings))",
}
TYPE_SCRIPT = 'on run argv\n' + SE + 'keystroke (item 1 of argv)\nend run'
# Front app + window title + window centre. Title/position need Accessibility; without it only the app name comes back.
FOCUS_SCRIPT = """set vs to get volume settings
tell application "System Events"
  set p to first application process whose frontmost is true
  set n to name of p
  set t to ""
  set c to ""
  try
    set w to front window of p
    set t to name of w
    if t is missing value then set t to ""
    set {x, y} to position of w
    set {ww, hh} to size of w
    set c to ((x + ww / 2) as integer as text) & "," & ((y + hh / 2) as integer as text)
  end try
  return n & linefeed & t & linefeed & c & linefeed & (output volume of vs) & linefeed & (output muted of vs)
end tell"""

# --- mouse via CoreGraphics (loaded lazily so --selftest works anywhere) ---
class CGPoint(ctypes.Structure):
    _fields_ = [("x", ctypes.c_double), ("y", ctypes.c_double)]

class CGRect(ctypes.Structure):
    _fields_ = [("x", ctypes.c_double), ("y", ctypes.c_double), ("w", ctypes.c_double), ("h", ctypes.c_double)]

_cg = None
def cg():
    global _cg
    if _cg is None:
        _cg = ctypes.CDLL("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices")
        _cg.CGEventCreate.restype = ctypes.c_void_p
        _cg.CGEventCreate.argtypes = [ctypes.c_void_p]
        _cg.CGEventGetLocation.restype = CGPoint
        _cg.CGEventGetLocation.argtypes = [ctypes.c_void_p]
        _cg.CGEventCreateMouseEvent.restype = ctypes.c_void_p
        _cg.CGEventCreateMouseEvent.argtypes = [ctypes.c_void_p, ctypes.c_uint32, CGPoint, ctypes.c_uint32]
        _cg.CGEventPost.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
        _cg.CFRelease.argtypes = [ctypes.c_void_p]
        _cg.CGWarpMouseCursorPosition.argtypes = [CGPoint]
        # The "2" variant is non-variadic, which ctypes can call safely on Apple Silicon.
        _cg.CGEventCreateScrollWheelEvent2.restype = ctypes.c_void_p
        _cg.CGEventCreateScrollWheelEvent2.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
                                                       ctypes.c_int32, ctypes.c_int32, ctypes.c_int32]
        _cg.CGGetActiveDisplayList.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32)]
        _cg.CGDisplayBounds.restype = CGRect
        _cg.CGDisplayBounds.argtypes = [ctypes.c_uint32]
        _cg.CGDisplayIsBuiltin.restype = ctypes.c_bool
        _cg.CGDisplayIsBuiltin.argtypes = [ctypes.c_uint32]
    return _cg

def mouse_pos():
    e = cg().CGEventCreate(None)
    p = cg().CGEventGetLocation(e)
    cg().CFRelease(e)
    return p

def mouse_post(kind, p, button=0):  # kinds: 5 moved, 1/2 left down/up, 3/4 right down/up
    e = cg().CGEventCreateMouseEvent(None, kind, p, button)
    cg().CGEventPost(0, e)
    cg().CFRelease(e)

def ax_trusted(prompt=False):
    """True if this process may send keys/mouse. prompt=True makes macOS show the Accessibility dialog."""
    ax = cg()
    ax.AXIsProcessTrustedWithOptions.restype = ctypes.c_bool
    ax.AXIsProcessTrustedWithOptions.argtypes = [ctypes.c_void_p]
    if not prompt:
        return ax.AXIsProcessTrustedWithOptions(None)
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    cf.CFDictionaryCreate.restype = ctypes.c_void_p
    cf.CFDictionaryCreate.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
                                      ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    keys = (ctypes.c_void_p * 1)(ctypes.c_void_p.in_dll(ax, "kAXTrustedCheckOptionPrompt").value)
    vals = (ctypes.c_void_p * 1)(ctypes.c_void_p.in_dll(cf, "kCFBooleanTrue").value)
    opts = cf.CFDictionaryCreate(None, keys, vals, 1,
                                 ctypes.addressof(ctypes.c_char.in_dll(cf, "kCFTypeDictionaryKeyCallBacks")),
                                 ctypes.addressof(ctypes.c_char.in_dll(cf, "kCFTypeDictionaryValueCallBacks")))
    ok = ax.AXIsProcessTrustedWithOptions(opts)
    ax.CFRelease(opts)  # ax has CFRelease typed for 64-bit pointers
    return ok

def scroll(dx, dy):
    e = cg().CGEventCreateScrollWheelEvent2(None, 0, 2, int(dy), int(dx), 0)  # 0 = pixel units
    cg().CGEventPost(0, e)
    cg().CFRelease(e)

def displays():
    ids, n = (ctypes.c_uint32 * 8)(), ctypes.c_uint32()
    cg().CGGetActiveDisplayList(8, ids, ctypes.byref(n))
    out = []
    for i in ids[:n.value]:
        r = cg().CGDisplayBounds(i)
        out.append((r.x, r.y, r.w, r.h, bool(cg().CGDisplayIsBuiltin(i))))
    return out

def screen_label(x, y, disps):
    """Name the display containing point (x, y): 'MacBook', 'Monitor', or 'Monitor 2'..."""
    n = 0
    for dx, dy, w, h, builtin in disps:
        if not builtin:
            n += 1
        if dx <= x < dx + w and dy <= y < dy + h:
            return "MacBook" if builtin else ("Monitor" if n == 1 else "Monitor %d" % n)
    return ""

def focus():
    r = subprocess.run(["osascript", "-e", FOCUS_SCRIPT], capture_output=True, text=True, timeout=3)
    app, title, centre, vol, muted = (r.stdout.rstrip("\n").split("\n") + [""] * 5)[:5]
    screen = ""
    if centre:
        x, y = map(float, centre.split(","))
        screen = screen_label(x, y, displays())
    out = {"app": app, "title": title[:120], "screen": screen}
    if vol.isdigit():
        out.update(vol=int(vol), muted=muted == "true")
    return out

def num(v):  # client-supplied deltas: finite and bounded, or the request is refused
    f = float(v)
    if not math.isfinite(f):
        raise ValueError("bad number")
    return max(-3000.0, min(3000.0, f))

def do(msg):
    a = msg.get("a")
    if a in ACTIONS:
        subprocess.run(["osascript", "-e", ACTIONS[a]], check=False)
    elif a == "type":
        text = str(msg.get("text", ""))[:500]
        if text:
            subprocess.run(["osascript", "-e", TYPE_SCRIPT, text], check=False)
    elif a == "move":
        p = mouse_pos()
        q = CGPoint(p.x + num(msg["dx"]), p.y + num(msg["dy"]))
        cg().CGWarpMouseCursorPosition(q)  # moves the cursor itself
        mouse_post(5, q)                    # lets pages see hover
    elif a == "setvol":  # volume slider; value is validated to an int 0-100 before use
        v = int(max(0.0, min(100.0, num(msg["v"]))))
        subprocess.run(["osascript", "-e", "set volume output volume %d" % v], check=False)
    elif a == "scroll":
        scroll(num(msg["dx"]), num(msg["dy"]))
    elif a == "ping":  # "Connected" + which app/window/screen has focus
        return focus()
    elif a == "click":
        p = mouse_pos()
        mouse_post(1, p)
        mouse_post(2, p)
    elif a == "rclick":
        p = mouse_pos()
        mouse_post(3, p, 1)
        mouse_post(4, p, 1)
    else:
        return False
    return True

# --- server ---
def setup():
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    tok_path = os.path.join(DIR, "token")
    if not os.path.exists(tok_path):
        fd = os.open(tok_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, secrets.token_urlsafe(32).encode())
        os.close(fd)
    cert, key = os.path.join(DIR, "cert.pem"), os.path.join(DIR, "key.pem")
    if not os.path.exists(cert):
        host = socket.gethostname().split(".")[0]
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "3650",
                        "-keyout", key, "-out", cert, "-subj", "/CN=mac-remote",
                        "-addext", "subjectAltName=DNS:%s.local" % host],
                       check=True, capture_output=True)
        os.chmod(key, 0o600)
    with open(tok_path) as f:
        return f.read().strip(), cert, key

class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive: touchpad moves reuse one TLS connection
    token = ""

    def log_message(self, *a):  # default logger would print the token from the URL
        pass

    def authed(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return "rt" in c and hmac.compare_digest(c["rt"].value, self.token)

    def send(self, code, body=b"", ctype="text/plain", extra=()):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in extra:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        t = parse_qs(u.query).get("t", [""])[0]
        if u.path == "/" and t and hmac.compare_digest(t, self.token):
            cookie = "rt=%s; Max-Age=315360000; Path=/; Secure; HttpOnly; SameSite=Strict" % self.token
            return self.send(303, extra=[("Set-Cookie", cookie), ("Location", "/")])
        if u.path == "/" and self.authed():
            return self.send(200, PAGE.encode(), "text/html; charset=utf-8")
        self.send(403, b"forbidden")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(min(n, 4096))
        if self.path != "/act" or not self.authed():
            return self.send(403, b"forbidden")
        try:
            ok = do(json.loads(body))
        except (ValueError, KeyError, TypeError, subprocess.TimeoutExpired):
            ok = False
        if isinstance(ok, dict):
            return self.send(200, json.dumps(ok).encode(), "application/json")
        self.send(204 if ok else 400)

def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # picks the Wi-Fi interface; no packet is sent
        return s.getsockname()[0]
    finally:
        s.close()

def show_qr():
    # IP, not .local: Chrome on Android often can't resolve .local names.
    url = "https://%s:%d/?t=%s" % (lan_ip(), PORT, setup()[0])
    print(url, flush=True)
    subprocess.run(["qrencode", "-t", "ANSIUTF8", "-m", "2", url], check=True)
    print("Scan with your phone camera, open in Chrome, then Add to Home screen.")

def serve(port=PORT, token=None, ready=None):
    tok, cert, key = setup()
    Handler.token = token or tok
    srv = http.server.ThreadingHTTPServer(("0.0.0.0", port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    if ready:
        ready(srv)
    elif not ax_trusted(prompt=True):
        print("Accessibility not granted yet: allow it in the dialog / System Settings, then restart.", flush=True)
    else:
        host = socket.gethostname().split(".")[0]
        print("Open this ONCE on your phone, then Add to Home screen:")
        print("  https://%s.local:%d/?t=%s" % (host, port, Handler.token))
        print("Mac Remote running. Ctrl+C to stop.", flush=True)
    srv.serve_forever()

PAGE = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,user-scalable=no,viewport-fit=cover">
<meta name="theme-color" content="#0a0b0e"><title>Mac Remote</title><style>
:root{--bg:#0a0b0e;--card:#14161b;--btn:#1d2026;--btn2:#2a2e36;--line:#ffffff0f;--txt:#f3f4f6;--mut:#8b909a;--dim:#5d626c;--acc:#4c8dff;--acc2:#3570e0;--ok:#3ddc84;--bad:#ff5c5c}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent;user-select:none;-webkit-user-select:none}
html,body{height:100%}
body{margin:0;padding:8px 14px 14px;background:var(--bg);color:var(--txt);font:15px/1.25 system-ui,sans-serif;display:flex;flex-direction:column;gap:10px;overflow:hidden}
.card{background:var(--card);border-radius:24px;padding:14px;box-shadow:inset 0 0 0 1px var(--line)}
button{font:inherit;color:var(--txt);background:var(--btn);border:0;border-radius:16px;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:5px;transition:transform .08s,background .12s;touch-action:manipulation}
button:active,button.held{transform:scale(.94);background:var(--btn2)}
button small{font-size:11px;color:var(--mut);letter-spacing:.2px}
svg{width:24px;height:24px;fill:currentColor;flex:none}

/* status: what has focus on the Mac */
.top{display:flex;align-items:center;gap:12px;padding:10px 12px 10px 10px}
.av{width:40px;height:40px;border-radius:12px;display:grid;place-items:center;font-weight:700;font-size:17px;flex:none;background:#2a2e36;color:#fff;transition:background .3s;position:relative}
.av .dot{position:absolute;right:-3px;bottom:-3px;width:12px;height:12px;border-radius:50%;background:var(--dim);border:2.5px solid var(--card)}
.av .dot.on{background:var(--ok)}.av .dot.off{background:var(--bad)}
.meta{flex:1;min-width:0}
.app{font-weight:650;font-size:15px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.win{color:var(--mut);font-size:12.5px;margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.badge{flex:none;font-size:11px;font-weight:650;padding:5px 9px;border-radius:999px;background:#4c8dff1f;color:var(--acc);display:flex;align-items:center;gap:4px}
.badge svg{width:12px;height:12px}
.badge.none{display:none}

/* media */
.media{padding:12px 14px 14px}
.transport{display:grid;grid-template-columns:1fr auto 1fr;align-items:center;gap:12px}
.transport button:not(.play){height:64px;background:transparent}
.transport button:not(.play):active,.transport button.held{background:var(--btn)}
.transport svg{width:30px;height:30px}
.play{width:88px;height:88px;border-radius:50%;background:linear-gradient(160deg,#5c9bff,var(--acc2));box-shadow:0 10px 28px #4c8dff3d,inset 0 1px 0 #ffffff30}
.play:active{background:var(--acc2)}.play svg{width:38px;height:38px}
.vol{display:flex;align-items:center;gap:6px;margin-top:12px;padding:6px;border-radius:18px;background:var(--bg)}
.vol>button{width:44px;height:44px;border-radius:13px;background:transparent;flex:none}
.vol>button:active,.vol>button.held{background:var(--btn)}
#mute{color:var(--txt)}
.slider{flex:1;height:44px;display:flex;align-items:center;touch-action:none;cursor:pointer;min-width:0}
.track{position:relative;flex:1;height:8px;border-radius:99px;background:var(--btn2)}
.fill{position:absolute;left:0;top:0;bottom:0;width:0;border-radius:99px;background:var(--txt)}
.knob{position:absolute;top:50%;left:0;width:20px;height:20px;margin:-10px 0 0 -10px;border-radius:50%;background:#fff;box-shadow:0 2px 8px #0008;transition:transform .1s}
.slider.drag .knob{transform:scale(1.25)}
.slider:not(.drag) .fill,.slider:not(.drag) .knob{transition:width .2s,left .2s}
.muted .fill{background:var(--dim)}.muted .knob{background:var(--mut)}
.pct{width:46px;text-align:center;font-variant-numeric:tabular-nums;color:var(--mut);font-size:12.5px;flex:none}

/* browser row */
.nav{display:grid;grid-template-columns:repeat(5,1fr);gap:4px;padding:6px}
.nav button{height:58px;border-radius:16px;background:transparent}
.nav button:active{background:var(--btn)}
.nav svg{width:22px;height:22px}

/* bottom: touchpad / d-pad / keyboard */
.ctl{flex:1;min-height:0;display:flex;flex-direction:column;gap:10px;padding:8px}
.seg{position:relative;display:grid;grid-template-columns:repeat(3,1fr);background:var(--bg);border-radius:14px;padding:3px;flex:none}
.seg .pill{position:absolute;top:3px;bottom:3px;left:3px;width:calc((100% - 6px)/3);border-radius:11px;background:var(--btn2);transition:transform .22s cubic-bezier(.3,.7,.2,1)}
.seg button{position:relative;height:36px;border-radius:11px;background:transparent;flex-direction:row;gap:6px;font-size:13px;font-weight:600;color:var(--mut);transition:color .2s}
.seg button svg{width:16px;height:16px}
.seg button.on{color:var(--txt)}
.seg button:active{transform:none;background:transparent}
.view{flex:1;display:none;flex-direction:column;gap:8px;min-height:0;animation:fade .18s ease}
.view.on{display:flex}
@keyframes fade{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}

#pad{flex:1;min-height:100px;position:relative;border-radius:18px;touch-action:none;background:var(--bg) radial-gradient(#ffffff14 1px,transparent 1.3px) 0 0/22px 22px;box-shadow:inset 0 0 0 1px transparent;transition:box-shadow .15s}
#pad.down{box-shadow:inset 0 0 0 2px #4c8dff88}
#pad .hint{position:absolute;inset:auto 0 12px;text-align:center;color:var(--dim);font-size:12px;line-height:1.6;pointer-events:none;transition:opacity .3s}
#pad .hint b{color:var(--mut);font-weight:600}
#pad.used .hint{opacity:0}
.clicks{display:grid;grid-template-columns:1fr 1fr;gap:8px;flex:none}
.clicks button{height:46px;border-radius:14px;flex-direction:row;font-size:14px;color:#d5d8de}

.dwrap{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px;min-height:0}
.dpad{width:min(220px,60vw,34vh);aspect-ratio:1;border-radius:50%;background:radial-gradient(circle at 50% 35%,#252931,var(--btn));display:grid;grid-template:repeat(3,1fr)/repeat(3,1fr);box-shadow:inset 0 0 0 1px var(--line),0 8px 24px #0006;touch-action:none}
.dpad button{background:transparent;border-radius:50%;color:#d5d8de}
.dpad button.held{background:#ffffff12;transform:scale(.9)}
.dpad svg{width:30px;height:30px}
.dpad .u{grid-area:1/2}.dpad .l{grid-area:2/1}.dpad .r{grid-area:2/3}.dpad .d{grid-area:3/2}
.dpad .ok{grid-area:2/2;margin:3px;background:linear-gradient(160deg,#5c9bff,var(--acc2));font-weight:700;font-size:15px;letter-spacing:.6px;color:#fff;box-shadow:0 6px 18px #4c8dff40}
.dpad .ok.held,.dpad .ok:active{background:var(--acc2)}
.pair{display:grid;grid-template-columns:1fr 1fr;gap:8px;width:100%;flex:none}
.pair button{height:46px;border-radius:14px;flex-direction:row;gap:8px;font-size:13.5px;color:#d5d8de}
.pair button svg{width:18px;height:18px}

.kb{flex:1;display:flex;flex-direction:column;gap:8px;min-height:0}
.field{display:flex;align-items:center;background:var(--bg);border-radius:16px;padding:0 6px 0 16px;box-shadow:inset 0 0 0 1px var(--line);flex:none}
.field:focus-within{box-shadow:inset 0 0 0 1.5px #4c8dff99}
input{flex:1;min-width:0;height:54px;background:none;border:0;outline:0;color:var(--txt);font:inherit;font-size:17px;user-select:text;-webkit-user-select:text}
input::placeholder{color:var(--dim)}
.field button{width:42px;height:42px;border-radius:12px;background:var(--acc)}
.field button svg{width:20px;height:20px}
.keys{flex:1;display:grid;grid-template-columns:repeat(3,1fr);grid-auto-rows:minmax(48px,1fr);gap:8px;max-height:150px}
.keys button{border-radius:14px;flex-direction:row;gap:7px;font-size:13.5px;color:#d5d8de}
.keys button svg{width:20px;height:20px}
.keys .enter{background:#4c8dff26;color:#cfe0ff}
/* phone keyboard open: keep only the focused window and the Keys card */
@media (max-height:600px){.media,.nav{display:none}.keys{max-height:none}}
.sent{text-align:center;font-size:12px;color:var(--ok);height:14px;opacity:0;transition:opacity .2s;flex:none}
.sent.show{opacity:1}
</style></head><body>

<section class="card top" aria-live="polite">
  <div class="av" id="av">·<i class="dot" id="dot"></i></div>
  <div class="meta"><div class="app" id="fa">Connecting…</div><div class="win" id="fw">Looking for your Mac</div></div>
  <span class="badge none" id="fs"></span>
</section>

<section class="card media">
  <div class="transport">
    <button data-a="rew" data-rep aria-label="Rewind"><svg viewBox="0 0 24 24"><path d="M11 18V6l-8.5 6zm.5-6 8.5 6V6z"/></svg><small>Rewind</small></button>
    <button class="play" data-a="play" aria-label="Play or pause"><svg viewBox="0 0 24 24"><path d="M3 5v14l9-7zm11 0h2.6v14H14zm5 0h2.6v14H19z"/></svg></button>
    <button data-a="ffw" data-rep aria-label="Forward"><svg viewBox="0 0 24 24"><path d="M4 18l8.5-6L4 6zm9-12v12l8.5-6z"/></svg><small>Forward</small></button>
  </div>
  <div class="vol" id="vol">
    <button id="mute" data-a="mute" aria-label="Mute"><svg viewBox="0 0 24 24"><path id="spk" d="M3 9v6h4l5 5V4L7 9zm13.5 3A4.5 4.5 0 0 0 14 8v8a4.5 4.5 0 0 0 2.5-4zM14 3.2v2.1a7 7 0 0 1 0 13.4v2.1a9 9 0 0 0 0-17.6z"/></svg></button>
    <button data-a="voldown" data-rep aria-label="Volume down"><svg viewBox="0 0 24 24"><path d="M5 11h14v2H5z"/></svg></button>
    <div class="slider" id="slider" role="slider" aria-label="Mac volume"><div class="track"><div class="fill" id="vb"></div><div class="knob" id="vk"></div></div></div>
    <button data-a="volup" data-rep aria-label="Volume up"><svg viewBox="0 0 24 24"><path d="M11 5h2v6h6v2h-6v6h-2v-6H5v-2h6z"/></svg></button>
    <span class="pct" id="vp">–</span>
  </div>
</section>

<section class="card nav">
  <button data-a="prevtab" aria-label="Previous tab"><svg viewBox="0 0 24 24"><path d="M18.4 7.4 17 6l-6 6 6 6 1.4-1.4-4.6-4.6zm-6 0L11 6l-6 6 6 6 1.4-1.4L7.8 12z"/></svg><small>Tab</small></button>
  <button data-a="back" aria-label="Back"><svg viewBox="0 0 24 24"><path d="M20 11H7.8l5.6-5.6L12 4l-8 8 8 8 1.4-1.4L7.8 13H20z"/></svg><small>Back</small></button>
  <button data-a="nexttab" aria-label="Next tab"><svg viewBox="0 0 24 24"><path d="m5.6 7.4 1.4-1.4 6 6-6 6-1.4-1.4 4.6-4.6zm6 0L13 6l6 6-6 6-1.4-1.4 4.6-4.6z"/></svg><small>Tab</small></button>
  <button data-a="full" aria-label="Fullscreen"><svg viewBox="0 0 24 24"><path d="M3 3h6v2H5v4H3zm12 0h6v6h-2V5h-4zM3 15h2v4h4v2H3zm16 0h2v6h-6v-2h4z"/></svg><small>Full</small></button>
  <button data-a="esc" aria-label="Escape"><svg viewBox="0 0 24 24"><path d="M19 6.4 17.6 5 12 10.6 6.4 5 5 6.4l5.6 5.6L5 17.6 6.4 19l5.6-5.6 5.6 5.6 1.4-1.4-5.6-5.6z"/></svg><small>Esc</small></button>
</section>

<section class="card ctl">
  <div class="seg" role="tablist">
    <i class="pill" id="pill"></i>
    <button data-mode="pad" role="tab"><svg viewBox="0 0 24 24"><path d="M4 4h16v12H4zm2 2v8h12V6zm-2 12h7v2H4zm9 0h7v2h-7z"/></svg>Touchpad</button>
    <button data-mode="dpad" role="tab"><svg viewBox="0 0 24 24"><path d="M9 2h6v7h7v6h-7v7H9v-7H2V9h7z"/></svg>D-pad</button>
    <button data-mode="kb" role="tab"><svg viewBox="0 0 24 24"><path d="M2 5h20v14H2zm2 2v10h16V7zm1 1h2v2H5zm3 0h2v2H8zm3 0h2v2h-2zm3 0h2v2h-2zm3 0h2v2h-2zM5 11h2v2H5zm3 0h2v2H8zm3 0h2v2h-2zm3 0h2v2h-2zm3 0h2v2h-2zM7 14h10v2H7z"/></svg>Keys</button>
  </div>

  <div class="view" id="v-pad">
    <div id="pad"><div class="hint"><b>Drag</b> to move · <b>tap</b> to click<br><b>Two fingers</b>: drag to scroll · tap to right-click</div></div>
    <div class="clicks">
      <button data-a="click">Left click</button>
      <button data-a="rclick">Right click</button>
    </div>
  </div>

  <div class="view" id="v-dpad">
    <div class="dwrap">
      <div class="dpad">
        <button class="u" data-a="up" data-rep aria-label="Up"><svg viewBox="0 0 24 24"><path d="M7.4 15.4 12 10.8l4.6 4.6L18 14l-6-6-6 6z"/></svg></button>
        <button class="l" data-a="left" data-rep aria-label="Left"><svg viewBox="0 0 24 24"><path d="M15.4 16.6 10.8 12l4.6-4.6L14 6l-6 6 6 6z"/></svg></button>
        <button class="ok" data-a="enter" aria-label="OK">OK</button>
        <button class="r" data-a="right" data-rep aria-label="Right"><svg viewBox="0 0 24 24"><path d="M8.6 16.6 13.2 12 8.6 7.4 10 6l6 6-6 6z"/></svg></button>
        <button class="d" data-a="down" data-rep aria-label="Down"><svg viewBox="0 0 24 24"><path d="M7.4 8.6 12 13.2l4.6-4.6L18 10l-6 6-6-6z"/></svg></button>
      </div>
      <div class="pair">
        <button data-a="shtab" data-rep><svg viewBox="0 0 24 24"><path d="M4 6h2v12H4zm4 6 7-6v4h5v4h-5v4z"/></svg>Prev link</button>
        <button data-a="tab" data-rep>Next link<svg viewBox="0 0 24 24"><path d="M18 6h2v12h-2zm-2 6-7 6v-4H4v-4h5V6z"/></svg></button>
      </div>
    </div>
  </div>

  <div class="view" id="v-kb">
    <div class="kb">
      <div class="field"><input id="t" placeholder="Type on the Mac…" enterkeyhint="send" autocomplete="off" autocapitalize="off" spellcheck="false">
        <button id="s" aria-label="Send text"><svg viewBox="0 0 24 24"><path d="M3 20.5 21 12 3 3.5v6.6l12 1.9-12 1.9z"/></svg></button></div>
      <div class="sent" id="sent">Sent ✓</div>
      <div class="keys">
        <button data-a="bksp" data-rep><svg viewBox="0 0 24 24"><path d="M22 4H8l-7 8 7 8h14zm-2 2v12H8.9l-5.2-6 5.2-6zm-9.6 2L9 9.4l2.6 2.6L9 14.6l1.4 1.4 2.6-2.6 2.6 2.6 1.4-1.4-2.6-2.6 2.6-2.6L15.6 8 13 10.6z"/></svg>Delete</button>
        <button data-a="space" data-rep>Space</button>
        <button class="enter" data-a="enter"><svg viewBox="0 0 24 24"><path d="M19 7v4H5.8l3.6-3.6L8 6l-6 6 6 6 1.4-1.4L5.8 13H21V7z"/></svg>Enter</button>
        <button data-a="left" data-rep><svg viewBox="0 0 24 24"><path d="M15.4 16.6 10.8 12l4.6-4.6L14 6l-6 6 6 6z"/></svg>Left</button>
        <button data-a="tab" data-rep>Tab<svg viewBox="0 0 24 24"><path d="M18 6h2v12h-2zm-2 6-7 6v-4H4v-4h5V6z"/></svg></button>
        <button data-a="right" data-rep>Right<svg viewBox="0 0 24 24"><path d="M8.6 16.6 13.2 12 8.6 7.4 10 6l6 6-6 6z"/></svg></button>
      </div>
    </div>
  </div>
</section>

<script>
const SPEED = 2.0;   // touchpad sensitivity, tune to taste
const SCROLL = 3.0;  // two-finger scroll speed; make negative to flip direction
const $ = id => document.getElementById(id);
const SPK = 'M3 9v6h4l5 5V4L7 9zm13.5 3A4.5 4.5 0 0 0 14 8v8a4.5 4.5 0 0 0 2.5-4zM14 3.2v2.1a7 7 0 0 1 0 13.4v2.1a9 9 0 0 0 0-17.6z';
const MUTE = 'M3 9v6h4l5 5V4L7 9zm13.6.4 1.4-1.4 2 2 2-2 1.4 1.4-2 2 2 2-1.4 1.4-2-2-2 2-1.4-1.4 2-2z';
const MON = '<svg viewBox="0 0 24 24"><path d="M3 4h18v12H3zm2 2v8h14V6zm3 12h8v2H8z"/></svg>';
const store = { get: k => { try { return localStorage.getItem(k); } catch (e) { return null; } },
                set: (k, v) => { try { localStorage.setItem(k, v); } catch (e) {} } };

// connection + focused window
let online = null;
function status(ok) {
  if (ok === online) return; online = ok;
  $('dot').className = 'dot ' + (ok ? 'on' : 'off');
  if (!ok) { $('fa').textContent = 'Mac offline'; $('fw').textContent = 'Is the Mac awake and Mac Remote running?'; $('av').firstChild.textContent = '!'; $('av').style.background = '#5a2328'; $('fs').className = 'badge none'; }
}
const post = m => fetch('/act', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(m)})
  .then(r => { status(r.ok); return r; }, e => { status(false); throw e; });
const buzz = () => navigator.vibrate && navigator.vibrate(12);
function hue(s) { let h = 0; for (const c of s) h = (h * 31 + c.charCodeAt(0)) % 360; return h; }

// volume slider
let vol = 0, muted = false, dragging = false;
function drawVol() {
  const w = (muted ? 0 : vol) + '%';
  $('vb').style.width = w; $('vk').style.left = w;
  $('vp').textContent = muted ? 'Muted' : vol + '%';
  $('vol').classList.toggle('muted', muted);
  $('spk').setAttribute('d', muted ? MUTE : SPK);
}
function show(f) {
  const app = f.app || 'Unknown app';
  $('fa').textContent = app;
  $('fw').textContent = f.title || (f.app ? 'Window title needs Accessibility' : '');
  $('av').firstChild.textContent = app.trim()[0] ? app.trim()[0].toUpperCase() : '·';
  $('av').style.background = 'hsl(' + hue(app) + ' 42% 30%)';
  $('fs').className = f.screen ? 'badge' : 'badge none';
  $('fs').innerHTML = f.screen ? MON + f.screen : '';
  if (typeof f.vol === 'number' && !dragging) { vol = f.vol; muted = !!f.muted; drawVol(); }
}
const ping = () => document.visibilityState === 'visible' && post({a:'ping'}).then(r => r.ok && r.json()).then(f => f && show(f)).catch(()=>{});
let pingSoon = 0;
const refresh = () => { clearTimeout(pingSoon); pingSoon = setTimeout(ping, 150); };
ping(); setInterval(ping, 2000); document.addEventListener('visibilitychange', ping);

const slider = $('slider');
let volSending = false, volWant = null;
function sendVol() {
  if (volSending || volWant === null) return;
  const v = volWant; volWant = null; volSending = true;
  post({a:'setvol', v}).catch(()=>{}).finally(() => { volSending = false; sendVol(); });
}
function volAt(e) {
  const r = slider.querySelector('.track').getBoundingClientRect();
  vol = Math.round(Math.max(0, Math.min(1, (e.clientX - r.left) / r.width)) * 100);
  muted = false; drawVol(); volWant = vol; sendVol();
}
slider.addEventListener('pointerdown', e => { dragging = true; slider.classList.add('drag'); slider.setPointerCapture(e.pointerId); volAt(e); });
slider.addEventListener('pointermove', e => { if (dragging) volAt(e); });
['pointerup', 'pointercancel'].forEach(ev => slider.addEventListener(ev, () => {
  if (!dragging) return; dragging = false; slider.classList.remove('drag'); buzz(); setTimeout(ping, 400);
}));

// buttons: tap = once; data-rep buttons repeat while held
const fire = a => post({a}).then(refresh).catch(()=>{});
document.querySelectorAll('[data-a]').forEach(b => {
  const a = b.dataset.a;
  if (!b.hasAttribute('data-rep')) { b.addEventListener('click', e => { e.stopPropagation(); buzz(); fire(a); }); return; }
  let delay = 0, timer = 0, busy = false;
  const tick = () => { if (busy) return; busy = true; post({a}).catch(()=>{}).finally(() => { busy = false; refresh(); }); };
  const stop = () => { clearTimeout(delay); clearInterval(timer); b.classList.remove('held'); };
  b.addEventListener('pointerdown', e => {
    e.preventDefault(); b.setPointerCapture(e.pointerId); b.classList.add('held'); buzz(); tick();
    delay = setTimeout(() => { timer = setInterval(tick, 140); }, 400);
  });
  ['pointerup', 'pointercancel', 'lostpointercapture'].forEach(ev => b.addEventListener(ev, stop));
  b.addEventListener('contextmenu', e => e.preventDefault());
});

// typing
const t = $('t');
let sentTimer = 0;
const send = () => {
  if (!t.value) return;
  post({a:'type', text:t.value}).then(r => { if (r.ok) { $('sent').classList.add('show'); clearTimeout(sentTimer); sentTimer = setTimeout(() => $('sent').classList.remove('show'), 1200); } }).catch(()=>{});
  t.value = ''; buzz();
};
$('s').onclick = send;
t.onkeydown = e => { if (e.key === 'Enter') { e.preventDefault(); send(); } };

// mode switch (remembered on this phone)
const MODES = ['pad', 'dpad', 'kb'];
function mode(m, user) {
  MODES.forEach((k, i) => {
    document.querySelector('[data-mode="' + k + '"]').classList.toggle('on', k === m);
    $('v-' + k).classList.toggle('on', k === m);
    if (k === m) $('pill').style.transform = 'translateX(' + (i * 100) + '%)';
  });
  store.set('mode', m);
  if (m === 'kb' && user) t.focus(); else t.blur();
}
document.querySelectorAll('[data-mode]').forEach(b => b.onclick = () => { buzz(); mode(b.dataset.mode, true); });
mode(MODES.includes(store.get('mode')) ? store.get('mode') : 'pad');

// touchpad: 1 finger moves/taps, 2 fingers scroll/tap = right click
const pad = $('pad');
const pts = new Map(); // pointerId -> [x, y]
let mx = 0, my = 0, sx = 0, sy = 0, moved = 0, multi = false, began = 0, sending = false;
async function flush() {
  if (sending) return;
  let m = null;
  if (mx || my) { m = {a:'move', dx:mx*SPEED, dy:my*SPEED}; mx = my = 0; }
  else if (sx || sy) { m = {a:'scroll', dx:sx*SCROLL, dy:sy*SCROLL}; sx = sy = 0; }
  if (!m) return;
  sending = true;
  try { await post(m); } catch (e) {} finally { sending = false; flush(); }
}
pad.onpointerdown = e => {
  if (!pts.size) { moved = 0; multi = false; began = Date.now(); }
  pts.set(e.pointerId, [e.clientX, e.clientY]);
  if (pts.size > 1) multi = true;
  pad.classList.add('down', 'used'); pad.setPointerCapture(e.pointerId);
};
pad.onpointermove = e => {
  const last = pts.get(e.pointerId); if (!last) return;
  const x = e.clientX - last[0], y = e.clientY - last[1];
  pts.set(e.pointerId, [e.clientX, e.clientY]);
  moved += Math.abs(x) + Math.abs(y);
  if (pts.size > 1) { sx += x / pts.size; sy += y / pts.size; }  // average of the fingers
  else if (!multi) { mx += x; my += y; }                           // ignore the last finger lifting off a scroll
  flush();
};
pad.onpointerup = pad.onpointercancel = e => {
  if (!pts.delete(e.pointerId)) return;
  if (pts.size) return;
  pad.classList.remove('down');
  const quick = Date.now() - began < 350;
  if (!multi && moved < 6) { buzz(); fire('click'); }
  else if (multi && moved < 14 && quick) { buzz(); fire('rclick'); }
};
</script></body></html>"""

def selftest():
    import tempfile, threading, urllib.request, urllib.error
    global DIR
    DIR = tempfile.mkdtemp()
    tok = "test-token-123"
    started = threading.Event()
    srv_box = []
    threading.Thread(target=serve, kwargs=dict(port=0, token=tok,
                     ready=lambda s: (srv_box.append(s), started.set())), daemon=True).start()
    assert started.wait(15), "server did not start"
    base = "https://127.0.0.1:%d" % srv_box[0].server_address[1]
    ctx = ssl._create_unverified_context()

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), NoRedirect)

    def status(path, data=None, cookie=None):
        req = urllib.request.Request(base + path, data=data)
        if cookie:
            req.add_header("Cookie", cookie)
        try:
            r = opener.open(req, timeout=5)
            return r.status, r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.headers

    act = json.dumps({"a": "nope"}).encode()
    assert status("/")[0] == 403, "no token must be rejected"
    assert status("/?t=wrong")[0] == 403, "bad token must be rejected"
    assert status("/", cookie="rt=wrong")[0] == 403, "bad cookie must be rejected"
    assert status("/act", act)[0] == 403, "POST without cookie must be rejected"
    assert status("/act", act, "rt=wrong")[0] == 403, "POST with bad cookie must be rejected"
    code, hdrs = status("/?t=" + tok)
    assert code == 303 and "HttpOnly" in hdrs["Set-Cookie"] and "Secure" in hdrs["Set-Cookie"]
    assert status("/", cookie="rt=" + tok)[0] == 200, "good cookie must get the page"
    assert status("/act", act, "rt=" + tok)[0] == 400, "unknown action must be refused"
    assert status("/act", b"not json", "rt=" + tok)[0] == 400
    import re
    buttons = set(re.findall(r'data-a="(\w+)"', PAGE))
    assert buttons <= set(ACTIONS) | {"click", "rclick"}, buttons - set(ACTIONS)
    bad = json.dumps({"a": "move", "dx": "nan", "dy": 0}).encode()
    assert status("/act", bad, "rt=" + tok)[0] == 400, "NaN delta must be refused"
    bad = json.dumps({"a": "setvol", "v": "1; do shell script \"x\""}).encode()
    assert status("/act", bad, "rt=" + tok)[0] == 400, "non-numeric volume must be refused"
    disps = [(0, 0, 1440, 900, True), (1440, -200, 1920, 1080, False), (-1920, 0, 1920, 1080, False)]
    assert screen_label(100, 100, disps) == "MacBook"
    assert screen_label(2000, 0, disps) == "Monitor"
    assert screen_label(-10, 10, disps) == "Monitor 2"
    assert screen_label(99999, 0, disps) == ""
    srv_box[0].shutdown()
    print("selftest OK")

if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
    elif "--qr" in sys.argv:
        show_qr()
    else:
        serve()
