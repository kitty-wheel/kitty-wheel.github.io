#!/usr/bin/env python3
"""kitty-wheel 打卡后端：只用 Python 标准库，不用装别的。

数据：/opt/kitty-wheel/data/checkins.json，照片：/opt/kitty-wheel/data/photos/
口令：环境变量 KW_PASS，每个请求都要带请求头 X-Pass
只监听本机 127.0.0.1:8787，外面由 Caddy / nginx 加 https 转进来
"""
import json, os, re, threading, time, hmac
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

PASS = os.environ.get("KW_PASS", "")
DATA = os.environ.get("KW_DATA", "/opt/kitty-wheel/data")
ORIGINS = {"https://kitty-wheel.github.io"}
PORT = int(os.environ.get("KW_PORT", "8787"))
MAX_PHOTO = 4 * 1024 * 1024
MAX_PHOTOS = 6

os.makedirs(os.path.join(DATA, "photos"), exist_ok=True)
DB = os.path.join(DATA, "checkins.json")
lock = threading.Lock()
ID = re.compile(r"^[A-Za-z0-9-]{6,40}$")


def load():
    try:
        with open(DB, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save(db):
    tmp = DB + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(db, f, ensure_ascii=False)
    os.replace(tmp, DB)


class H(BaseHTTPRequestHandler):
    server_version = "kw/1"

    def log_message(self, *a):
        pass

    # ---------- helpers ----------
    def cors(self):
        o = self.headers.get("Origin", "")
        if o in ORIGINS:
            self.send_header("Access-Control-Allow-Origin", o)
            self.send_header("Vary", "Origin")
            self.send_header("Access-Control-Allow-Headers", "X-Pass, Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            self.send_header("Access-Control-Max-Age", "86400")

    def reply(self, code, obj=None, body=None, ctype="application/json"):
        if obj is not None:
            body = json.dumps(obj, ensure_ascii=False).encode()
        body = body or b""
        self.send_response(code)
        self.cors()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, max-age=86400" if ctype.startswith("image/") else "no-store")
        self.end_headers()
        self.wfile.write(body)

    def authed(self):
        if not PASS or not hmac.compare_digest(self.headers.get("X-Pass", ""), PASS):
            time.sleep(0.5)
            self.reply(401, {"error": "口令不对"})
            return False
        return True

    def body(self, limit):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > limit:
            return None
        return self.rfile.read(n)

    # ---------- routes ----------
    def do_OPTIONS(self):
        self.reply(204)

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/api/ping":
            return self.reply(200, {"ok": True})
        if not self.authed():
            return
        if p == "/api/checkins":
            with lock:
                db = load()
            return self.reply(200, sorted(db.values(), key=lambda e: -e["time"]))
        m = re.match(r"^/api/photos/([A-Za-z0-9-]+)-(\d)\.jpg$", p)
        if m and ID.match(m.group(1)):
            f = os.path.join(DATA, "photos", f"{m.group(1)}-{m.group(2)}.jpg")
            if os.path.exists(f):
                with open(f, "rb") as fh:
                    return self.reply(200, body=fh.read(), ctype="image/jpeg")
        self.reply(404, {"error": "没有"})

    def do_POST(self):
        if urlparse(self.path).path != "/api/checkins":
            return self.reply(404, {"error": "没有"})
        if not self.authed():
            return
        raw = self.body(20000)
        try:
            e = json.loads(raw or b"")
            assert ID.match(e["id"])
            rec = {
                "id": e["id"],
                "place": str(e["place"])[:60],
                "text": str(e.get("text", ""))[:500],
                "who": str(e.get("who", ""))[:12],
                "time": int(e["time"]),
                "photos": max(0, min(MAX_PHOTOS, int(e.get("photos", 0)))),
            }
        except Exception:
            return self.reply(400, {"error": "格式不对"})
        with lock:
            db = load()
            db[rec["id"]] = rec
            save(db)
        self.reply(200, rec)

    def do_PUT(self):
        m = re.match(r"^/api/checkins/([A-Za-z0-9-]+)/photos/(\d)$", urlparse(self.path).path)
        if not m or not ID.match(m.group(1)) or int(m.group(2)) >= MAX_PHOTOS:
            return self.reply(404, {"error": "没有"})
        if not self.authed():
            return
        data = self.body(MAX_PHOTO)
        if not data or data[:3] != b"\xff\xd8\xff":
            return self.reply(400, {"error": "只收 jpg"})
        with open(os.path.join(DATA, "photos", f"{m.group(1)}-{m.group(2)}.jpg"), "wb") as fh:
            fh.write(data)
        self.reply(200, {"ok": True})

    def do_DELETE(self):
        m = re.match(r"^/api/checkins/([A-Za-z0-9-]+)$", urlparse(self.path).path)
        if not m or not ID.match(m.group(1)):
            return self.reply(404, {"error": "没有"})
        if not self.authed():
            return
        with lock:
            db = load()
            db.pop(m.group(1), None)
            save(db)
        for i in range(MAX_PHOTOS):
            try:
                os.remove(os.path.join(DATA, "photos", f"{m.group(1)}-{i}.jpg"))
            except FileNotFoundError:
                pass
        self.reply(200, {"ok": True})


if __name__ == "__main__":
    if not PASS:
        raise SystemExit("请先设置 KW_PASS")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
