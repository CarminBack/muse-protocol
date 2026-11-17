"""Small authenticated control panel for the single-account example flow."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.environ.get("MUSE_CONFIG", ROOT / "config.json"))
OUTPUT_DIR = Path(os.environ.get("MUSE_OUTPUT", ROOT / "output"))
PASSWORD = os.environ.get("MUSE_WEB_PASSWORD", "")
PORT = int(os.environ.get("MUSE_WEB_PORT", "3098"))
SESSION_TTL = 12 * 60 * 60

sessions: dict[str, float] = {}
state_lock = threading.Lock()
state = {
    "status": "idle",
    "started_at": None,
    "finished_at": None,
    "exit_code": None,
    "logs": [],
    "process": None,
}


def json_response(handler, payload, status=HTTPStatus.OK):
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def load_config():
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_config(data):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp = CONFIG_PATH.with_suffix(".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(temp, 0o600)
    temp.replace(CONFIG_PATH)


def public_config():
    config = load_config()
    proxy = config.get("proxy") or ""
    config["proxy"] = "" if proxy else ""
    config["proxy_set"] = bool(proxy)
    return config


def append_log(line):
    with state_lock:
        state["logs"].append(line.rstrip("\n"))
        state["logs"] = state["logs"][-300:]
        if "输入收到的 6 位验证码" in line:
            state["status"] = "waiting_otp"


def stream_process(process):
    try:
        for line in process.stdout:
            append_log(line)
    finally:
        code = process.wait()
        with state_lock:
            state["exit_code"] = code
            state["finished_at"] = time.time()
            state["status"] = "succeeded" if code == 0 else "failed"
            state["process"] = None


def authorized(handler):
    cookie = SimpleCookie(handler.headers.get("Cookie", ""))
    token = cookie.get("session")
    if not token:
        return False
    expiry = sessions.get(token.value)
    if not expiry or expiry < time.time():
        sessions.pop(token.value, None)
        return False
    return True


class Handler(BaseHTTPRequestHandler):
    server_version = "MuseConsole/1.0"

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        if self.path == "/healthz":
            json_response(self, {"ok": True})
            return
        if self.path == "/api/session":
            json_response(self, {"authenticated": authorized(self)})
            return
        if self.path == "/":
            self.serve_file(ROOT / "web" / "index.html", "text/html; charset=utf-8")
            return
        if self.path == "/app.css":
            self.serve_file(ROOT / "web" / "app.css", "text/css; charset=utf-8")
            return
        if self.path == "/app.js":
            self.serve_file(ROOT / "web" / "app.js", "application/javascript; charset=utf-8")
            return
        if not authorized(self):
            json_response(self, {"error": "登录已过期"}, HTTPStatus.UNAUTHORIZED)
            return
        if self.path == "/api/config":
            json_response(self, public_config())
        elif self.path == "/api/status":
            with state_lock:
                payload = {key: value for key, value in state.items() if key != "process"}
            json_response(self, payload)
        else:
            self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self):
        if self.path == "/api/login":
            payload = self.read_json()
            supplied = str(payload.get("password", ""))
            if not PASSWORD or not hmac.compare_digest(supplied, PASSWORD):
                json_response(self, {"error": "密码不正确"}, HTTPStatus.UNAUTHORIZED)
                return
            token = secrets.token_urlsafe(32)
            sessions[token] = time.time() + SESSION_TTL
            body = {"ok": True}
            encoded = json.dumps(body).encode()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", f"session={token}; Max-Age={SESSION_TTL}; HttpOnly; SameSite=Strict; Secure; Path=/")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return
        if not authorized(self):
            json_response(self, {"error": "登录已过期"}, HTTPStatus.UNAUTHORIZED)
            return
        if self.path == "/api/config":
            payload = self.read_json()
            email = str(payload.get("email", "")).strip()
            if "@" not in email:
                json_response(self, {"error": "请输入有效邮箱"}, HTTPStatus.BAD_REQUEST)
                return
            current = load_config()
            allowed = ("email", "proxy", "invite_code", "lang", "impersonate",
                       "first_name", "last_name", "date_of_birth", "send_caa", "send_falco")
            for key in allowed:
                if key in payload:
                    current[key] = payload[key]
            current["otp_file"] = ""
            current.setdefault("invite_code", "")
            try:
                save_config(current)
            except OSError:
                json_response(self, {"error": "配置保存失败，请检查服务器配置目录的写入权限"},
                              HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            json_response(self, {"ok": True, **public_config()})
        elif self.path == "/api/start":
            with state_lock:
                if state["process"] is not None:
                    json_response(self, {"error": "已有任务正在运行"}, HTTPStatus.CONFLICT)
                    return
                config = load_config()
                if "@" not in str(config.get("email", "")):
                    json_response(self, {"error": "请先保存邮箱配置"}, HTTPStatus.BAD_REQUEST)
                    return
                process = subprocess.Popen(
                    [sys.executable, "example_register.py"], cwd=ROOT,
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, bufsize=1,
                )
                state.update(status="starting", started_at=time.time(), finished_at=None,
                             exit_code=None, logs=[], process=process)
            threading.Thread(target=stream_process, args=(process,), daemon=True).start()
            json_response(self, {"ok": True})
        elif self.path == "/api/otp":
            payload = self.read_json()
            code = str(payload.get("code", "")).strip()
            if not code.isdigit() or len(code) != 6:
                json_response(self, {"error": "验证码必须是 6 位数字"}, HTTPStatus.BAD_REQUEST)
                return
            with state_lock:
                process = state["process"]
                if state["status"] != "waiting_otp" or process is None or process.stdin is None:
                    json_response(self, {"error": "当前没有等待验证码的任务"}, HTTPStatus.CONFLICT)
                    return
                process.stdin.write(code + "\n")
                process.stdin.flush()
                state["status"] = "running"
            json_response(self, {"ok": True})
        elif self.path == "/api/stop":
            with state_lock:
                process = state["process"]
                if process is not None:
                    process.terminate()
                    state["status"] = "stopping"
            json_response(self, {"ok": True})
        else:
            json_response(self, {"error": "Not found"}, HTTPStatus.NOT_FOUND)

    def read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length > 100_000:
            raise ValueError("payload_too_large")
        return json.loads(self.rfile.read(length) or b"{}")

    def serve_file(self, path, content_type):
        try:
            body = path.read_bytes()
        except OSError:
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    if not PASSWORD:
        raise SystemExit("MUSE_WEB_PASSWORD is required")
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
