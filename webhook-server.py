#!/usr/bin/env python3
"""EDIT 2510 WhatsApp Cloud API webhook receiver (stdlib only).

Designed to run on a small cloud host (Render free tier preferred).

  GET  /                                   -> 200 "ok" (health check)
  GET  /webhook?hub.mode=subscribe&hub.verify_token=...&hub.challenge=...
       -> returns hub.challenge verbatim when the token matches.
  POST /webhook -> logs the payload (parsed messages + raw JSON) to
       whatsapp-webhook-inbox.jsonl and to stdout, returns 200 quickly.
       No auto-reply here; replies are sent by Muse (which polls the
       inbox, see GET /inbox below) via the WhatsApp API.
  GET  /inbox?key=<WHATSAPP_VERIFY_TOKEN> -> last inbox entries as JSON
       (for Muse polling only; protected by the same secret token).

Configuration (environment variables):
  WHATSAPP_VERIFY_TOKEN  required on the host (Render: set it in the
                         dashboard under Environment; never commit it).
                         Locally, the server falls back to reading
                         webhook-verify-token.txt next to this file.
  PORT                   set automatically by Render (default 10000).
                         WEBHOOK_PORT is accepted as a fallback.
  WHATSAPP_APP_SECRET    optional; when set, POST signatures
                         (X-Hub-Signature-256) are verified.

Note: on Render's free tier the local filesystem is ephemeral, so the
.jsonl file is a convenience only. The authoritative record is stdout
(Render > Logs) and the /inbox endpoint above.
"""
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
INBOX = os.path.join(HERE, "whatsapp-webhook-inbox.jsonl")
TOKEN_FILE = os.path.join(HERE, "webhook-verify-token.txt")

# Render injects PORT; local default is 8787.
PORT = int(os.environ.get("PORT", os.environ.get("WEBHOOK_PORT", "8787")))

VERIFY_TOKEN = os.environ.get("WHATSAPP_VERIFY_TOKEN", "").strip()
if not VERIFY_TOKEN and os.path.exists(TOKEN_FILE):
    with open(TOKEN_FILE) as f:
        VERIFY_TOKEN = f.read().strip()
if not VERIFY_TOKEN:
    sys.stderr.write(
        "ERROR: set WHATSAPP_VERIFY_TOKEN (or place "
        "webhook-verify-token.txt next to this file).\n")
    sys.exit(1)

APP_SECRET = os.environ.get("WHATSAPP_APP_SECRET", "").strip()


def log_event(kind, data):
    rec = {
        "received_at_utc": datetime.now(timezone.utc).isoformat(),
        "kind": kind,
        "data": data,
    }
    # Stdout is the durable log on a cloud host (Render > Logs).
    print(json.dumps(rec, ensure_ascii=False), flush=True)
    try:
        with open(INBOX, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass  # filesystem may be read-only/ephemeral; stdout already has it


def read_inbox(limit=20):
    try:
        with open(INBOX, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-limit:]:
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def extract_messages(payload):
    out = []
    try:
        for entry in payload.get("entry", []):
            for change in entry.get("changes", []):
                value = change.get("value", {})
                for msg in value.get("messages", []):
                    text = ""
                    if msg.get("type") == "text":
                        text = msg.get("text", {}).get("body", "")
                    out.append({
                        "from": msg.get("from"),
                        "message_id": msg.get("id"),
                        "timestamp": msg.get("timestamp"),
                        "type": msg.get("type"),
                        "text": text,
                    })
                for status in value.get("statuses", []):
                    out.append({
                        "status_update": True,
                        "message_id": status.get("id"),
                        "status": status.get("status"),
                        "recipient": status.get("recipient_id"),
                    })
    except Exception as e:  # noqa: BLE001 - never crash the webhook
        out.append({"parse_error": str(e)})
    return out


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # keep stdout clean; events go to jsonl
        sys.stderr.write("[webhook] " + fmt % args + "\n")

    def _send(self, code, body, ctype="text/plain"):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, code, obj):
        self._send(code, json.dumps(obj, ensure_ascii=False), "application/json")

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            return self._send(200, "EDIT 2510 WhatsApp webhook is up.\n")
        if parsed.path == "/inbox":
            qs = parse_qs(parsed.query)
            if qs.get("key", [""])[0] != VERIFY_TOKEN:
                return self._send(403, "forbidden\n")
            try:
                limit = max(1, min(100, int(qs.get("limit", ["20"])[0])))
            except ValueError:
                limit = 20
            return self._send_json(200, {"entries": read_inbox(limit)})
        if parsed.path != "/webhook":
            return self._send(404, "not found\n")
        qs = parse_qs(parsed.query)
        mode = qs.get("hub.mode", [""])[0]
        token = qs.get("hub.verify_token", [""])[0]
        challenge = qs.get("hub.challenge", [""])[0]
        if mode == "subscribe" and token == VERIFY_TOKEN and challenge:
            return self._send(200, challenge)
        return self._send(403, "verification failed\n")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/webhook":
            return self._send(404, "not found\n")
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        if APP_SECRET:
            sig = self.headers.get("X-Hub-Signature-256", "")
            expected = "sha256=" + hmac.new(
                APP_SECRET.encode(), body, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(sig, expected):
                return self._send(403, "bad signature\n")
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except Exception:  # noqa: BLE001
            payload = {"raw_unparseable": body.decode("utf-8", "replace")}
        log_event("whatsapp_webhook", {
            "messages": extract_messages(payload),
            "payload": payload,
        })
        return self._send(200, "OK\n")


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
