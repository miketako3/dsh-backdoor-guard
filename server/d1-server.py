#!/usr/bin/env python3
"""systemone-compatible local judge server for LiquidAI d1-3B (or d1-omni-600M).

Exposes POST /v1/systemone with the same Decision Index wire contract as the
hosted Jev API, so dsh-backdoor-guard can switch between hosted Jev and a
local d1 by changing only `endpoint` / `model` / `apiKeyEnv` (empty).

Usage:
    pip install "transformers>=5.14" torch torchvision pillow
    python3 d1-server.py [--model LiquidAI/d1-3B] [--host 127.0.0.1] [--port 8400]

Request:  {"state": "...", "model": "d1-3B", "questions": {"k": {"type": "noul", "instructions": "..."}}}
Response: {"model": "...", "answers": {"k": {"type": "noul", "noul": 0.97}}, "usage": {...}}
"""
import argparse
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL_LOCK = threading.Lock()
model = None
model_id = ""


def load_model(name: str):
    global model, model_id
    import torch
    from transformers import AutoModel

    device = "cuda" if torch.cuda.is_available() else "mps" if torch.backends.mps.is_available() else "cpu"
    dtype = torch.float32 if device == "cpu" else torch.bfloat16
    model = AutoModel.from_pretrained(name, trust_remote_code=True, dtype=dtype).to(device)
    model_id = name
    # Warm the hot shape so the first guarded call does not pay kernel selection.
    model.system_one("warmup", {"warmup": {"type": "noul", "instructions": "Is this a warmup?"}})
    print(f"[d1-server] {name} ready on {device}", flush=True)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quiet per-request logs; errors still print
        pass

    def _send(self, status: int, body: dict):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"ok": model is not None, "model": model_id})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path not in ("/v1/systemone", "/systemone"):
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length))
            state = body["state"]
            questions = body["questions"]
            with MODEL_LOCK:
                result = model.system_one(state, questions)
            self._send(200, {
                "model": model_id,
                "answers": result["answers"],
                "usage": result.get("usage", {}),
            })
        except Exception as error:  # noqa: BLE001 — the guard treats any 500 as judge failure
            self._send(500, {"error": f"{type(error).__name__}: {error}"})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="LiquidAI/d1-3B")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8400)
    args = parser.parse_args()
    load_model(args.model)
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[d1-server] listening on http://{args.host}:{args.port}/v1/systemone", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
