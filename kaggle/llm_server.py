"""Kaggle GPU LLM server cho Strix (chay nhu 1 Kaggle Script kernel, GPU T4 x2, Internet ON).

  Ollama (GPU)  <-  auth proxy :8000 (Bearer key)  <-  Cloudflare quick tunnel (HTTPS)  <-  Strix tren may local

Gia tri __PLACEHOLDER__ duoc scripts/kaggle_llm.sh thay the truoc khi push (kernel de PRIVATE).
URL tunnel duoc in ra log voi tien to TUNNEL_URL= de script local doc qua `kaggle kernels logs`.
Kernel tu tat sau MAX_HOURS, hoac khi local goi POST /__stop (kem key).
"""

import os
import re
import subprocess
import sys
import threading
import time
import urllib.request

API_KEY = "__API_KEY__"
MODELS = "__MODELS__".split(",")          # model dau tien = model chinh cho Strix
MAX_HOURS = float("__MAX_HOURS__")
CTX = int("__CTX__")
PARALLEL = "__PARALLEL__"        # so request dong thoi / model (32B: 1 de vua VRAM)
MAX_LOADED = "__MAX_LOADED__"    # so model giu tren GPU cung luc (32B: 1 -> judge swap khi can)
T0 = time.time()


def log(*a):
    print(f"[{time.time() - T0:7.1f}s]", *a, flush=True)


def sh(cmd, **kw):
    log("$", cmd)
    return subprocess.run(cmd, shell=True, check=True, **kw)


# ---------------------------------------------------------------- 1. GPU + Ollama
sh("nvidia-smi --query-gpu=name,memory.total --format=csv")
if subprocess.run("which ollama", shell=True).returncode != 0:
    sh("apt-get install -y -qq zstd >/dev/null 2>&1 || true")
    sh("curl -fsSL https://ollama.com/install.sh | sh > /tmp/ollama_install.log 2>&1")

env = dict(os.environ,
           OLLAMA_HOST="127.0.0.1:11434",
           OLLAMA_CONTEXT_LENGTH=str(CTX),
           OLLAMA_NUM_PARALLEL=PARALLEL,
           OLLAMA_MAX_LOADED_MODELS=MAX_LOADED,
           OLLAMA_SCHED_SPREAD="1",          # chia model ra ca 2 GPU T4
           OLLAMA_FLASH_ATTENTION="1",
           OLLAMA_KV_CACHE_TYPE="q8_0",      # giam 1/2 VRAM cho KV cache
           OLLAMA_KEEP_ALIVE="-1")
ollama = subprocess.Popen(["ollama", "serve"], env=env, stdout=open("/tmp/ollama.log", "w"), stderr=subprocess.STDOUT)
for _ in range(60):
    try:
        urllib.request.urlopen("http://127.0.0.1:11434/api/version", timeout=2)
        break
    except Exception:
        time.sleep(1)
for m in MODELS:
    sh(f"ollama pull {m} 2>&1 | tail -1")
for m in reversed(MODELS):   # nap model chinh SAU CUNG -> no nam san tren GPU khi MAX_LOADED=1
    t = time.time()
    sh(f"ollama run {m} 'Reply with OK' --nowordwrap 2>&1 | tail -2")
    log(f"warm-up {m}: {time.time() - t:.1f}s")
sh("ollama ps")

# ---------------------------------------------------------------- 2. Auth proxy (aiohttp, ho tro streaming)
PROXY = r'''
# Cloudflare quick tunnel cat ket noi neu origin im lang > ~100s (loi 524).
# Model 32B tren T4 can >100s de xu ly prompt dai cua Strix -> proxy gui "nhip tim" trong luc cho:
#   - stream OpenAI (SSE): dong comment ": keepalive" (client SSE bo qua)
#   - non-stream JSON    : khoang trang truoc JSON (json parser bo qua)
import asyncio, json, os, aiohttp
from aiohttp import web
KEY = os.environ["PROXY_KEY"]; UP = "http://127.0.0.1:11434"; BEAT = 15
async def handle(req):
    if req.headers.get("Authorization", "") != f"Bearer {KEY}":
        return web.json_response({"error": "unauthorized"}, status=401)
    if req.path == "/__stop":
        open("/tmp/STOP", "w").close(); return web.json_response({"ok": True})
    if req.path == "/__health":
        return web.json_response({"ok": True})
    body = await req.read()
    native = req.path.startswith("/api/")
    try:
        j = json.loads(body) if body else {}
    except Exception:
        j = {}
    stream = bool(j.get("stream", native))
    beat = b": keepalive\n\n" if (stream and not native) else (b"\n" if stream else b" ")
    ctype = "text/event-stream" if (stream and not native) else ("application/x-ndjson" if stream else "application/json")
    hdr = {k: v for k, v in req.headers.items() if k.lower() not in ("host", "authorization", "content-length")}
    s = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=None, sock_read=1800))
    try:
        fut = asyncio.ensure_future(s.request(req.method, UP + req.path_qs, data=body, headers=hdr))
        try:   # loi nhanh (model khong ton tai...) -> tra dung status
            await asyncio.wait_for(asyncio.shield(fut), 8)
        except asyncio.TimeoutError:
            pass
        status = fut.result().status if fut.done() and not fut.exception() else 200
        resp = web.StreamResponse(status=status, headers={"Content-Type": ctype, "Cache-Control": "no-cache"})
        await resp.prepare(req)
        while not fut.done():
            try:
                await asyncio.wait_for(asyncio.shield(fut), BEAT)
            except asyncio.TimeoutError:
                await resp.write(beat)
        up = fut.result()
        it = up.content.iter_any().__aiter__()
        started = False
        while True:
            nxt = asyncio.ensure_future(it.__anext__())
            while True:
                try:
                    chunk = await asyncio.wait_for(asyncio.shield(nxt), BEAT)
                    break
                except asyncio.TimeoutError:
                    if stream or not started:
                        await resp.write(beat)
                except StopAsyncIteration:
                    chunk = None
                    break
            if chunk is None:
                break
            started = True
            await resp.write(chunk)
        await resp.write_eof()
        return resp
    finally:
        await s.close()
app = web.Application(client_max_size=64 * 1024 * 1024)
app.router.add_route("*", "/{tail:.*}", handle)
web.run_app(app, host="127.0.0.1", port=8000, print=None)
'''
open("/tmp/proxy.py", "w").write(PROXY)
proxy = subprocess.Popen([sys.executable, "/tmp/proxy.py"], env=dict(os.environ, PROXY_KEY=API_KEY),
                         stdout=open("/tmp/proxy.log", "w"), stderr=subprocess.STDOUT)
time.sleep(3)

# ---------------------------------------------------------------- 3. Cloudflare quick tunnel
sh("curl -fsSL -o /tmp/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 && chmod +x /tmp/cloudflared")
tun = subprocess.Popen(["/tmp/cloudflared", "tunnel", "--no-autoupdate", "--url", "http://127.0.0.1:8000"],
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
url = None
for line in tun.stdout:
    m = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", line)
    if m:
        url = m.group(0)
        break
if not url:
    sys.exit("Khong lay duoc URL tunnel")
log(f"TUNNEL_URL={url}")
log(f"MODELS={','.join(MODELS)} CTX={CTX}")


# ---------------------------------------------------------------- 4. Giu kernel song
threading.Thread(target=lambda: [None for _ in tun.stdout], daemon=True).start()  # tranh day pipe

deadline = T0 + MAX_HOURS * 3600
while time.time() < deadline and not os.path.exists("/tmp/STOP"):
    for p, name in ((ollama, "ollama"), (proxy, "proxy"), (tun, "tunnel")):
        if p.poll() is not None:
            log(f"!! {name} da dung (code {p.returncode})")
            sys.exit(1)
    time.sleep(30)
    if int(time.time() - T0) % 600 < 30:
        log(f"alive, TUNNEL_URL={url}")
log("Dung server.")
for p in (tun, proxy, ollama):
    p.terminate()
