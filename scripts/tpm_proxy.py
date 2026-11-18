#!/usr/bin/env python3
"""Proxy dieu tiet TPM: dat giua Strix va Gemini, gian request de khong vuot token/phut.

Strix (LiteLLM, api_base=http://127.0.0.1:8787) -> proxy -> Gemini (generativelanguage.googleapis.com)

Proxy trong suot: chuyen tiep nguyen header+body (LiteLLM da gan key san), chi them:
  - Hang doi theo ngan sach token/phut: uoc luong token moi request = len(body)/4 + reserve,
    neu tong token trong cua so 60s vuot BUDGET thi cho den khi co cho -> khong con 429.
  - Gioi han so request dong thoi.

Chay:  python scripts/tpm_proxy.py   (lang nghe 127.0.0.1:8787)
Env:   TPM_BUDGET (mac dinh 850000, duoi tran 1M), TPM_CONCURRENCY (4), TPM_PORT (8787)
"""
import asyncio, os, time, collections
import aiohttp
from aiohttp import web

UPSTREAM = "https://generativelanguage.googleapis.com"
BUDGET = int(os.environ.get("TPM_BUDGET", "850000"))      # token/phut cho phep (margin duoi 1M)
CONCURRENCY = int(os.environ.get("TPM_CONCURRENCY", "4"))
PORT = int(os.environ.get("TPM_PORT", "8787"))
OUTPUT_RESERVE = 3000                                      # du phong token dau ra moi request

_window = collections.deque()   # (timestamp, tokens)
_wlock = asyncio.Lock()
_sem = asyncio.Semaphore(CONCURRENCY)
_stats = {"req": 0, "waited_s": 0.0, "max_window": 0}


def _window_tokens(now):
    while _window and now - _window[0][0] > 60:
        _window.popleft()
    return sum(t for _, t in _window)


async def _reserve(est):
    """Cho den khi them `est` token khong vuot BUDGET trong cua so 60s."""
    while True:
        async with _wlock:
            now = time.time()
            used = _window_tokens(now)
            if used + est <= BUDGET or not _window:
                _window.append((now, est))
                _stats["max_window"] = max(_stats["max_window"], used + est)
                return
            wait = max(0.2, 60 - (now - _window[0][0]))
        _stats["waited_s"] += wait
        await asyncio.sleep(min(wait, 2.0))


async def handle(req):
    body = await req.read()
    est = len(body) // 4 + OUTPUT_RESERVE          # uoc luong token (ky tu/4)
    await _reserve(est)
    _stats["req"] += 1
    hdr = {k: v for k, v in req.headers.items() if k.lower() not in ("host", "content-length", "connection")}
    url = UPSTREAM + req.path_qs
    async with _sem:
        timeout = aiohttp.ClientTimeout(total=None, sock_connect=30, sock_read=900)
        async with aiohttp.ClientSession(timeout=timeout) as s:
            async with s.request(req.method, url, data=body, headers=hdr) as up:
                resp = web.StreamResponse(status=up.status, headers={
                    k: v for k, v in up.headers.items()
                    if k.lower() not in ("transfer-encoding", "content-encoding", "content-length", "connection")})
                await resp.prepare(req)
                async for chunk in up.content.iter_any():
                    await resp.write(chunk)
                await resp.write_eof()
                return resp


async def health(req):
    now = time.time()
    return web.json_response({"ok": True, "budget": BUDGET, "window_tokens": _window_tokens(now), **_stats})


def main():
    app = web.Application(client_max_size=256 * 1024 * 1024)
    app.router.add_get("/__health", health)
    app.router.add_route("*", "/{tail:.*}", handle)
    print(f"[tpm_proxy] 127.0.0.1:{PORT} -> {UPSTREAM} | budget={BUDGET} tok/60s | concurrency={CONCURRENCY}", flush=True)
    web.run_app(app, host="127.0.0.1", port=PORT, print=None)


if __name__ == "__main__":
    main()
