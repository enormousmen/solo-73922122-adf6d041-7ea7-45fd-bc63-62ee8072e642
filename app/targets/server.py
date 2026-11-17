"""演示用目标 Web 服务。

同一进程监听：
* 8080/tcp HTTP（允许目标 172.31.10.10 与禁止目标 172.31.20.10 都运行本服务）；
* 8443/tcp HTTPS（使用受信演示 CA 签发的证书，含全部演示域名 SAN）；
* 8090/tcp 原始可控目标（裸 TCP，完全控制响应字节与连接行为，
  用于演示保活、断流、分块、长度冲突等 HTTP/1.1 响应完整性场景）。

按 Host 头提供不同路径行为：正常 200、跳转至允许/禁止目标、跳转链、
回显请求来源等。``/_requests`` 记录本进程收到的请求，供演示脚本验证
“被策略拒绝的目标从未收到探测请求”。
"""

from __future__ import annotations

import asyncio
import os
import time
from collections import deque

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse

CERT_DIR = os.getenv("CERT_DIR", "/app/certs")
RECENT_REQUESTS: deque[dict] = deque(maxlen=200)

app = FastAPI(title="demo-targets", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def record_requests(request: Request, call_next):
    RECENT_REQUESTS.appendleft(
        {
            "ts": round(time.time(), 3),
            "method": request.method,
            "host": request.headers.get("host"),
            "path": request.url.path,
            "peer": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
        }
    )
    return await call_next(request)


@app.get("/")
async def root(request: Request):
    return JSONResponse(
        {
            "service": "demo-targets",
            "host": request.headers.get("host"),
            "peer": request.client.host if request.client else None,
            "tls": request.url.scheme == "https",
            "message": "目标可达",
        }
    )


@app.get("/healthz")
async def healthz():
    return PlainTextResponse("ok")


@app.get("/_requests")
async def list_requests():
    return JSONResponse(list(RECENT_REQUESTS))


@app.get("/redirect-allowed")
async def redirect_allowed():
    return RedirectResponse(url="http://redirect-final.demo.test/final", status_code=302)


@app.get("/redirect-https")
async def redirect_https():
    return RedirectResponse(
        url="https://https.allowed.demo.test/secure", status_code=302
    )


@app.get("/redirect-forbidden")
async def redirect_forbidden():
    # 跳到禁止网段的目标：探测方必须在第二跳解析校验时拦截
    return RedirectResponse(url="http://forbidden.demo.test/secret", status_code=302)


@app.get("/redirect-scheme")
async def redirect_scheme():
    # 跳到非 HTTP(S) 协议：探测方应拒绝
    return RedirectResponse(url="file:///etc/passwd", status_code=302)


@app.get("/final")
async def final():
    return JSONResponse({"message": "跳转链终点，可达"})


@app.get("/secure")
async def secure(request: Request):
    return JSONResponse(
        {
            "message": "HTTPS 目标可达，证书按原域名验证通过",
            "host": request.headers.get("host"),
            "scheme": request.url.scheme,
        }
    )


# 跳转链：loop1/loop/1 -> loop2/loop/2 -> loop3/loop/3 -> loop4/loop/4 -> loop1 …
@app.get("/loop/{n}")
async def loop_chain(n: int):
    next_n = 1 if n >= 4 else n + 1
    return RedirectResponse(
        url=f"http://loop{next_n}.demo.test/loop/{next_n}",
        status_code=307,
    )


@app.get("/secret")
async def secret():
    return JSONResponse({"message": "禁止网段目标不应被任何探测请求到达"})


# ---------------------------------------------------------------- 原始可控目标
# 裸 TCP 服务器，逐字节控制响应与连接行为，用于演示探测端的
# HTTP/1.1 响应完整性判定：
#   /keepalive           完整响应（Content-Length 正确）后保持连接不关闭
#   /keepalive-redirect  302 + Content-Length: 0 后保持连接（验证及时跟随跳转）
#   /truncated           声明 Content-Length 大于实际发送，随后立即断开
#   /stalled             声明 Content-Length 大于实际发送，随后保持连接（挂起）
#   /chunked             正常分块响应，终止块后保持连接
#   /chunked-bad         非法块大小（分块格式错误）
#   /conflict            同时携带 Content-Length 与 Transfer-Encoding（长度冲突）
#   /no-length           无长度头，正文以连接关闭为界
#   /status/204          204 无正文，响应头后保持连接
#   /status/304          304 无正文，响应头后保持连接
# HEAD 请求一律只发响应头（符合 HTTP 语义），连接行为与 GET 相同。
RAW_BODY = b"egress-probe raw demo target\n"
RAW_KEEPALIVE_SECONDS = float(os.getenv("RAW_KEEPALIVE_SECONDS", "30"))


def _raw_head(status: int, reason: str, headers: list[tuple[str, str]]) -> bytes:
    lines = [f"HTTP/1.1 {status} {reason}\r\n"]
    for key, value in headers:
        lines.append(f"{key}: {value}\r\n")
    lines.append("\r\n")
    return "".join(lines).encode("ascii")


async def _raw_read_request(reader) -> tuple[str, str, dict[str, str]] | None:
    try:
        request_line = await reader.readline()
        if not request_line:
            return None
        parts = request_line.decode("iso-8859-1").split()
        if len(parts) < 2:
            return None
        headers: dict[str, str] = {}
        while True:
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
            key, _, value = line.decode("iso-8859-1").partition(":")
            headers[key.strip().lower()] = value.strip()
    except (ConnectionError, ValueError):
        return None
    return parts[0].upper(), parts[1], headers


async def _raw_handle(reader, writer) -> None:  # noqa: ANN001
    try:
        req = await asyncio.wait_for(_raw_read_request(reader), timeout=10)
        if req is None:
            return
        method, target, headers = req
        path = target.split("?", 1)[0].lower()
        peer = writer.get_extra_info("peername")
        RECENT_REQUESTS.appendleft(
            {
                "ts": round(time.time(), 3),
                "method": method,
                "host": headers.get("host"),
                "path": path,
                "peer": peer[0] if peer else None,
                "user_agent": headers.get("user-agent"),
                "raw": True,
            }
        )
        head_only = method == "HEAD"
        keep_open = False
        if path == "/keepalive":
            head = _raw_head(200, "OK", [("Content-Length", str(len(RAW_BODY)))])
            payload, keep_open = RAW_BODY, True
        elif path == "/keepalive-redirect":
            head = _raw_head(
                302,
                "Found",
                [
                    ("Location", "http://redirect-final.demo.test/final"),
                    ("Content-Length", "0"),
                ],
            )
            payload, keep_open = b"", True
        elif path == "/truncated":
            # 声明长度大于实际发送，随后立即断开：探测端必须报“正文不完整”
            head = _raw_head(
                200, "OK", [("Content-Length", str(len(RAW_BODY) + 32))]
            )
            payload = RAW_BODY
        elif path == "/stalled":
            # 声明长度大于实际发送且保持连接：探测端应在读取超时后报错
            head = _raw_head(
                200, "OK", [("Content-Length", str(len(RAW_BODY) + 32))]
            )
            payload, keep_open = RAW_BODY, True
        elif path == "/chunked":
            head = _raw_head(200, "OK", [("Transfer-Encoding", "chunked")])
            payload, keep_open = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", True
        elif path == "/chunked-bad":
            head = _raw_head(200, "OK", [("Transfer-Encoding", "chunked")])
            payload = b"ZZZ\r\nhello\r\n"
        elif path == "/conflict":
            head = _raw_head(
                200,
                "OK",
                [
                    ("Content-Length", str(len(RAW_BODY))),
                    ("Transfer-Encoding", "chunked"),
                ],
            )
            payload = b"0\r\n\r\n"
        elif path == "/no-length":
            head = _raw_head(200, "OK", [])
            payload = RAW_BODY
        elif path == "/status/204":
            head = _raw_head(204, "No Content", [])
            payload, keep_open = b"", True
        elif path == "/status/304":
            head = _raw_head(304, "Not Modified", [])
            payload, keep_open = b"", True
        else:
            head = _raw_head(404, "Not Found", [("Content-Length", "9")])
            payload = b"not found"
        writer.write(head)
        if not head_only:
            writer.write(payload)
        await writer.drain()
        if keep_open:
            # 保持连接：等客户端关闭或空闲超时，模拟“发完响应不关闭”的目标
            try:
                await asyncio.wait_for(reader.read(), timeout=RAW_KEEPALIVE_SECONDS)
            except asyncio.TimeoutError:
                pass
    except (ConnectionError, asyncio.TimeoutError):
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except OSError:
            pass


async def _raw_server(port: int) -> None:
    server = await asyncio.start_server(_raw_handle, "0.0.0.0", port)
    async with server:
        await server.serve_forever()


def _server_kwargs() -> dict:
    return {
        "app": app,
        "log_level": "warning",
        "access_log": False,
    }


async def _one_server(port: int, ssl_cert: str | None = None,
                      ssl_key: str | None = None) -> uvicorn.Server:
    cfg_kwargs = dict(host="0.0.0.0", port=port, **_server_kwargs())
    if ssl_cert and ssl_key:
        cfg_kwargs.update(ssl_certfile=ssl_cert, ssl_keyfile=ssl_key)
    server = uvicorn.Server(uvicorn.Config(**cfg_kwargs))
    # 直接返回由 gather 驱动；这里只构造，不阻塞
    return server


async def serve() -> None:
    # 同时监听标准端口（80/443，供跳转 URL 直接使用）与演示端口（8080/8443）。
    # 容器以 root 启动可绑定特权端口；本地非特权演示可经环境变量改为高位端口。
    # 另监听原始可控端口（默认 8090），演示保活/断流等响应完整性场景。
    http_ports = [int(p) for p in os.getenv("TARGET_HTTP_PORTS", "80,8080").split(",")]
    https_ports = [int(p) for p in os.getenv("TARGET_HTTPS_PORTS", "443,8443").split(",")]
    raw_port = int(os.getenv("TARGET_RAW_PORT", "8090"))
    cert = f"{CERT_DIR}/targets.fullchain.pem"
    key = f"{CERT_DIR}/targets.key.pem"
    servers: list[uvicorn.Server] = []
    for p in http_ports:
        servers.append(await _one_server(p))
    for p in https_ports:
        servers.append(await _one_server(p, cert, key))
    await asyncio.gather(*(s.serve() for s in servers), _raw_server(raw_port))


if __name__ == "__main__":
    asyncio.run(serve())
