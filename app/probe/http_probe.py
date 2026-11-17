"""HTTP/HTTPS 出站探测引擎。

安全模型（每一跳都完整执行，跳转目标也不例外）：

  URL 静态校验 → DNS A 记录查询 → *全部* 解析地址过白名单
  → 仅向已批准 IP 建 TCP（运行时不再解析）→ HTTPS 按原域名校验证书
  → 发送一次请求 → 读取响应 → 若是跳转则对 Location 重复上述流程

因此：
* DNS 在检查后变化、连接重试、HTTP 跳转都不会让请求进入未获准网段；
* 被策略拒绝的目标在任何 socket 建立之前就被拦下，收不到探测请求；
* 每跳最多把已批准的地址各试一次，重试绝不重新解析 DNS。
"""

from __future__ import annotations

import asyncio
import ipaddress
import ssl
from dataclasses import asdict, dataclass, field
from urllib.parse import urljoin, urlsplit

from .connection import TlsInfo, build_ssl_context, open_tcp, start_tls
from .dns_client import DnsError, DnsResolver
from .policy import (
    AddressPolicy,
    PolicyError,
    is_ip_literal,
    parse_target,
)

DEFAULT_PORTS = {"http": 80, "https": 443}
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 3
MAX_BYTES = 64 * 1024


@dataclass
class HopReport:
    hop: int
    url: str
    scheme: str
    hostname: str
    port: int
    resolved_addresses: list[str] = field(default_factory=list)
    approved_addresses: list[str] = field(default_factory=list)
    connected_peer: str | None = None
    tls: dict | None = None
    request_sent: bool = False
    status_code: int | None = None
    reason: str | None = None
    location: str | None = None
    redirect_count: int = 0
    outcome: str = "pending"  # ok | redirected | blocked | error
    reject_reason: str | None = None
    error: str | None = None

    def mark_blocked(self, reason: str) -> None:
        self.outcome = "blocked"
        self.reject_reason = reason
        self.reason = reason

    def mark_error(self, message: str) -> None:
        self.outcome = "error"
        self.error = message
        self.reason = message


class Prober:
    def __init__(
        self,
        policy: AddressPolicy,
        resolver: DnsResolver,
        ca_bundle: str | None = None,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        tls_timeout: float = 8.0,
        max_redirects: int = MAX_REDIRECTS,
        max_bytes: int = MAX_BYTES,
    ) -> None:
        self._policy = policy
        self._resolver = resolver
        self._ssl = build_ssl_context(ca_bundle)
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._tls_timeout = tls_timeout
        self._max_redirects = max_redirects
        self._max_bytes = max_bytes

    async def probe(self, url: str, method: str = "GET") -> list[HopReport]:
        method = method.upper()
        if method not in ("GET", "HEAD"):
            raise PolicyError("探测仅支持 GET/HEAD 方法")
        hops: list[HopReport] = []
        redirects = 0
        current = url
        while True:
            hop_idx = len(hops) + 1
            hop = HopReport(hop=hop_idx, url=current, scheme="", hostname="", port=0)
            hops.append(hop)
            next_url = await self._do_hop(hop, current, method)
            if hop.outcome in ("blocked", "error"):
                return hops
            if next_url is None:
                hop.outcome = "ok"
                return hops
            # 发生跳转
            redirects += 1
            hop.redirect_count = redirects
            hop.outcome = "redirected"
            if redirects > self._max_redirects:
                limit_hop = HopReport(
                    hop=len(hops) + 1,
                    url=next_url,
                    scheme="",
                    hostname="",
                    port=0,
                )
                limit_hop.mark_blocked(
                    f"已跟随 {self._max_redirects} 次跳转，达到上限，"
                    f"拒绝继续访问: {next_url}"
                )
                hops.append(limit_hop)
                return hops
            current = next_url

    async def _do_hop(self, hop: HopReport, url: str, method: str) -> str | None:
        # 1) URL 静态校验（不产生任何网络流量）
        try:
            scheme, host, port, _user, raw = parse_target(url)
        except PolicyError as exc:
            hop.mark_blocked(str(exc))
            return None
        hop.scheme = scheme
        hop.hostname = host
        hop.port = port or DEFAULT_PORTS[scheme]

        # 2) 解析 + 白名单：IP 字面量直接校验；域名只问配置的解析器
        try:
            if is_ip_literal(host):
                resolved = [host]
            else:
                resolved = await self._resolver.resolve_a(host)
            hop.resolved_addresses = list(resolved)
            approved = self._policy.check_resolved(resolved)
            hop.approved_addresses = [str(ip) for ip in approved]
        except (PolicyError, DnsError) as exc:
            hop.mark_blocked(str(exc))
            return None

        # 3) 仅对已批准地址尝试连接，每个地址一次，绝不重新解析
        last_err: str | None = None
        for ip in approved:
            connected = await self._try_one_address(hop, ip, scheme, host, method)
            if connected is not None:
                # 该地址连接成功：清除此前地址尝试留下的错误，避免残留
                hop.error = None
                reader, writer, tls_info = connected
                try:
                    return await self._send_and_read(
                        hop, reader, writer, method, host, hop.port, url
                    )
                except PolicyError as exc:
                    # 响应阶段的策略性错误（响应头超限、非法状态行、正文不完整、
                    # 分块格式错误、长度信息冲突等）：记录为本跳错误，
                    # 不逃逸到 API 入口，也绝不继续跳转
                    hop.mark_error(str(exc))
                    return None
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except (OSError, ssl.SSLError):
                        pass
            last_err = hop.error or hop.reject_reason
        # 所有已批准地址均连接失败
        hop.mark_error(f"全部已批准地址连接失败（未尝试任何未获准地址）: {last_err}")
        return None

    async def _try_one_address(self, hop, ip: ipaddress.IPv4Address,
                               scheme: str, host: str, method: str):
        try:
            reader, writer, peer = await open_tcp(
                ip, hop.port, self._connect_timeout
            )
            hop.connected_peer = peer
            if scheme == "https":
                reader, writer, tls_info = await start_tls(
                    writer, reader, host, self._ssl, self._tls_timeout
                )
                hop.tls = asdict(tls_info)
            return reader, writer, tls_info if scheme == "https" else None
        except PolicyError as exc:
            # 记录失败原因后继续试下一个 *已批准* 地址
            hop.connected_peer = None
            hop.tls = None
            hop.error = str(exc)
            return None

    async def _send_and_read(
        self, hop: HopReport, reader, writer, method: str,
        host: str, port: int, url: str,
    ) -> str | None:
        parts = urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path = f"{path}?{parts.query}"
        authority = host if (
            (parts.scheme == "http" and port == 80)
            or (parts.scheme == "https" and port == 443)
        ) else f"{host}:{port}"
        request_lines = (
            f"{method} {path} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "User-Agent: egress-probe/1.0\r\n"
            "Accept: */*\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        try:
            writer.write(request_lines.encode("ascii", errors="replace"))
            await writer.drain()
            hop.request_sent = True
            response = await asyncio.wait_for(
                self._read_response(reader, method), timeout=self._read_timeout
            )
        except asyncio.TimeoutError as exc:
            hop.mark_error(f"读取响应超时（{self._read_timeout}s）")
            return None
        except OSError as exc:
            hop.mark_error(f"连接读写错误: {exc}")
            return None

        hop.status_code = response["status"]
        hop.reason = response["reason"]
        if response["status"] in REDIRECT_STATUSES:
            location = response["headers"].get("location")
            hop.location = location
            if not location:
                hop.mark_error(f"收到 {response['status']} 跳转但缺少 Location 头")
                return None
            try:
                next_url = normalize_redirect(url, location)
            except PolicyError as exc:
                # 跳转目标违反策略（非 HTTP(S)、userinfo 等）：在建立任何
                # 到目标的连接前拒绝，标记为 blocked 并保留已收到的 Location
                hop.mark_blocked(str(exc))
                return None
            return next_url
        return None

    async def _read_response(self, reader, method: str) -> dict:
        """读取一个 *完整* 的 HTTP/1.1 响应；不完整或自相矛盾即抛 PolicyError。

        报文完整性判定（RFC 9112 消息边界）：
        * HEAD 响应及 204/304 状态码：完整响应头即为完整响应，不读正文；
        * ``Transfer-Encoding`` 最终编码为 chunked：必须读到终止块（0 长度
          块）及其后的 trailer 结束行，块格式错误即判错；
        * ``Content-Length: N``：必须收齐 N 字节正文，连接在收齐前关闭
          即“正文不完整”（超过 64KiB 上限的部分按上限截断，不再读取）；
        * 无长度信息：正文以连接关闭为界，读到 EOF 为止；
        * ``Content-Length`` 与 ``Transfer-Encoding`` 并存、或多个
          ``Content-Length`` 值不一致：长度信息冲突，直接判错。

        完整响应即使对端保持连接（keep-alive）也立即返回，不等连接关闭，
        因此跳转检查不会被慢关闭的连接拖延。
        """
        interim = 0
        while True:
            head = await self._read_head_block(reader)
            status, reason, headers, content_length, chunked, has_te = (
                self._parse_head(head)
            )
            if 100 <= status < 200:
                # 1xx 临时响应（如 100 Continue）：无正文，继续读最终响应
                interim += 1
                if interim > 8:
                    raise PolicyError("服务器连续返回过多 1xx 临时响应")
                continue
            break

        if content_length is not None and has_te:
            raise PolicyError(
                "响应长度信息冲突: 同时携带 Content-Length 与 Transfer-Encoding"
            )
        has_body = method != "HEAD" and status not in (204, 304)
        if has_body:
            if chunked:
                await self._read_chunked_body(reader)
            elif content_length is not None:
                await self._read_fixed_body(reader, content_length)
            else:
                await self._read_until_eof(reader)
        return {"status": status, "reason": reason, "headers": headers}

    async def _read_head_block(self, reader) -> bytes:
        """逐行读响应头直到空行；总量超过 64KiB 上限或对端提前关闭即判错。"""
        blob = b""
        while True:
            try:
                line = await reader.readline()
            except ValueError as exc:  # 单行超过流缓冲上限
                raise PolicyError("响应头部超过大小上限") from exc
            if not line:
                if blob:
                    raise PolicyError("响应头未收齐，连接提前关闭")
                raise PolicyError("连接已关闭，未收到任何响应数据")
            blob += line
            if len(blob) > self._max_bytes:
                raise PolicyError("响应头部超过大小上限")
            if line in (b"\r\n", b"\n"):
                return blob

    def _parse_head(
        self, blob: bytes
    ) -> tuple[int, str, dict[str, str], int | None, bool, bool]:
        """解析状态行与响应头。

        返回 (status, reason, headers, content_length, chunked, has_transfer_encoding)。
        多个 Content-Length 值不一致、或值非十进制数字，直接判错。
        """
        text = blob.decode("iso-8859-1")
        lines = text.split("\r\n")
        status_line = lines[0]
        if not status_line.startswith("HTTP/"):
            raise PolicyError(f"非法 HTTP 响应行: {status_line[:80]!r}")
        try:
            _proto, rest = status_line.split(" ", 1)
            status_text, reason = rest.split(" ", 1) if " " in rest else (rest, "")
            status = int(status_text)
        except (IndexError, ValueError) as exc:
            raise PolicyError(f"无法解析状态行: {status_line[:80]!r}") from exc
        headers: dict[str, str] = {}
        lengths: list[int] = []
        chunked = False
        has_te = False
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.strip()
            headers[key] = value
            if key == "content-length":
                # 允许 "Content-Length: 42, 42" 这类等值重复，值不一致即冲突
                for part in value.split(","):
                    part = part.strip()
                    if not part.isdigit():
                        raise PolicyError(f"非法 Content-Length 值: {part!r}")
                    if lengths and int(part) != lengths[0]:
                        raise PolicyError(
                            "响应长度信息冲突: 多个 Content-Length 值不一致 "
                            f"({lengths[0]} != {part})"
                        )
                    lengths.append(int(part))
            elif key == "transfer-encoding":
                has_te = True
                # 仅最终编码为 chunked 时按分块界定；否则按连接关闭界定
                encodings = [e.strip().lower() for e in value.split(",")]
                chunked = bool(encodings) and encodings[-1] == "chunked"
        content_length = lengths[0] if lengths else None
        return status, reason, headers, content_length, chunked, has_te

    async def _read_fixed_body(self, reader, declared: int) -> None:
        """按 Content-Length 收齐正文；提前断开即“正文不完整”。

        声明长度超过 64KiB 上限时读满上限即停（自我保护性截断，
        连通性已确认，不再消耗对端剩余数据）。
        """
        remaining = min(declared, self._max_bytes)
        while remaining > 0:
            chunk = await reader.read(min(4096, remaining))
            if not chunk:
                raise PolicyError(
                    f"响应正文不完整: 声明 Content-Length {declared} 字节，"
                    "连接在收齐前关闭"
                )
            remaining -= len(chunk)

    async def _read_until_eof(self, reader) -> None:
        """无长度信息时正文以连接关闭为界；最多读取 64KiB 上限。"""
        read_total = 0
        while read_total < self._max_bytes:
            chunk = await reader.read(4096)
            if not chunk:
                return
            read_total += len(chunk)

    async def _read_chunked_body(self, reader) -> None:
        """读取分块编码正文直到终止块；格式错误或未收齐即判错。"""
        read_total = 0
        while True:
            size_line = await self._read_chunk_line(reader, "块大小行")
            try:
                size = int(size_line.split(b";", 1)[0].strip(), 16)
            except ValueError as exc:
                raise PolicyError(
                    f"分块编码格式错误: 非法块大小 {size_line[:40]!r}"
                ) from exc
            if size < 0:
                raise PolicyError(
                    f"分块编码格式错误: 非法块大小 {size_line[:40]!r}"
                )
            if size == 0:
                # 终止块后读 trailer，直到空行结束
                while True:
                    trailer = await self._read_chunk_line(reader, "trailer 行")
                    if not trailer.strip(b"\r\n"):
                        return
            remaining = size
            while remaining > 0:
                chunk = await reader.read(min(4096, remaining))
                if not chunk:
                    raise PolicyError("分块编码格式错误: 块数据未收齐连接即关闭")
                remaining -= len(chunk)
                read_total += len(chunk)
                if read_total >= self._max_bytes:
                    return  # 达到 64KiB 上限：截断保护，连通性已确认
            crlf = await self._read_exactly(reader, 2)
            if crlf != b"\r\n":
                raise PolicyError("分块编码格式错误: 块数据后缺少 CRLF")

    async def _read_chunk_line(self, reader, what: str) -> bytes:
        try:
            line = await reader.readline()
        except ValueError as exc:
            raise PolicyError(f"分块编码格式错误: {what}过长") from exc
        if not line:
            raise PolicyError(f"分块编码格式错误: 读取{what}时连接提前关闭")
        return line

    async def _read_exactly(self, reader, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = await reader.read(n - len(buf))
            if not chunk:
                raise PolicyError("分块编码格式错误: 连接提前关闭")
            buf += chunk
        return buf


def normalize_redirect(base_url: str, location: str) -> str:
    """规范化跳转目标，并限制 scheme 为 http/https（相对 Location 也支持）。"""
    location = location.strip()
    if len(location) > 2048:
        raise PolicyError("跳转 Location 过长")
    if location.startswith("//"):
        # 协议相对 URL：继承当前 scheme
        location = urlsplit(base_url).scheme + ":" + location
    next_url = urljoin(base_url, location)
    scheme = urlsplit(next_url).scheme.lower()
    if scheme not in ("http", "https"):
        raise PolicyError(
            f"跳转到非 HTTP(S) 协议 {scheme!r}，拒绝: {next_url}"
        )
    if urlsplit(next_url).username is not None:
        raise PolicyError("跳转目标 URL 禁止携带 userinfo")
    return next_url
