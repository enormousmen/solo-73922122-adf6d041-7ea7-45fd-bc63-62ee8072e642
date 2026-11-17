"""端到端探测引擎测试（真实本地 DNS / TCP / TLS）。

覆盖需求关键点：
* 全部解析地址获准才连接（混合应答整体拒绝）；
* DNS 在检查后换址不会进入未获准网段（连接地址固定为检查时的 IP）；
* 被拒目标收不到任何探测请求；
* 跳转逐跳校验、最多 3 次、跳转到禁区/非 http 协议被拦；
* HTTPS 按原域名校验证书，校验失败即拒绝；
* 慢探测不阻塞其他请求（并发执行）。
"""

import asyncio

import pytest

from app.probe.policy import PolicyError


class TestProbeCore:
    async def test_allowed_http_probe(self, fake_dns, http_server, make_prober):
        fake_dns.set_zones({"good.test": ["127.0.0.1"]})
        http_server.route("good.test", "/")
        prober = make_prober()

        hops = await prober.probe(f"http://good.test:{http_server.port}/")

        assert len(hops) == 1
        hop = hops[0]
        assert hop.outcome == "ok"
        assert hop.resolved_addresses == ["127.0.0.1"]
        assert hop.approved_addresses == ["127.0.0.1"]
        assert hop.connected_peer == f"127.0.0.1:{http_server.port}"
        assert hop.request_sent is True
        assert hop.status_code == 200
        assert http_server.requests[-1]["host"] == "good.test"

    async def test_blocked_target_receives_no_request(
        self, fake_dns, http_server, make_prober
    ):
        # 禁止地址也绑定了同一个本地服务器（模拟“路由可达但策略禁止”）
        fake_dns.set_zones({"bad.test": ["127.0.0.1"]})
        http_server.route("bad.test", "/")
        # 白名单不含 127.0.0.1
        prober = make_prober(allowed=("10.10.0.0/24",))
        before = len(http_server.requests)

        hops = await prober.probe(f"http://bad.test:{http_server.port}/")

        assert hops[-1].outcome == "blocked"
        assert "白名单" in hops[-1].reject_reason
        assert hops[-1].request_sent is False
        assert hops[-1].connected_peer is None
        assert len(http_server.requests) == before  # 目标没有收到任何请求

    async def test_mixed_resolution_full_rejection(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({"mix.test": ["127.0.0.1", "8.8.8.8"]})
        prober = make_prober()
        before = len(http_server.requests)

        hops = await prober.probe(f"http://mix.test:{http_server.port}/")

        assert hops[-1].outcome == "blocked"
        assert "整体拒绝" in hops[-1].reject_reason
        assert hops[-1].approved_addresses == []
        assert hops[-1].connected_peer is None
        assert len(http_server.requests) == before

    async def test_dns_swap_after_check_uses_checked_ip(
        self, fake_dns, http_server, make_prober
    ):
        # 第一次解析返回允许地址；若探测端在连接前再次解析（错误实现），
        # 会拿到禁止地址。正确实现只使用检查时批准的 127.0.0.1。
        call_count = {"n": 0}
        orig = fake_dns.datagram_received

        def swapping(data, addr):  # noqa: ANN001
            call_count["n"] += 1
            if call_count["n"] == 1:
                fake_dns.set_zones({"swap.test": ["127.0.0.1"]})
            else:
                fake_dns.set_zones({"swap.test": ["8.8.8.8"]})
            orig(data, addr)

        fake_dns.datagram_received = swapping  # type: ignore[method-assign]
        http_server.route("swap.test", "/")
        prober = make_prober()

        hops = await prober.probe(f"http://swap.test:{http_server.port}/")

        assert hops[-1].outcome == "ok"
        assert hops[-1].resolved_addresses == ["127.0.0.1"]
        assert hops[-1].connected_peer == f"127.0.0.1:{http_server.port}"

    async def test_multi_address_failover_uses_approved_only(
        self, fake_dns, http_server, make_prober
    ):
        # 第一个已批准地址无服务（连接失败），第二个成功；重试不得离开已批准集合
        fake_dns.set_zones({"ha.test": ["127.0.0.2", "127.0.0.1"]})
        http_server.route("ha.test", "/")
        prober = make_prober(allowed=("127.0.0.0/24",),)
        # 127.0.0.2 上无服务 -> 先失败再切换到 127.0.0.1
        hops = await prober.probe(f"http://ha.test:{http_server.port}/")
        hop = hops[-1]
        assert hop.outcome == "ok"
        assert hop.connected_peer == f"127.0.0.1:{http_server.port}"
        assert hop.error is None  # 首个地址的失败错误不残留
        assert hop.resolved_addresses == ["127.0.0.2", "127.0.0.1"]

    async def test_ip_literal_denied_without_dns(
        self, fake_dns, http_server, make_prober
    ):
        prober = make_prober(allowed=("10.0.0.0/8",))
        hops = await prober.probe(f"http://127.0.0.1:{http_server.port}/")
        assert hops[-1].outcome == "blocked"
        assert fake_dns.queried_names == []  # IP 字面量不触发 DNS

    async def test_ipv6_literal_rejected(self, make_prober):
        prober = make_prober(allowed=("127.0.0.1/32",))
        hops = await prober.probe("http://[::1]/")
        assert hops[-1].outcome == "blocked"
        assert "IPv6" in hops[-1].reject_reason

    async def test_redirect_to_allowed_target(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({
            "start.test": ["127.0.0.1"],
            "final.test": ["127.0.0.1"],
        })
        http_server.route(
            "start.test", "/go",
            status=302, headers=[("Location", f"http://final.test:{http_server.port}/done")],
        )
        http_server.route("final.test", "/done")
        prober = make_prober()

        hops = await prober.probe(f"http://start.test:{http_server.port}/go")

        assert [h.outcome for h in hops] == ["redirected", "ok"]
        assert hops[0].location.endswith("/done")
        assert hops[1].hostname == "final.test"
        assert hops[1].status_code == 200

    async def test_redirect_to_forbidden_blocked_on_second_hop(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({
            "start.test": ["127.0.0.1"],
            "evil.test": ["8.8.8.8"],
        })
        http_server.route(
            "start.test", "/go",
            status=302, headers=[("Location", "http://evil.test/secret")],
        )
        prober = make_prober()
        before = len(http_server.requests)

        hops = await prober.probe(f"http://start.test:{http_server.port}/go")

        assert [h.outcome for h in hops] == ["redirected", "blocked"]
        assert "白名单" in hops[-1].reject_reason
        assert hops[-1].request_sent is False
        # 第一跳的请求只到 start，evil 从未被请求
        assert all(r["host"] != "evil.test" for r in http_server.requests[before:])

    async def test_redirect_to_non_http_scheme_rejected(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({"start.test": ["127.0.0.1"]})
        http_server.route(
            "start.test", "/go",
            status=302, headers=[("Location", "file:///etc/passwd")],
        )
        prober = make_prober()
        hops = await prober.probe(f"http://start.test:{http_server.port}/go")
        assert hops[-1].outcome == "blocked"
        assert "非 HTTP" in hops[-1].reject_reason
        assert hops[-1].request_sent is True  # 仅对第一跳源站发了请求

    async def test_redirect_limit_three(self, fake_dns, http_server, make_prober):
        names = [f"r{i}.test" for i in range(6)]
        fake_dns.set_zones({n: ["127.0.0.1"] for n in names})
        # r0 -> r1 -> r2 -> r3 -> r4 -> r5
        for i in range(5):
            http_server.route(
                names[i], "/",
                status=302,
                headers=[("Location", f"http://{names[i + 1]}:{http_server.port}/")],
            )
        http_server.route(names[5], "/")
        prober = make_prober(max_redirects=3)

        hops = await prober.probe(f"http://{names[0]}:{http_server.port}/")

        # 初始 1 跳 + 3 次跟随 + 1 个被上限拦截的未连接跳
        assert len(hops) == 5
        assert [h.outcome for h in hops[:4]] == (
            ["redirected", "redirected", "redirected", "redirected"]
        )
        assert hops[-1].outcome == "blocked"
        assert "上限" in hops[-1].reject_reason
        assert hops[-1].request_sent is False

    async def test_oversized_response_header_marked_as_hop_error(
        self, fake_dns, make_prober
    ):
        # 服务器返回超长头部，探测端应在跳内标记 error，而不是向 API 层抛异常
        async def huge_handle(reader, writer):  # noqa: ANN001
            body = "x"
            head = (
                "HTTP/1.1 200 OK\r\n"
                f"X-Big: {'a' * 70000}\r\n"
                "Content-Length: 1\r\nConnection: close\r\n\r\n" + body
            )
            writer.write(head.encode())
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(huge_handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        fake_dns.set_zones({"huge.test": ["127.0.0.1"]})
        prober = make_prober()
        try:
            hops = await prober.probe(f"http://huge.test:{port}/")
            assert hops[-1].outcome == "error"
            assert "上限" in (hops[-1].error or "")
        finally:
            server.close()
            await server.wait_closed()

    async def test_zero_redirect_allowed(self, fake_dns, http_server, make_prober):
        fake_dns.set_zones({"a.test": ["127.0.0.1"], "b.test": ["127.0.0.1"]})
        http_server.route(
            "a.test", "/",
            status=302, headers=[("Location", f"http://b.test:{http_server.port}/")],
        )
        prober = make_prober(max_redirects=0)
        hops = await prober.probe(f"http://a.test:{http_server.port}/")
        assert hops[-1].outcome == "blocked"
        assert "上限" in hops[-1].reject_reason


class TestResponseFraming:
    """HTTP/1.1 响应完整性判定（保活、断流、分块、长度冲突）。"""

    async def test_keepalive_get_completes_without_waiting_for_close(
        self, fake_dns, raw_server, make_prober
    ):
        # 完整响应（Content-Length 正确）后连接保持：应立即完成，不等读取超时
        port = await raw_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
            keep_open=True,
        )
        fake_dns.set_zones({"ka.test": ["127.0.0.1"]})
        prober = make_prober(read_timeout=5.0)

        started = asyncio.get_running_loop().time()
        hops = await prober.probe(f"http://ka.test:{port}/")
        elapsed = asyncio.get_running_loop().time() - started

        assert hops[-1].outcome == "ok"
        assert hops[-1].status_code == 200
        assert elapsed < 2.0  # 远小于 read_timeout=5s

    async def test_keepalive_redirect_followed_promptly(
        self, fake_dns, http_server, raw_server, make_prober
    ):
        # 保活目标返回 302：响应完整即应进行跳转检查，不被未关闭的连接拖延
        fake_dns.set_zones({
            "start.test": ["127.0.0.1"],
            "final.test": ["127.0.0.1"],
        })
        http_server.route("final.test", "/done")
        port = await raw_server(
            (
                "HTTP/1.1 302 Found\r\n"
                f"Location: http://final.test:{http_server.port}/done\r\n"
                "Content-Length: 0\r\n\r\n"
            ).encode(),
            keep_open=True,
        )
        prober = make_prober(read_timeout=5.0)

        started = asyncio.get_running_loop().time()
        hops = await prober.probe(f"http://start.test:{port}/go")
        elapsed = asyncio.get_running_loop().time() - started

        assert [h.outcome for h in hops] == ["redirected", "ok"]
        assert hops[1].status_code == 200
        assert elapsed < 2.0

    async def test_truncated_fixed_body_is_error_not_ok(
        self, fake_dns, raw_server, make_prober
    ):
        # 声明 Content-Length 100 但只发 5 字节就断开：不得报可达
        port = await raw_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort",
        )
        fake_dns.set_zones({"cut.test": ["127.0.0.1"]})
        prober = make_prober()

        hops = await prober.probe(f"http://cut.test:{port}/")

        assert hops[-1].outcome == "error"
        assert "不完整" in (hops[-1].error or "")

    async def test_truncated_redirect_is_not_followed(
        self, fake_dns, http_server, raw_server, make_prober
    ):
        # 302 声明了正文但未收齐即断开：不得报可达，也不得继续跳转
        fake_dns.set_zones({
            "start.test": ["127.0.0.1"],
            "final.test": ["127.0.0.1"],
        })
        http_server.route("final.test", "/done")
        port = await raw_server(
            (
                "HTTP/1.1 302 Found\r\n"
                f"Location: http://final.test:{http_server.port}/done\r\n"
                "Content-Length: 64\r\n\r\npartial"
            ).encode(),
        )
        prober = make_prober()

        hops = await prober.probe(f"http://start.test:{port}/go")

        assert len(hops) == 1
        assert hops[0].outcome == "error"
        assert "不完整" in (hops[0].error or "")
        assert len(http_server.requests) == 0  # 未跟随跳转

    async def test_chunked_body_ok_despite_keepalive(
        self, fake_dns, raw_server, make_prober
    ):
        port = await raw_server(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
            keep_open=True,
        )
        fake_dns.set_zones({"ch.test": ["127.0.0.1"]})
        prober = make_prober(read_timeout=5.0)

        started = asyncio.get_running_loop().time()
        hops = await prober.probe(f"http://ch.test:{port}/")
        elapsed = asyncio.get_running_loop().time() - started

        assert hops[-1].outcome == "ok"
        assert elapsed < 2.0

    async def test_chunked_bad_size_is_error(
        self, fake_dns, raw_server, make_prober
    ):
        port = await raw_server(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
            b"ZZZ\r\nhello\r\n",
        )
        fake_dns.set_zones({"bad-ch.test": ["127.0.0.1"]})
        prober = make_prober()

        hops = await prober.probe(f"http://bad-ch.test:{port}/")

        assert hops[-1].outcome == "error"
        assert "分块" in (hops[-1].error or "")

    async def test_chunked_cut_mid_data_is_error(
        self, fake_dns, raw_server, make_prober
    ):
        # 块声明 5 字节，只收到 2 字节连接就关闭
        port = await raw_server(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhe",
        )
        fake_dns.set_zones({"cut-ch.test": ["127.0.0.1"]})
        prober = make_prober()

        hops = await prober.probe(f"http://cut-ch.test:{port}/")

        assert hops[-1].outcome == "error"
        assert "分块" in (hops[-1].error or "")

    async def test_conflicting_length_headers_is_error(
        self, fake_dns, raw_server, make_prober
    ):
        # Content-Length 与 Transfer-Encoding 并存：长度信息冲突
        port = await raw_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        )
        fake_dns.set_zones({"cf.test": ["127.0.0.1"]})
        prober = make_prober()

        hops = await prober.probe(f"http://cf.test:{port}/")

        assert hops[-1].outcome == "error"
        assert "冲突" in (hops[-1].error or "")

    async def test_non_chunked_te_with_content_length_is_error(
        self, fake_dns, raw_server, make_prober
    ):
        # 非 chunked 的 Transfer-Encoding 与 Content-Length 并存同样是冲突
        port = await raw_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
            b"Transfer-Encoding: gzip\r\n\r\nhello",
        )
        fake_dns.set_zones({"cf2.test": ["127.0.0.1"]})
        prober = make_prober()

        hops = await prober.probe(f"http://cf2.test:{port}/")

        assert hops[-1].outcome == "error"
        assert "冲突" in (hops[-1].error or "")

    async def test_mismatched_duplicate_content_length_is_error(
        self, fake_dns, raw_server, make_prober
    ):
        port = await raw_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
        )
        fake_dns.set_zones({"dup.test": ["127.0.0.1"]})
        prober = make_prober()

        hops = await prober.probe(f"http://dup.test:{port}/")

        assert hops[-1].outcome == "error"
        assert "冲突" in (hops[-1].error or "")

    async def test_duplicate_equal_content_length_ok(
        self, fake_dns, raw_server, make_prober
    ):
        # 等值重复的 Content-Length 合法（RFC 9110 允许）
        port = await raw_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
            keep_open=True,
        )
        fake_dns.set_zones({"eq.test": ["127.0.0.1"]})
        prober = make_prober()

        hops = await prober.probe(f"http://eq.test:{port}/")

        assert hops[-1].outcome == "ok"

    async def test_head_response_ends_after_headers(
        self, fake_dns, raw_server, make_prober
    ):
        # HEAD：服务器只发响应头（声明了 Content-Length）且保持连接
        port = await raw_server(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
            keep_open=True,
        )
        fake_dns.set_zones({"head.test": ["127.0.0.1"]})
        prober = make_prober(read_timeout=5.0)

        started = asyncio.get_running_loop().time()
        hops = await prober.probe(f"http://head.test:{port}/", method="HEAD")
        elapsed = asyncio.get_running_loop().time() - started

        assert hops[-1].outcome == "ok"
        assert hops[-1].status_code == 200
        assert elapsed < 2.0

    async def test_204_response_ends_after_headers(
        self, fake_dns, raw_server, make_prober
    ):
        port = await raw_server(b"HTTP/1.1 204 No Content\r\n\r\n", keep_open=True)
        fake_dns.set_zones({"nc.test": ["127.0.0.1"]})
        prober = make_prober(read_timeout=5.0)

        started = asyncio.get_running_loop().time()
        hops = await prober.probe(f"http://nc.test:{port}/")
        elapsed = asyncio.get_running_loop().time() - started

        assert hops[-1].outcome == "ok"
        assert hops[-1].status_code == 204
        assert elapsed < 2.0

    async def test_304_response_ends_after_headers(
        self, fake_dns, raw_server, make_prober
    ):
        port = await raw_server(b"HTTP/1.1 304 Not Modified\r\n\r\n", keep_open=True)
        fake_dns.set_zones({"nm.test": ["127.0.0.1"]})
        prober = make_prober(read_timeout=5.0)

        started = asyncio.get_running_loop().time()
        hops = await prober.probe(f"http://nm.test:{port}/")
        elapsed = asyncio.get_running_loop().time() - started

        assert hops[-1].outcome == "ok"
        assert hops[-1].status_code == 304
        assert elapsed < 2.0

    async def test_no_length_body_delimited_by_close(
        self, fake_dns, raw_server, make_prober
    ):
        # 无长度信息：正文以连接关闭为界（原有行为保持）
        port = await raw_server(b"HTTP/1.1 200 OK\r\n\r\nbody-bytes")
        fake_dns.set_zones({"nl.test": ["127.0.0.1"]})
        prober = make_prober()

        hops = await prober.probe(f"http://nl.test:{port}/")

        assert hops[-1].outcome == "ok"
        assert hops[-1].status_code == 200

    async def test_interim_100_response_then_final(
        self, fake_dns, raw_server, make_prober
    ):
        port = await raw_server(
            b"HTTP/1.1 100 Continue\r\n\r\n"
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
            keep_open=True,
        )
        fake_dns.set_zones({"ic.test": ["127.0.0.1"]})
        prober = make_prober()

        hops = await prober.probe(f"http://ic.test:{port}/")

        assert hops[-1].outcome == "ok"
        assert hops[-1].status_code == 200


class TestTls:
    async def test_https_verified_with_original_hostname(
        self, fake_dns, https_server, make_prober
    ):
        fake_dns.set_zones({"https.allowed.demo.test": ["127.0.0.1"]})
        https_server.route("https.allowed.demo.test", "/secure")
        prober = make_prober()

        hops = await prober.probe(
            f"https://https.allowed.demo.test:{https_server.port}/secure"
        )

        assert hops[-1].outcome == "ok"
        assert hops[-1].tls is not None
        assert hops[-1].tls["version"].startswith("TLS")
        assert "https.allowed.demo.test" in hops[-1].tls["san"]
        assert hops[-1].connected_peer.startswith("127.0.0.1:")

    async def test_https_untrusted_cert_rejected(
        self, fake_dns, tmp_path, make_prober
    ):
        # 用自签证书起服务器，但探测端只信任 demo CA -> 握手必须失败
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime
        import ssl as ssl_mod

        key = rsa.generate_private_key(65537, 2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "rogue.test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
            .not_valid_after(
                datetime.datetime.now(datetime.timezone.utc)
                + datetime.timedelta(days=1)
            )
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("rogue.test")]), False
            )
            .sign(key, hashes.SHA256())
        )
        cert_p = tmp_path / "rogue.crt"
        key_p = tmp_path / "rogue.key"
        cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_p.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        ctx = ssl_mod.SSLContext(ssl_mod.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(cert_p), str(key_p))

        from tests.conftest import FakeHttpServer

        rogue = FakeHttpServer(ssl_ctx=ctx)
        await rogue.start()
        rogue.port = rogue._server.sockets[0].getsockname()[1]
        try:
            fake_dns.set_zones({"rogue.test": ["127.0.0.1"]})
            prober = make_prober()
            hops = await prober.probe(
                f"https://rogue.test:{rogue.port}/"
            )
            assert hops[-1].outcome == "error"
            assert "证书校验失败" in hops[-1].error
            assert "未关闭校验" in hops[-1].error
        finally:
            await rogue.stop()

    async def test_https_hostname_mismatch_rejected(
        self, fake_dns, https_server, make_prober
    ):
        # 服务器证书不含 other.test -> 主机名校验失败
        fake_dns.set_zones({"other.test": ["127.0.0.1"]})
        https_server.route("other.test", "/")
        prober = make_prober()
        hops = await prober.probe(f"https://other.test:{https_server.port}/")
        assert hops[-1].outcome == "error"
        assert "证书校验失败" in hops[-1].error


class TestConcurrency:
    async def test_slow_probe_does_not_block_others(
        self, fake_dns, http_server, make_prober
    ):
        fake_dns.set_zones({"slow.test": ["127.0.0.1"], "fast.test": ["127.0.0.1"]})

        slow_finished = asyncio.Event()

        async def slow_handle(reader, writer):  # noqa: ANN001
            # 等到测试发出快请求并完成后再响应，模拟慢目标
            await slow_finished.wait()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
            writer.close()

        server = await asyncio.start_server(slow_handle, "127.0.0.1", 0)
        slow_port = server.sockets[0].getsockname()[1]
        http_server.route("fast.test", "/")
        prober = make_prober(read_timeout=10.0)

        async def run_slow():
            return await prober.probe(f"http://slow.test:{slow_port}/")

        slow_task = asyncio.create_task(run_slow())
        await asyncio.sleep(0.2)  # 确保慢探测已在飞行中

        fast_started = asyncio.get_running_loop().time()
        fast_hops = await prober.probe(f"http://fast.test:{http_server.port}/")
        fast_elapsed = asyncio.get_running_loop().time() - fast_started
        slow_finished.set()
        slow_hops = await slow_task
        server.close()
        await server.wait_closed()

        assert fast_hops[-1].outcome == "ok"
        assert fast_elapsed < 2.0  # 未被慢探测阻塞
        assert slow_hops[-1].outcome == "ok"


class TestDnsClient:
    async def test_nxdomain_surfaces_as_block(self, fake_dns, make_prober):
        fake_dns.set_zones({})
        prober = make_prober()
        hops = await prober.probe("http://unknown.test/")
        assert hops[-1].outcome == "blocked"
        assert "NXDOMAIN" in hops[-1].reject_reason
        assert hops[-1].connected_peer is None

    async def test_dns_timeout_surfaces_as_block(self, make_prober):
        from app.probe.dns_client import DnsResolver
        from app.probe.http_probe import Prober
        from app.probe.policy import AddressPolicy

        # 指向一个丢弃 UDP 的端口（不可达端口会 ICMP 报错，因此用未绑定端口+短超时）
        resolver = DnsResolver("127.0.0.1", port=1, timeout=0.3, retries=0)
        prober = Prober(
            policy=AddressPolicy.from_cidrs(["127.0.0.1/32"]),
            resolver=resolver,
            ca_bundle=None,
            connect_timeout=1.0,
            read_timeout=2.0,
            tls_timeout=2.0,
        )
        hops = await prober.probe("http://timeout.test/")
        assert hops[-1].outcome == "blocked"
        assert "DNS" in hops[-1].reject_reason


async def test_bad_method_rejected(make_prober):
    prober = make_prober()
    with pytest.raises(PolicyError):
        await prober.probe("http://x.test/", method="POST")
