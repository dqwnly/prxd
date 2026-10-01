import asyncio
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import proxy_pipeline as p

REAL = '8.8.8.8'
EXIT = '1.1.1.1'


def dump(nonce='test', **headers):
    return json.dumps({'origin': EXIT, 'headers': {'Host': 'judge', 'X-Proxy-Pipeline-Nonce': nonce, **headers}})


class Parsing(unittest.TestCase):
    def test_url_hints(self):
        for url, expected in [
            ('https://geonode.com/free-proxy-list', p.POOLS),
            ('https://x/socks.txt', ('socks4', 'socks5')),
            ('https://x/connect.txt', ('http',)),
            ('https://x/SOCKS5_RAW.txt', ('socks5',)),
            ('https://x/api?protocol=socks4', ('socks4',)),
            ('https://x/all.txt', p.POOLS),
        ]:
            self.assertEqual(p.source_hint(url), expected)

    def test_scheme_override_credentials_and_dedupe(self):
        result = p.extract('socks5://user:secret@1.1.1.1:1080\nsocks5://1.1.1.1:1080', ('http',))
        self.assertEqual(result['socks5'], {'1.1.1.1:1080'})
        self.assertFalse(result['http'])

    def test_json_formats(self):
        shapes = [
            [{'host': EXIT, 'port': 80, 'protocol': 'socks4'}],
            {'data': [{'ip': EXIT, 'port': '80', 'protocols': ['socks4']}]},
            {'socks4': [f'{EXIT}:80']},
            {'data': {'unknown': [f'socks4://u:p@{EXIT}:80']}},
        ]
        for shape in shapes:
            parsed = p.extract(json.dumps(shape))
            self.assertEqual(parsed['socks4'], {f'{EXIT}:80'})
            self.assertFalse(parsed['http'])
            self.assertFalse(parsed['socks5'])

    def test_static_html(self):
        parsed = p.extract('<table><tr><td><a>1.1.1.1</a></td><td>8080</td></tr></table>')
        self.assertTrue(all(v == {'1.1.1.1:8080'} for v in parsed.values()))

    def test_invalid_non_global_and_ipv6(self):
        for host in ['127.0.0.1', '10.1.2.3', '192.168.1.1', '0.0.0.0', '100.64.0.1',
                     '192.0.2.1', '224.0.0.1', '999.1.2.3', '::1', 'fc00::1']:
            self.assertIsNone(p.endpoint(host, 80))
        for port in [0, -1, 65536, 'hi', '1.5']:
            self.assertIsNone(p.endpoint(EXIT, port))
        self.assertEqual(p.endpoint('2606:4700:4700::1111', 80), '[2606:4700:4700::1111]:80')

    def test_elite(self):
        self.assertTrue(p.elite(dump(), {REAL}, 'test'))
        self.assertFalse(p.elite(dump(), {REAL}, 'other'))
        for header in p.FORBIDDEN:
            self.assertFalse(p.elite(dump(**{'HTTP_' + header: 'something'}), {REAL}))
        self.assertFalse(p.elite(dump(extra=REAL), {REAL}))
        self.assertFalse(p.elite('documentation REMOTE_ADDR = 1.1.1.1', {REAL}))
        self.assertTrue(p.elite('REMOTE_ADDR = 1.1.1.1\nHTTP_HOST = example.org\n', {REAL}))
        self.assertFalse(p.elite('REMOTE_ADDR = 1.1.1.1\nHTTP_VIA = proxy\n', {REAL}))

    def test_services(self):
        svc = {'blocked_url_markers': ['/sorry/'], 'captcha_markers': ['robot check'], 'ok_markers': ['result']}
        for status, url, headers, body, expected in [
            (200, 'https://google.com/sorry/index', {}, '', 'captcha'),
            (403, '', {'Cf-Mitigated': 'challenge'}, '', 'captcha'),
            (200, '', {}, 'robot check', 'captcha'),
            (403, '', {}, '', 'blocked'), (429, '', {}, '', 'blocked'),
            (503, '', {}, '', 'error'), (200, '', {}, 'wrong', 'blocked'),
            (200, '', {}, 'RESULT', 'ok'),
        ]:
            self.assertEqual(p.classify(status, url, headers, body, svc), expected)


class Pipeline(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.cfg = p.load_config()
        self.cfg.update(concurrency=3, source_concurrency=2, judge_max_rps=10000)

    async def test_worker_bound_and_failure_propagation(self):
        active = peak = completed = 0
        async def job(_):
            nonlocal active, peak, completed
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0)
            active -= 1
            completed += 1
        await p.workers(range(10000), 7, job)
        self.assertEqual(completed, 10000)
        self.assertLessEqual(peak, 7)
        async def broken(_):
            raise RuntimeError('broken')
        with self.assertRaises(ExceptionGroup):
            await asyncio.wait_for(p.workers(range(100), 2, broken), 1)

    async def test_no_judges_preserves_every_byte(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'proxies'
            target.mkdir()
            sentinel = target / 'http.txt'
            sentinel.write_bytes(b'old\n')
            with patch.object(p, 'discover_ips', AsyncMock(return_value={REAL})), \
                 patch.object(p, 'request', AsyncMock(side_effect=TimeoutError)), \
                 patch.object(p, 'scrape', AsyncMock()) as scrape:
                with self.assertRaisesRegex(RuntimeError, 'No live'):
                    await p.run(self.cfg, target)
                scrape.assert_not_called()
            self.assertEqual(sentinel.read_bytes(), b'old\n')
            self.assertEqual(list(target.iterdir()), [sentinel])

    async def test_dead_source_is_nonfatal(self):
        self.cfg['checker_net']['enabled'] = False
        self.cfg['sources'] = ['https://dead.example/http.txt']
        with patch.object(p, 'request', AsyncMock(side_effect=TimeoutError('dead'))), self.assertLogs(p.LOG, 'WARNING'):
            pools, counts = await p.scrape(None, self.cfg)
        self.assertFalse(any(pools.values()))
        self.assertEqual(next(iter(counts.values()))['status'], 'error')

    async def test_archive_unknown_shape(self):
        self.cfg['sources'] = []
        self.cfg['checker_net']['days'] = 2
        seen = []
        async def fetch(_session, url, *args, **kwargs):
            seen.append(url)
            body = json.dumps({'data': {'dates': ['2026-09-01', '2026-09-03', '2026-09-02']}}) if url.endswith('archive') else json.dumps({'data': {'nested': ['socks5://u:p@1.1.1.1:1080']}})
            return p.Response(200, url, {}, body, 1)
        with patch.object(p, 'request', fetch):
            pools, _ = await p.scrape(None, self.cfg)
        self.assertEqual(pools['socks5'], {'1.1.1.1:1080'})
        self.assertEqual(len(seen), 3)
        self.assertFalse(any(x.endswith('2026-09-01') for x in seen))

    async def test_judges_require_real_echo_and_keep_both_schemes(self):
        self.cfg['judges'] = ['http://good', 'https://good', 'http://static']
        self.cfg['max_judges'] = 2
        async def fetch(_session, url, *args, **kw):
            nonce = kw['headers']['X-Proxy-Pipeline-Nonce'] if 'good' in url else 'stale'
            body = json.dumps({'origin': REAL, 'headers': {'X-Proxy-Pipeline-Nonce': nonce}})
            return p.Response(200, url, {}, body, 1)
        with patch.object(p, 'request', fetch):
            judges = await p.validate_judges(None, self.cfg, {REAL})
        self.assertEqual({j.url for j in judges}, {'http://good', 'https://good'})

    async def test_protocol_checks_elite_filter_and_output(self):
        judges = [p.Judge('http://judge', 1, self.cfg), p.Judge('https://judge', 2, self.cfg)]
        pools = {'http': {'1.1.1.1:80', '9.9.9.9:80'}, 'socks4': {'1.0.0.1:80'}, 'socks5': set()}
        called = []
        async def fake(_session, _cfg, protocol, address, url, *args, **kwargs):
            called.append((protocol, address, url))
            headers = {'Via': 'bad'} if address.startswith('9.') else {}
            return p.Response(200, url, {}, dump(kwargs['headers']['X-Proxy-Pipeline-Nonce'], **headers), 1)
        with patch.object(p, 'via_proxy', fake):
            rows = await p.check_candidates(None, self.cfg, pools, judges, {REAL})
        self.assertEqual(len(called), 5)
        self.assertEqual({r['protocol'] for r in rows}, {'http', 'https', 'socks4'})
        self.assertTrue(all(url.startswith('https:') == (proto == 'https') for proto, _, url in called))
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'proxies'
            p.publish_files(dest, rows, {'working': len(rows)}, self.cfg)
            self.assertEqual(len((dest / 'all.txt').read_text().splitlines()), 3)
            before = {f.relative_to(dest): f.read_bytes() for f in dest.rglob('*') if f.is_file()}
            with self.assertRaises(RuntimeError):
                p.publish_files(dest, [], {}, self.cfg)
            self.assertEqual(before, {f.relative_to(dest): f.read_bytes() for f in dest.rglob('*') if f.is_file()})

    async def test_fastest_https_services_only(self):
        self.cfg['service_check']['limit'] = 1
        self.cfg['services'] = [{'name': 'test', 'url': 'https://test', 'ok_markers': ['yes']}]
        rows = [{'proxy': f'1.1.1.{i}:80', 'protocol': proto, 'ms': i}
                for i, proto in enumerate(['http', 'https', 'socks5'], 1)]
        with patch.object(p, 'via_proxy', AsyncMock(return_value=p.Response(200, '', {}, 'yes', 1))) as fetch:
            await p.check_services(None, self.cfg, rows)
        self.assertEqual(fetch.await_count, 1)
        self.assertEqual(rows[1]['services'], {'test': 'ok'})
        self.assertNotIn('services', rows[0])
        self.assertNotIn('services', rows[2])

    async def test_socks_library_errors_are_candidate_failures(self):
        for error in (p.ProxyError, p.ProxyConnectionError, p.ProxyTimeoutError):
            with patch.object(p.ProxyConnector, 'from_url', side_effect=error('dead proxy')):
                with self.assertRaises(OSError):
                    await p.via_proxy(None, self.cfg, 'socks5', '1.1.1.1:80', 'http://judge', 1, 1000)

    async def test_truncated_socks_handshake_is_nonfatal(self):
        async def close_early(reader, writer):
            await reader.read(1)
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(close_early, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            for protocol in ('socks4', 'socks5'):
                with self.assertRaises(OSError):
                    await p.via_proxy(None, self.cfg, protocol, f'127.0.0.1:{port}',
                                      'http://judge.invalid/get', 1, 1000)

    async def test_real_http_proxy_transport(self):
        seen = []
        async def proxy(reader, writer):
            raw = (await reader.readuntil(b'\r\n\r\n')).decode()
            seen.append(raw.splitlines()[0])
            nonce = next(line.split(': ', 1)[1] for line in raw.splitlines()
                         if line.lower().startswith('x-proxy-pipeline-nonce:'))
            body = dump(nonce).encode()
            writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode()
                         + b'\r\nConnection: close\r\n\r\n' + body)
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(proxy, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]
        async with server, p.aiohttp.ClientSession(trust_env=False) as session:
            result = await p.via_proxy(session, self.cfg, 'http', f'127.0.0.1:{port}',
                                       'http://judge.invalid/get', 1, 10000,
                                       headers={'X-Proxy-Pipeline-Nonce': 'live'})
        self.assertTrue(p.elite(result.body, {REAL}, 'live'))
        self.assertEqual(seen, ['GET http://judge.invalid/get HTTP/1.1'])

    async def test_connect_is_used_for_https(self):
        seen = []
        async def proxy(reader, writer):
            raw = await reader.readuntil(b'\r\n\r\n')
            seen.append(raw.decode().splitlines()[0])
            writer.write(b'HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n')
            await writer.drain()
            writer.close()
            await writer.wait_closed()
        server = await asyncio.start_server(proxy, '127.0.0.1', 0)
        port = server.sockets[0].getsockname()[1]
        async with server, p.aiohttp.ClientSession(trust_env=False) as session:
            with self.assertRaises(p.aiohttp.ClientHttpProxyError):
                await p.via_proxy(session, self.cfg, 'https', f'127.0.0.1:{port}',
                                  'https://judge.invalid/get', 1, 10000)
        self.assertEqual(seen, ['CONNECT judge.invalid:443 HTTP/1.1'])

    async def test_deadline_includes_body_read(self):
        from aiohttp import web
        async def slow(request):
            response = web.StreamResponse()
            await response.prepare(request)
            await asyncio.sleep(.2)
            return response
        app = web.Application()
        app.router.add_get('/', slow)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, '127.0.0.1', 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        try:
            async with p.aiohttp.ClientSession() as session:
                with self.assertRaises(TimeoutError):
                    await p.request(session, f'http://127.0.0.1:{port}', .03, 1000)
        finally:
            await runner.cleanup()


if __name__ == '__main__':
    unittest.main()
