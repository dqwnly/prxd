"""Scrape, verify and publish a fresh proxy snapshot. Python 3.11+."""
from __future__ import annotations

import asyncio
import html
import ipaddress
import json
import logging
import os
import random
import re
import shutil
import socket
import tempfile
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import aiohttp
from aiohttp_socks import ProxyConnector, ProxyConnectionError, ProxyError, ProxyTimeoutError
import yaml

ROOT = Path(__file__).resolve().parents[1]
LOG = logging.getLogger("proxy-pipeline")
POOLS = ("http", "socks4", "socks5")
OUTPUT_PROTOCOLS = ("http", "https", "socks4", "socks5")
FORBIDDEN = {
    "VIA", "X_FORWARDED_FOR", "FORWARDED", "X_FORWARDED", "FORWARDED_FOR",
    "X_REAL_IP", "CLIENT_IP", "X_CLIENT_IP", "X_CLUSTER_CLIENT_IP",
    "X_ORIGINATING_IP", "PROXY_CONNECTION", "X_PROXY_ID",
}
ENDPOINT = re.compile(
    r"(?<![\w.:])(?:(?P<scheme>https?|socks[45]|socks|connect)://"
    r"(?:[^\s/@\"<>]+@)?)?(?P<host>\[[0-9a-fA-F:]+\]|(?:\d{1,3}\.){3}\d{1,3})"
    r":(?P<port>\d{1,6})(?!\d)", re.I
)


def protocol_names(value):
    if isinstance(value, list):
        return tuple(dict.fromkeys(p for v in value for p in protocol_names(v)))
    tokens = re.findall(r"[a-z]+[45]?", str(value).lower())
    result = []
    for token in tokens:
        if token in {"http", "https", "connect"}:
            result.append("http")
        elif token == "socks":
            result.extend(("socks4", "socks5"))
        elif token in {"socks4", "socks5"}:
            result.append(token)
    return tuple(dict.fromkeys(result))


def source_hint(url):
    parsed = urlsplit(url)
    query = parse_qs(parsed.query)
    for key in ("protocol", "protocols", "type"):
        if key in query and (hint := protocol_names(query[key])):
            return hint
    return protocol_names(parsed.path) or POOLS


def endpoint(host, port):
    try:
        ip = ipaddress.ip_address(str(host).strip("[] "))
        number = int(str(port))
        if not ip.is_global or ip.is_multicast or ip.is_reserved or not 1 <= number <= 65535:
            return None
        return f"[{ip}]:{number}" if ip.version == 6 else f"{ip}:{number}"
    except (ValueError, TypeError):
        return None


def extract(text, hints=POOLS):
    """One parser for text, recursive JSON records, DSNs and static table rows."""
    found = {p: set() for p in POOLS}

    def add(host, port, protocols):
        if address := endpoint(host, port):
            for protocol in protocols:
                found[protocol].add(address)

    def strings(value, inherited):
        for match in ENDPOINT.finditer(value):
            add(match['host'], match['port'], protocol_names(match['scheme']) or inherited)

    def walk(value, inherited):
        if isinstance(value, dict):
            lower = {str(k).lower(): v for k, v in value.items()}
            own = protocol_names(lower.get('protocols', lower.get('protocol', lower.get('type', '')))) or inherited
            host = lower.get('ip', lower.get('host', lower.get('ipaddress')))
            port = lower.get('port')
            if host is not None and port is not None:
                add(host, port, own)
            for key, child in value.items():
                # Some lists group records under protocol keys.
                key_hint = protocol_names(key) if str(key).lower() in OUTPUT_PROTOCOLS + ('socks', 'connect') else ()
                strings(str(key), own)
                walk(child, key_hint or own)
        elif isinstance(value, list):
            for child in value:
                walk(child, inherited)
        elif isinstance(value, str):
            strings(value, inherited)

    try:
        walk(json.loads(text), hints)
    except (ValueError, RecursionError):
        strings(text, hints)
        for row in re.findall(r'<tr\b[^>]*>(.*?)</tr>', text, re.I | re.S):
            cells = [html.unescape(re.sub(r'<[^>]*>', '', cell)).strip()
                     for cell in re.findall(r'<t[dh]\b[^>]*>(.*?)</t[dh]>', row, re.I | re.S)]
            for i in range(len(cells) - 1):
                add(cells[i], cells[i + 1], hints)
    return found


def normalize_header(name):
    return str(name).upper().replace('-', '_').removeprefix('HTTP_')


def parse_judge(body):
    """Require both an origin and real header fields; documentation is not a dump."""
    try:
        data = json.loads(body)
        if isinstance(data, dict) and isinstance(data.get('headers'), dict) and data['headers']:
            origins = {str(ipaddress.ip_address(x.strip())) for x in str(data.get('origin', '')).split(',')}
            return origins, {normalize_header(k): v for k, v in data['headers'].items()}
    except (ValueError, TypeError):
        pass
    plain = html.unescape(re.sub(r'<[^>]*>', '\n', body))
    fields = dict(re.findall(r'\b(REMOTE_ADDR|HTTP_[A-Z0-9_-]+)\s*(?:=|:)\s*([^\r\n<]+)', plain, re.I))
    normalized = {normalize_header(k): v.strip().strip('"\'') for k, v in fields.items()}
    try:
        origins = {str(ipaddress.ip_address(normalized.pop('REMOTE_ADDR')))}
    except (ValueError, KeyError):
        return None
    return (origins, normalized) if normalized else None


def has_nonce(dump, nonce):
    value = dump[1].get('X_PROXY_PIPELINE_NONCE', '')
    return nonce in (value if isinstance(value, list) else [value])


def elite(body, real_ips, nonce=None):
    dump = parse_judge(body)
    if not dump or FORBIDDEN.intersection(dump[1]):
        return False
    if dump[0].intersection(real_ips) or any(ip in html.unescape(body) for ip in real_ips):
        return False
    return nonce is None or has_nonce(dump, nonce)


def classify(status, url, headers, body, service):
    body, url = body.lower(), url.lower()
    headers = {k.lower(): v.lower() for k, v in headers.items()}
    if (any(x.lower() in url for x in service.get('blocked_url_markers', []))
            or headers.get('cf-mitigated') == 'challenge'
            or any(x.lower() in body for x in service.get('captcha_markers', []))):
        return 'captcha'
    if status in (403, 429):
        return 'blocked'
    if status >= 400 or status < 200 or status >= 300:
        return 'error'
    markers = service.get('ok_markers', [])
    if status == 200 and markers and not any(x.lower() in body for x in markers):
        return 'blocked'
    return 'ok'


@dataclass
class Response:
    status: int
    url: str
    headers: dict
    body: str
    ms: float


async def read_response(response, maximum):
    chunks, size = [], 0
    async for chunk in response.content.iter_chunked(65536):
        size += len(chunk)
        if size > maximum:
            raise ValueError('response exceeds configured byte limit')
        chunks.append(chunk)
    return b''.join(chunks).decode('utf-8', errors='replace')


async def request(session, url, timeout, maximum, *, headers=None, proxy=None, redirects=False):
    start = time.perf_counter()
    # Outer deadline includes connection setup, redirects and reading the entire body.
    async with asyncio.timeout(timeout):
        async with session.get(url, proxy=proxy, headers=headers,
                               allow_redirects=redirects, max_redirects=6,
                               timeout=aiohttp.ClientTimeout(total=timeout)) as response:
            body = await read_response(response, maximum)
            return Response(response.status, str(response.url), dict(response.headers), body,
                            (time.perf_counter() - start) * 1000)


async def workers(items, count, handler):
    """Bounded queue and fixed task count, even for half a million candidates."""
    queue = asyncio.Queue(maxsize=count * 2)

    async def consume():
        while True:
            item = await queue.get()
            try:
                if item is None:
                    return
                await handler(item)
            finally:
                queue.task_done()

    async with asyncio.TaskGroup() as group:
        for _ in range(count):
            group.create_task(consume())
        for item in items:
            await queue.put(item)
        for _ in range(count):
            await queue.put(None)
        await queue.join()


def load_config(path=ROOT / 'config.yml'):
    with path.open(encoding='utf-8') as file:
        cfg = yaml.safe_load(file)
    if cfg.get('elite_only') is not True:
        raise ValueError('elite_only must be true; non-elite publishing is unsupported')
    for key in ('max_ms', 'concurrency', 'max_judges', 'judge_validate_timeout',
                'source_timeout', 'source_concurrency', 'max_source_bytes', 'max_judge_bytes',
                'judge_concurrency', 'judge_max_rps', 'progress_every', 'nofile'):
        if not isinstance(cfg.get(key), (int, float)) or cfg[key] <= 0:
            raise ValueError(f'{key} must be positive')
    for key in ('concurrency', 'max_judges', 'source_concurrency', 'judge_concurrency',
                'max_source_bytes', 'max_judge_bytes', 'progress_every', 'nofile'):
        if not isinstance(cfg[key], int):
            raise ValueError(f'{key} must be an integer')
    if cfg['max_judges'] < 2:
        raise ValueError('max_judges must be at least 2 to cover HTTP and HTTPS')
    if not cfg['real_ip_urls'] or not cfg['judges'] or not cfg['sources']:
        raise ValueError('real_ip_urls, judges and sources must be nonempty')
    names = set()
    for service in cfg['services']:
        if not re.fullmatch(r'[a-z0-9][a-z0-9_-]*', service['name']) or service['name'] in names:
            raise ValueError('service names must be unique, safe lowercase file names')
        names.add(service['name'])
        if urlsplit(service['url']).scheme != 'https':
            raise ValueError('service URLs must use HTTPS')
    sc = cfg['service_check']
    for key in ('limit', 'concurrency', 'timeout', 'max_bytes'):
        if not isinstance(sc.get(key), int) or sc[key] <= 0:
            raise ValueError(f'service_check.{key} must be a positive integer')
    if not isinstance(cfg['checker_net']['days'], int) or cfg['checker_net']['days'] <= 0:
        raise ValueError('checker_net.days must be a positive integer')
    return cfg


def raise_nofile(target):
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(max(soft, target), hard), hard))
    except (ImportError, OSError, ValueError) as exc:
        LOG.info('File descriptor limit unchanged: %s', exc)


class Judge:
    def __init__(self, url, ms, cfg):
        self.url, self.ms = url, ms
        self.semaphore = asyncio.Semaphore(cfg['judge_concurrency'])
        self.lock = asyncio.Lock()
        self.next_start = 0.0
        self.interval = 1.0 / cfg['judge_max_rps']

    async def pace(self):
        async with self.lock:
            now = asyncio.get_running_loop().time()
            delay = max(0, self.next_start - now)
            self.next_start = max(now, self.next_start) + self.interval
        if delay:
            await asyncio.sleep(delay)


async def discover_ips(session, cfg):
    ips = set()
    for url in cfg['real_ip_urls']:
        try:
            result = await request(session, url, cfg['judge_validate_timeout'], cfg['max_judge_bytes'])
            if result.status != 200:
                raise ValueError(f'HTTP {result.status}')
            try:
                data = json.loads(result.body)
                value = data.get('ip', data.get('origin', '')) if isinstance(data, dict) else data
            except ValueError:
                value = result.body
            for part in str(value).strip().split(','):
                ip = ipaddress.ip_address(part.strip())
                if ip.is_global:
                    ips.add(str(ip))
        except (aiohttp.ClientError, OSError, ValueError, TimeoutError) as exc:
            LOG.warning('IP discovery skipped %s: %s', url, exc)
    if not ips:
        raise RuntimeError('Cannot determine runner IP; existing outputs preserved')
    return ips


async def validate_judges(session, cfg, ips):
    valid = []

    async def check(url):
        try:
            nonce = uuid.uuid4().hex
            result = await request(session, url, cfg['judge_validate_timeout'], cfg['max_judge_bytes'],
                                   headers={'X-Proxy-Pipeline-Nonce': nonce})
            dump = parse_judge(result.body)
            if result.status != 200 or not dump or not dump[0].intersection(ips) or not has_nonce(dump, nonce):
                raise ValueError('not a live runner-IP/header echo')
            valid.append(Judge(url, result.ms, cfg))
        except (aiohttp.ClientError, OSError, ValueError, TimeoutError) as exc:
            LOG.info('Judge skipped %s: %s', url, exc)

    await workers(list(dict.fromkeys(cfg['judges'])), cfg['source_concurrency'], check)
    valid.sort(key=lambda j: j.ms)
    selected = []
    # Reserve the fastest of each scheme so CONNECT cannot starve out HTTP.
    for scheme in ('http', 'https'):
        compatible = [j for j in valid if urlsplit(j.url).scheme == scheme]
        if not compatible:
            raise RuntimeError(f'No live {scheme} judge; existing outputs preserved')
        selected.append(compatible[0])
    selected += [j for j in valid if j not in selected][:cfg['max_judges'] - len(selected)]
    LOG.info('Selected %d live judges', len(selected))
    return selected


async def scrape(session, cfg):
    pools = {p: set() for p in POOLS}
    counts = {}

    async def fetch(url):
        try:
            result = await request(session, url, cfg['source_timeout'], cfg['max_source_bytes'],
                                   headers={'Content-Type': 'application/json'}, redirects=True)
            if result.status != 200:
                raise ValueError(f'HTTP {result.status}')
            parsed = extract(result.body, source_hint(url))
            counts[url] = {'status': 'ok', 'counts': {p: len(v) for p, v in parsed.items()}}
            for p in POOLS:
                pools[p].update(parsed[p])
            LOG.info('Source %s: %d protocol candidates', url, sum(map(len, parsed.values())))
        except (aiohttp.ClientError, OSError, ValueError, TimeoutError) as exc:
            counts[url] = {'status': 'error', 'error': str(exc)}
            LOG.warning('Source skipped %s: %s', url, exc)

    sources = list(dict.fromkeys(cfg['sources']))
    archive = cfg['checker_net']
    if archive['enabled']:
        url = archive['url'].rstrip('/')
        try:
            result = await request(session, url, cfg['source_timeout'], cfg['max_source_bytes'],
                                   headers={'Content-Type': 'application/json'})
            if result.status != 200:
                raise ValueError(f'HTTP {result.status}')
            dates = sorted(set(re.findall(r'\b\d{4}-\d{2}-\d{2}\b', result.body)), reverse=True)
            if not dates:
                raise ValueError('no archive dates returned')
            counts[url] = {'status': 'ok', 'dates': dates[:archive['days']]}
            sources.extend(f'{url}/{date}' for date in dates[:archive['days']])
        except (aiohttp.ClientError, OSError, ValueError, TimeoutError) as exc:
            counts[url] = {'status': 'error', 'error': str(exc)}
            LOG.warning('Archive skipped: %s', exc)
    random.shuffle(sources)
    await workers(sources, cfg['source_concurrency'], fetch)
    return pools, counts


async def via_proxy(session, cfg, protocol, address, url, timeout, maximum, **kwargs):
    # An https output record denotes HTTP CONNECT, not TLS to the proxy itself.
    if protocol in ('http', 'https'):
        return await request(session, url, timeout, maximum, proxy=f'http://{address}', **kwargs)
    try:
        async with asyncio.timeout(timeout):
            connector = ProxyConnector.from_url(f'{protocol}://{address}', rdns=True, limit=1)
            async with aiohttp.ClientSession(connector=connector, trust_env=False,
                                             cookie_jar=aiohttp.DummyCookieJar(),
                                             headers={'User-Agent': cfg['user_agent']}) as socks:
                return await request(socks, url, timeout, maximum, **kwargs)
    except (ProxyConnectionError, ProxyTimeoutError, ProxyError, EOFError) as exc:
        raise OSError(str(exc)) from exc


async def check_candidates(session, cfg, pools, judges, ips):
    jobs = [(p, address) for p in POOLS for address in pools[p]]
    jobs.extend(('https', address) for address in pools['http'])
    random.shuffle(jobs)
    by_scheme = {scheme: [j for j in judges if urlsplit(j.url).scheme == scheme]
                 for scheme in ('http', 'https')}
    working, checked = [], 0
    indices = {'http': 0, 'https': 0}

    async def check(job):
        nonlocal checked
        protocol, address = job
        scheme = 'https' if protocol == 'https' else 'http'
        available = by_scheme[scheme]
        judge = available[indices[scheme] % len(available)]
        indices[scheme] += 1
        try:
            async with judge.semaphore:
                await judge.pace()
                nonce = uuid.uuid4().hex
                start = time.perf_counter()
                result = await via_proxy(session, cfg, protocol, address, judge.url,
                                         cfg['max_ms'] / 1000, cfg['max_judge_bytes'],
                                         headers={'X-Proxy-Pipeline-Nonce': nonce})
                elapsed = (time.perf_counter() - start) * 1000
                if result.status == 200 and elapsed < cfg['max_ms'] and elite(result.body, ips, nonce):
                    working.append({'proxy': address, 'protocol': protocol, 'ms': elapsed})
        except (aiohttp.ClientError, OSError, ValueError, TimeoutError):
            pass
        checked += 1
        if checked % cfg['progress_every'] == 0:
            LOG.info('Checked %d/%d; passing %d', checked, len(jobs), len(working))

    await workers(jobs, cfg['concurrency'], check)
    working.sort(key=lambda row: (row['ms'], row['protocol'], row['proxy']))
    LOG.info('Checked %d; passing %d', checked, len(working))
    return working


async def check_services(session, cfg, working):
    sc = cfg['service_check']
    if not sc['enabled']:
        return
    eligible = [row for row in working if row['protocol'] != 'http'][:sc['limit']]

    async def check(job):
        row, service = job
        verdict = 'error'
        try:
            result = await via_proxy(session, cfg, row['protocol'], row['proxy'], service['url'],
                                     sc['timeout'], sc['max_bytes'], redirects=True)
            verdict = classify(result.status, result.url, result.headers, result.body, service)
        except (aiohttp.ClientError, OSError, ValueError, TimeoutError):
            pass
        row.setdefault('services', {})[service['name']] = verdict

    await workers(((row, service) for row in eligible for service in cfg['services']), sc['concurrency'], check)


def publish_files(destination, working, meta, cfg):
    if not working:
        raise RuntimeError('Zero survivors; existing outputs preserved')
    if any(row['ms'] >= cfg['max_ms'] for row in working):
        raise ValueError('Refusing to publish a proxy beyond the speed limit')
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.proxy-stage-', dir=destination.parent))
    backup = destination.with_name('.proxy-backup-' + uuid.uuid4().hex)
    try:
        def lines(path, values):
            path.write_text(''.join(v + '\n' for v in values), encoding='utf-8')

        def write_json(name, value):
            (stage / name).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')

        for protocol in OUTPUT_PROTOCOLS:
            lines(stage / f'{protocol}.txt', (r['proxy'] for r in working if r['protocol'] == protocol))
        key = lambda r: f"{r['protocol']}://{r['proxy']}"
        lines(stage / 'all.txt', map(key, working))
        write_json('proxies.json', working)
        write_json('services.json', {key(r): r['services'] for r in working if 'services' in r})
        (stage / 'by-service').mkdir()
        for service in cfg['services']:
            name = service['name']
            lines(stage / 'by-service' / f'{name}.txt',
                  (key(r) for r in working if r.get('services', {}).get(name) == 'ok'))
        write_json('meta.json', meta)
        # Build everything before swapping directories. Restore old data on an I/O failure.
        if destination.exists():
            destination.rename(backup)
        try:
            stage.rename(destination)
        except BaseException:
            if backup.exists():
                backup.rename(destination)
            raise
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    if backup.exists():
        shutil.rmtree(backup)


async def run(cfg, destination=ROOT / 'proxies'):
    started = datetime.now(timezone.utc).isoformat()
    raise_nofile(cfg['nofile'])
    # IPv4 egress is deliberate: discover the same runner address family used by tests.
    connector = aiohttp.TCPConnector(limit=cfg['concurrency'], family=socket.AF_INET, force_close=True)
    async with aiohttp.ClientSession(connector=connector, trust_env=False,
                                     cookie_jar=aiohttp.DummyCookieJar(),
                                     headers={'User-Agent': cfg['user_agent']}) as session:
        ips = await discover_ips(session, cfg)
        judges = await validate_judges(session, cfg, ips)
        pools, counts = await scrape(session, cfg)
        working = await check_candidates(session, cfg, pools, judges, ips)
        if not working:
            raise RuntimeError('Zero survivors; existing outputs preserved')
        await check_services(session, cfg, working)
    meta = {'started_at': started, 'timestamp': datetime.now(timezone.utc).isoformat(),
            'candidates': {p: len(v) for p, v in pools.items()},
            'checks': sum(map(len, pools.values())) + len(pools['http']),
            'working': {p: sum(r['protocol'] == p for r in working) for p in OUTPUT_PROTOCOLS},
            'judges': [{'url': j.url, 'direct_ms': j.ms} for j in judges],
            'sources': counts, 'max_ms': cfg['max_ms'], 'elite_only': True}
    publish_files(destination, working, meta, cfg)
    LOG.info('Published %d verified records to %s', len(working), destination)


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    try:
        asyncio.run(run(load_config()))
    except (Exception, KeyboardInterrupt) as exc:
        LOG.error('Run aborted: %s', exc)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
