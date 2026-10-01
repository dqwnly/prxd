# Verified proxy snapshot pipeline

Runs on GitHub Actions every four hours, on manual dispatch, and when configuration,
scripts, tests or the workflow change. All 92 supplied sources, nine additional
sources, checker.net daily archives and all 135 supplied judge entries are included.
Dead sources are logged and skipped. No unverified proxy files are bundled.

## Setup

1. Copy the contents of this directory, **including `.github/`**, to the root of a
   GitHub repository and commit them to its default branch.
2. Enable Actions and allow the workflow to write repository contents. Branch
   protection must permit the bot's results commit, or configure a separate data branch.
3. Open **Actions → Refresh verified proxies → Run workflow**. Scheduled runs use
   the default branch. Other branches run tests but do not publish.
4. After a successful run, consume files at
   `https://raw.githubusercontent.com/OWNER/REPO/BRANCH/proxies/http.txt`
   (replace OWNER, REPO and BRANCH). Other filenames follow the same pattern.

Local use, with Python 3.11 or newer:

```sh
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python scripts/proxy_pipeline.py
```

The script locates `config.yml` beside this README regardless of the current
directory. It writes local results only; `scripts/publish_results.py` is the
separate Git publication step. Failures exit nonzero. If public-IP discovery,
either judge scheme, or every proxy fails, existing `proxies/` files are preserved.

## Configuration

`config.yml` contains all runtime settings, source and judge URLs, service markers,
timeouts, byte limits, concurrency, rate limits and publication settings. `elite_only`
must remain true. `max_ms` is the strict upper bound (default 5000); queue/rate-limit
wait is excluded, while connection setup and the full response body are included.

GitHub requires the triggering cron, workflow permissions, concurrency and job timeout
to be declared in workflow YAML; it cannot load these from a repository config before
starting a job. Consequently those platform settings are the explicit exception to
single-file configuration: the cron is `23 */4 * * *`, and the refresh timeout is
230 minutes. Both can be edited in `.github/workflows/proxies.yml`. Schedules may
be delayed by GitHub; they are not a timing guarantee.

Sources use protocol hints from path tokens or explicit query fields, never from
the URL's scheme or hostname. `https` and `connect` enter the HTTP pool. Explicit
DSN schemes override hints; credentials are discarded. Authentication-required
proxies therefore fail validation rather than publishing credentials. Unknown
protocols are tried as HTTP, SOCKS4 and SOCKS5; generic `socks` is tried as both SOCKS
versions. JSON records, nested lists, DSNs and ordinary HTML table rows are supported.
JS-only or obfuscated ports cannot be recovered without a site-specific API; these
sources may yield zero records. Pagination is controlled by the URLs in config.

## Verification and scale

At each run, independent direct IP services discover runner IPv4 egress addresses.
Direct connections use IPv4 consistently. Judges must return 200, a parseable origin
and header dump, the runner IP, and a fresh random header nonce. Redirects are refused
for judge tests. This drops dead hosts, static documentation, login pages and stale
responses. The fastest judge of each scheme is retained first, then the fastest
remaining judges, up to `max_judges`. Both HTTP and HTTPS judges are required.

Each HTTP candidate receives a plain HTTP test and a separate HTTPS CONNECT test.
SOCKS4/5 are tested against plain HTTP judges. Every successful record requires a
fresh nonce, a clean header dump, no runner IP anywhere in the response, no forbidden
proxy-identifying headers, status 200 and elapsed time strictly below `max_ms`.
TLS certificates are verified. A proxy never gets a direct-request fallback.
Response byte limits guard against oversized judge/source/service responses.

Candidates are shuffled and deduplicated by protocol. A bounded queue feeds a fixed
worker pool, instead of creating hundreds of thousands of tasks. Linux descriptor
limits are raised when possible. Per-judge concurrency and request start rate are
capped to spread load; defaults cap each selected judge at 50 starts/second. At that
rate, very large HTTP pools with only one live HTTP or HTTPS judge can approach the
job timeout. Lower service limits, select additional reliable judges, or adjust rates
for judges you control. A timeout before publication preserves the old Git snapshot.
Public fallback judges can also be unavailable or rate-limited; none is guaranteed.

HTTP forwarding judges are untrusted: nonce checking prevents accidental cached/static
passes but does not prove that a malicious proxy or judge is honest. These checks
measure observed behavior, not a security guarantee.

## Outputs

| Path under `proxies/` | Contents |
| --- | --- |
| `http.txt`, `https.txt`, `socks4.txt`, `socks5.txt` | `ip:port`, fastest first; IPv6 uses `[ip]:port` |
| `all.txt` | `protocol://ip:port`, globally fastest first |
| `proxies.json` | Records with `proxy`, `protocol`, `ms` and optional `services` |
| `services.json` | Tested protocol-qualified endpoints mapped to service verdicts |
| `by-service/NAME.txt` | Protocol-qualified endpoints with an `ok` verdict |
| `meta.json` | UTC timestamps, candidate/check/working counts, selected judges and source results |

`https://` in these output records means **HTTP CONNECT capability**, not a TLS
connection to the proxy itself. Configure clients to contact that proxy with an
`http://` proxy URL when using HTTPS destinations.

Service tests select the fastest HTTPS/SOCKS records up to `service_check.limit` and
follow at most five redirects. HTTP-only records are skipped. Captcha markers take
precedence over status codes; 403/429 and missing success markers on 200 are blocked;
other errors/timeouts are error. Absent results mean **not tested**, not allowed.
`cloudflare` tests the configured Cloudflare website, not all Cloudflare-protected
sites. Service markers are simple heuristics and should be adjusted as sites change.

Files are built in a temporary directory and swapped only after successful validation
and service checks. A failed swap attempts to restore the previous directory. This
is not a crash-atomic transaction for concurrent local readers; Git commits present
the entire snapshot together. Removed services have their old allowlists removed.

## Git publication and history

Only `proxies/` changes are staged using an isolated Git index. A commit is created
only if the complete resulting tree differs. Metadata includes a new timestamp and
latencies, so successful refreshes normally change files even if endpoints match.
The workflow's fixed concurrency group prevents overlapping runs. Generated files
do not match the push trigger. A moving default branch causes publication to abort
instead of committing results generated from an outdated config. Rerun after that.

To keep one data snapshot rather than grow history, explicitly configure:

```yaml
publish:
  branch: data
  mode: snapshot
```

This creates a **data-only orphan commit** and replaces that separate branch using
`--force-with-lease`. It discards that branch's previous history and all non-results
files; use a dedicated branch. Snapshot mode refuses the checked-out default branch.
Consumers then use `/OWNER/REPO/data/proxies/...`. GitHub must permit force pushes
on that dedicated branch. `mode: history` retains normal history. Publication failures
leave the remote branch unchanged; no automatic force push happens in history mode.

## Limits and external references

* Elite detection is meaningful over plain HTTP. Through CONNECT the proxy cannot
  inject HTTP headers: `https.txt` means the tunnel works quickly and the response
  does not expose the known runner IP; it does not prove plain HTTP anonymity.
* Free proxies can die within minutes. Files are snapshots of successful checks,
  not a promise that endpoints remain alive when downloaded.
* Service results reflect one request through that proxy from a GitHub runner.
  Google and Cloudflare verdicts can vary on the next request.
* Checker.net was live-checked on 2026-09-30: the index returned
  `data.items[{date, proxyCount}]`, and the daily endpoint returned
  `data.{date, proxyList}` with 22,250 entries. The parser still walks generically
  because the documentation does not guarantee these inner shapes.

References: [archive index docs](https://docs.checker.net/en/operations/get-v1-landing-archive.html),
[daily archive docs](https://docs.checker.net/en/operations/get-v1-landing-archive-%7Bdate%7D.html),
[aiohttp client](https://docs.aiohttp.org/en/stable/client_quickstart.html),
[SOCKS connector](https://github.com/romis2012/aiohttp-socks), and
[GitHub workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).
