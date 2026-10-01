# Validation record

Checked on 2026-09-30 with Python 3.12 on Windows.

* **20 automated tests passed.** Coverage includes protocol hints and overrides,
  recursive JSON and HTML extraction, invalid/global address filtering, all forbidden
  elite headers, runner-IP leaks, fresh judge tokens, service classification, a bounded
  10,000-item queue, dead sources, archive date selection, unchanged files after failed
  judge validation, zero-survivor output preservation, actual HTTP proxy routing,
  actual CONNECT negotiation, truncated SOCKS handshakes, full-body deadlines,
  and Git publication against a temporary local bare repository.
* **Dependency check passed** with the pinned top-level requirements.
* **Live archive checks passed.** Both checker.net archive endpoints returned HTTP
  200. The daily archive had 22,250 entries before address filtering and deduplication.
* **Live judge checks passed.** Proxyscrape judge 1, HTTP/HTTPS httpbingo and HTTP/HTTPS
  httpbin passed the IP, parseable-header and nonce requirements at check time.
* **Live scrape and sample validation passed.** Monosans HTTP text, ProxyScrape JSON,
  Geonode JSON and the newest checker.net archive were retrieved and parsed. A bounded
  sample of 40 candidates from each protocol pool produced 160 checks, including HTTP
  and CONNECT separately. Four records passed with elapsed times of approximately
  818, 1255, 1561 and 2748 ms. Six configured services were probed through the three
  HTTPS-capable survivors, and output generation completed.

The live sample files are deliberately not bundled as a current proxy list. Run the
workflow to generate a fresh snapshot in your own repository. A full 100k–500k run
and execution on a hosted GitHub runner have not been performed here. The workflow
has not been installed or enabled in a remote repository because none was supplied.
