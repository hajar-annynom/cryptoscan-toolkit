# CryptoScan-Toolkit

Asynchronous CLI scanner that audits **TLS/SSL configuration, certificate
chains, and SSH cipher suites** across a range of hosts, and reports findings
with CVSS-style severity ratings.

Built as a portfolio project during an M2 in Cryptography & Information
Security — the goal is a small, correct, well-tested tool rather than a
feature-maximal one.

## Why

Most crypto-audit tools (`testssl.sh`, `sslyze`) are excellent but opaque as
learning material. This project re-implements a focused subset of their
checks from first principles in Python, to demonstrate:
- Applied understanding of TLS handshake internals and SSH KEX negotiation
- Production-grade `asyncio` concurrency (bounded, cancellation-safe, no
  event-loop blocking calls)
- Clean architecture: scanners, engine, and reporting never share state
  directly — everything flows through typed dataclasses (see `ARCHITECTURE.md`)

## Quickstart

```bash
pip install -e .
cryptoscan example.com --ports 443 8443 --output html --out-file report.html
```

Or via Docker, against bundled deliberately-misconfigured targets:

```bash
docker compose up --build
```

## Sample output

```
              CryptoScan-Toolkit — Findings
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Severity ┃ Target           ┃ Finding                     ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ HIGH     │ 10.0.0.5:4433    │ Weak cipher suite: RC4-SHA  │
│ HIGH     │ 10.0.0.5:4433    │ Deprecated protocol: TLSv1.1│
└──────────┴──────────────────┴─────────────────────────────┘
```

## Architecture

See `ARCHITECTURE.md` for the full data-flow diagram and class reference.
In short: `cli` → `core.engine` → `scanners.*` → `core.models.AuditResult`
→ `report.render`. Each arrow is a dataclass boundary, not a direct import,
so any layer can be swapped or unit-tested in isolation.

## Testing

```bash
pip install -e ".[pdf]" && pip install -r requirements-dev.txt
make unit          # pure logic, no network
make integration   # real TCP against local fixtures (fake SSH server + legacy openssl s_server)
```

Try the CLI by hand against deliberately weak local targets (two terminals):

```bash
make demo-ssh                                   # terminal 1  -> 127.0.0.1:2222
cryptoscan 127.0.0.1 -p 2222 --protocol ssh     # terminal 2
make demo-tls                                   # terminal 1  -> 127.0.0.1:4433
cryptoscan 127.0.0.1 -p 4433 --protocol tls     # terminal 2
```

Optional Docker fixtures: `make docker-up && make docker-scan && make docker-down`.

## How it works

* **TLS** - active probing: one deliberately permissive handshake per protocol version
  (TLS 1.0-1.3) and per weak cipher family (RC4, 3DES, EXPORT, NULL, anonymous), plus
  certificate analysis (expiry, self-signed, key size, signature hash, hostname).
* **SSH** - reads the server's `SSH_MSG_KEXINIT` to list *every* advertised KEX / host-key /
  cipher / MAC algorithm. No authentication is ever attempted.

## Known limitations

* SSLv2/SSLv3 cannot be probed (Python's `ssl` module does not speak them).
* Cipher families the local OpenSSL cannot offer are reported as `TLS-PROBE-SKIPPED` (INFO):
  "unknown", never "safe".
* `openssl s_server` serves one client at a time: use `--protocol tls|ssh` against it.

## Status

Early-stage / actively developed. TLS protocol/cipher/certificate checks and SSH algorithm
auditing work; SSH host-key *size* checks and STARTTLS are next.

## Legal / ethical use

Only scan hosts you own or are explicitly authorized to test. The bundled
`docker-compose.yml` targets are local, deliberately-vulnerable containers
provided for safe demonstration and development.

## License

MIT
