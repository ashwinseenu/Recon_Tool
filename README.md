# ReconForge 2.0

Infrastructure and attack-surface OSINT framework for **Linux** (Debian 11+, Ubuntu 22.04+, RHEL / Rocky / Alma / CentOS Stream 8+).
One CLI and one local dashboard run 21 modules over a domain or IP: DNS, email security, RDAP, certificate transparency,
subdomain discovery, threat intel, look-alike domains, IP intelligence, exposure data, and (scope-gated) TLS, HTTP, port and exposure checks.

**Out of scope by design:** profiling private individuals (username hunting, phone/address/face lookups).

## Install
```bash
sudo ./scripts/install.sh              # system install, configures Tor
./scripts/install.sh --user            # no root
docker compose up -d --build           # Docker (dashboard on 127.0.0.1:8787)
```
Then: `reconforge doctor`.

## Use
```bash
reconforge keys setup                  # optional API keys
reconforge scope add example.com       # authorise active modules for systems you own/are permitted to test
reconforge scan example.com            # all modules; --passive-only never touches the target
reconforge serve                       # dashboard, prints a tokenised link
```
Reports: `reconforge report list|show|export`, formats JSON/HTML/Markdown/CSV.

## Anonymity
`proxy.mode`: `tor` (default), `proxy`, `chain` (Tor then your proxy via proxychains4), `direct`. Fail-closed: if the egress
is not verified, scans refuse to run. DNS goes through DNS-over-HTTPS inside the same tunnel, so it does not leak.
Tor gives network anonymity, not immunity: do not log in to personal accounts while scanning.

## Safety
Active modules (TLS, HTTP, ports, exposure checks, nmap) only touch targets in your scope allowlist. Use only on systems you
are authorised to test. See docs/LEGAL.md. Docs: docs/INSTALL.md, docs/USAGE.md.

License: MIT
