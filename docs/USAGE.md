# Usage
- `reconforge modules` lists modules (phase 1 discovery, 2 resolution, 3 enrichment, 4 active).
- `reconforge scan TARGET -m dns -m rdap` select modules; `-x NAME` exclude; `--fail-on high` for CI exit codes.
- `reconforge check` verifies your egress IP and Tor; `reconforge newid` requests a fresh Tor circuit.
- `reconforge config show|set KEY VALUE`, e.g. `config set proxy.mode chain`, `config set proxy.url socks5://host:1080`.
- Keys: shodan, virustotal, abuseipdb, otx, securitytrails. Modules without a key are skipped; keyless sources always run.
- Precedence: environment > reconforge.env > local.yaml > defaults.
