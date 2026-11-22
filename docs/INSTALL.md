# Install

| Distro | Versions | Notes |
|---|---|---|
| Debian / Kali / Parrot | 11+ | apt: tor, proxychains4, nmap |
| Ubuntu / Mint / Pop | 22.04+ | apt |
| RHEL / Rocky / Alma / CentOS Stream | 8+ | EPEL + CRB enabled automatically; RHEL 8 uses python39 |

`sudo ./scripts/install.sh` installs to `/opt/reconforge`, links `/usr/local/bin/reconforge`, installs Tor, writes a
managed block to `/etc/tor/torrc` with a random hashed control password (stored in your reconforge config, mode 600), and
checks it with `tor --verify-config`. Options: `--user`, `--no-tor`, `--no-extras`, `--service` (systemd dashboard), `--uninstall [--purge]`.

If Tor can't be reached: `sudo systemctl enable --now tor` (or `tor@default`). On RHEL with SELinux, the default ports 9050/9051 are allowed.
Docker: `docker compose up -d --build`; open the tokenised link from `docker compose logs reconforge`.
