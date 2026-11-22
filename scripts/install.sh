#!/usr/bin/env bash
# ReconForge installer - Debian/Ubuntu (and derivatives) and RHEL/Rocky/Alma/CentOS Stream/Fedora.
#   sudo ./scripts/install.sh            system install (/opt/reconforge, /usr/local/bin/reconforge)
#   ./scripts/install.sh --user          per-user install (~/.local), no root; Tor/proxychains need root separately
#   sudo ./scripts/install.sh --uninstall [--purge]
# Options: --no-tor  --no-extras  --service (systemd unit for the dashboard)  --yes
set -euo pipefail

PREFIX_SYS=/opt/reconforge
BIN_SYS=/usr/local/bin/reconforge
MODE=system; DO_TOR=1; DO_EXTRAS=1; DO_SERVICE=0; UNINSTALL=0; PURGE=0; ASSUME_YES=0
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { printf '\033[1;34m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# ---- distro detection (testable: RF_OS_RELEASE overrides the file) ---------------
detect_distro() {
  local f="${RF_OS_RELEASE:-/etc/os-release}"
  [ -r "$f" ] || die "Cannot read $f - unsupported system"
  # shellcheck disable=SC1090
  ( . "$f"; echo "${ID:-unknown}|${ID_LIKE:-}|${VERSION_ID:-0}|${PRETTY_NAME:-$ID}" )
}

family_of() {  # id id_like -> debian|rhel|unsupported
  local id="$1" like=" $2 "
  case "$id" in
    debian|ubuntu|kali|parrot|linuxmint|pop|raspbian) echo debian; return;;
    rhel|rocky|almalinux|centos|ol|fedora|amzn) echo rhel; return;;
  esac
  case "$like" in
    *" debian "*|*" ubuntu "*) echo debian;;
    *" rhel "*|*" fedora "*|*" centos "*) echo rhel;;
    *) echo unsupported;;
  esac
}

major() { echo "${1%%.*}"; }

check_supported() {  # family id version
  local fam="$1" id="$2" ver="$3" m; m=$(major "$ver")
  [ "$fam" != unsupported ] || die "Unsupported distribution '$id'. Supported: Debian 11+, Ubuntu 22.04+, RHEL/Rocky/Alma/CentOS Stream 8+."
  case "$id" in
    debian) [ "${m:-0}" -ge 11 ] || die "Debian 11 or newer required (found $ver)";;
    ubuntu) [ "${m:-0}" -ge 22 ] || die "Ubuntu 22.04 or newer required (found $ver)";;
    rhel|rocky|almalinux|centos|ol) [ "${m:-0}" -ge 8 ] || die "RHEL-family 8 or newer required (found $ver)";;
  esac
}

# ---- python discovery ---------------------------------------------------------------
find_python() {
  local c v
  for c in python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
    if command -v "$c" >/dev/null 2>&1; then
      v=$("$c" -c 'import sys;print("%d%02d"%sys.version_info[:2])' 2>/dev/null || echo 0)
      if [ "$v" -ge 309 ]; then command -v "$c"; return 0; fi
    fi
  done
  return 1
}

# ---- packages -----------------------------------------------------------------------------
SUDO=""; [ "$(id -u)" -eq 0 ] || SUDO="sudo"

install_packages() {  # family id version
  local fam="$1" id="$2" ver="$3" m; m=$(major "$ver")
  if [ "$fam" = debian ]; then
    export DEBIAN_FRONTEND=noninteractive
    $SUDO apt-get update -qq
    local pk=(python3 python3-venv python3-pip ca-certificates openssl)
    [ "$DO_TOR" = 1 ] && pk+=(tor)
    [ "$DO_EXTRAS" = 1 ] && pk+=(proxychains4 nmap)
    $SUDO apt-get install -y -qq "${pk[@]}"
  else
    local mgr=dnf; command -v dnf >/dev/null 2>&1 || mgr=yum
    if [ "$id" != fedora ] && [ "$id" != amzn ]; then
      $SUDO $mgr install -y epel-release || warn "Could not install EPEL (Tor/proxychains may be unavailable)"
      if [ "$m" -ge 8 ]; then $SUDO $mgr config-manager --set-enabled crb 2>/dev/null \
        || $SUDO $mgr config-manager --set-enabled powertools 2>/dev/null || true; fi
    fi
    local pk=(python3 python3-pip ca-certificates openssl)
    # RHEL/Rocky 8 ships Python 3.6 by default: use an AppStream 3.9+ module if needed
    if [ "$m" = 8 ] && [ "$id" != fedora ]; then pk=(python39 python39-pip ca-certificates openssl); fi
    [ "$DO_TOR" = 1 ] && pk+=(tor)
    [ "$DO_EXTRAS" = 1 ] && pk+=(proxychains-ng nmap)
    for p in "${pk[@]}"; do
      $SUDO $mgr install -y "$p" || warn "Package '$p' not available - continuing"
    done
  fi
}

# ---- tor configuration --------------------------------------------------------------------
tor_service_name() {
  if systemctl list-unit-files 2>/dev/null | grep -q '^tor@default'; then echo tor@default; else echo tor; fi
}

configure_tor() {  # echoes the generated control password to stdout (caller stores it)
  command -v tor >/dev/null 2>&1 || { warn "tor not installed; skipping Tor setup"; return 1; }
  local pw hashed rc=/etc/tor/torrc
  pw=$(openssl rand -hex 16)
  hashed=$(tor --hash-password "$pw" 2>/dev/null | tail -n1)
  [ -n "$hashed" ] || { warn "Could not hash Tor control password"; return 1; }
  $SUDO mkdir -p /etc/tor
  if ! $SUDO grep -q '# reconforge-managed' "$rc" 2>/dev/null; then
    $SUDO cp -a "$rc" "$rc.reconforge.bak" 2>/dev/null || true
    {
      echo ""
      echo "# reconforge-managed"
      echo "SocksPort 127.0.0.1:9050"
      echo "ControlPort 127.0.0.1:9051"
      echo "HashedControlPassword $hashed"
    } | $SUDO tee -a "$rc" >/dev/null
  else
    $SUDO sed -i "s|^HashedControlPassword .*|HashedControlPassword $hashed|" "$rc"
  fi
  if ! $SUDO tor --verify-config -f "$rc" >/dev/null 2>&1; then
    warn "tor --verify-config failed; restoring the original torrc"
    [ -f "$rc.reconforge.bak" ] && $SUDO cp -a "$rc.reconforge.bak" "$rc"
    return 1
  fi
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    $SUDO systemctl enable --now "$(tor_service_name)" >/dev/null 2>&1 || warn "Could not start Tor service"
    $SUDO systemctl restart "$(tor_service_name)" >/dev/null 2>&1 || true
  else
    $SUDO service tor restart >/dev/null 2>&1 || warn "systemd not running: start Tor manually ('tor &')"
  fi
  echo "$pw"
}

# ---- main install -----------------------------------------------------------------------------
do_install() {
  local info id like ver pretty fam py
  info=$(detect_distro); IFS='|' read -r id like ver pretty <<<"$info"
  fam=$(family_of "$id" "$like")
  log "Detected: $pretty (family: $fam)"
  check_supported "$fam" "$id" "$ver"

  if [ "$MODE" = system ]; then
    [ "$(id -u)" -eq 0 ] || command -v sudo >/dev/null 2>&1 || die "Run as root or install sudo"
    install_packages "$fam" "$id" "$ver"
  else
    log "User mode: skipping system packages (install tor/proxychains4/nmap yourself if wanted)"
  fi

  py=$(find_python) || die "Python 3.9+ not found. On RHEL/Rocky 8: 'sudo dnf install python39'."
  log "Using $($py --version) at $py"

  local prefix bin
  if [ "$MODE" = system ]; then prefix=$PREFIX_SYS; bin=$BIN_SYS
  else prefix="${XDG_DATA_HOME:-$HOME/.local/share}/reconforge"; bin="$HOME/.local/bin/reconforge"; fi

  $SUDO_IF_SYSTEM mkdir -p "$prefix" "$(dirname "$bin")"
  log "Creating virtualenv in $prefix"
  $SUDO_IF_SYSTEM "$py" -m venv "$prefix/venv" || die "venv creation failed (Debian/Ubuntu: apt install python3-venv)"
  $SUDO_IF_SYSTEM "$prefix/venv/bin/pip" install -q --upgrade pip
  $SUDO_IF_SYSTEM "$prefix/venv/bin/pip" install -q "$SRC_DIR"
  $SUDO_IF_SYSTEM ln -sf "$prefix/venv/bin/reconforge" "$bin"

  local cfgdir
  cfgdir=${XDG_CONFIG_HOME:-$HOME/.config}/reconforge

  if [ "$MODE" = system ] && [ "$DO_TOR" = 1 ]; then
    if pw=$(configure_tor); then
      local runas=""; [ -n "${SUDO_USER:-}" ] && [ "$(id -u)" -eq 0 ] && runas="sudo -u $SUDO_USER -H"
      $runas "$bin" config set tor.control_password "$pw" >/dev/null 2>&1 && log "Tor control password stored in $cfgdir (mode 600)"
    fi
  fi

  if [ "$DO_SERVICE" = 1 ] && [ "$MODE" = system ]; then install_service "$bin"; fi

  log "Done. Try:  reconforge doctor   |   reconforge keys setup   |   reconforge scope add example.com   |   reconforge scan example.com"
  case ":$PATH:" in *":$(dirname "$bin"):"*) ;; *) warn "$(dirname "$bin") is not on your PATH";; esac
}

install_service() {
  local bin="$1" user="${SUDO_USER:-root}"
  $SUDO tee /etc/systemd/system/reconforge-web.service >/dev/null <<UNIT
[Unit]
Description=ReconForge dashboard (loopback only)
After=network-online.target tor.service

[Service]
User=$user
ExecStart=$bin serve
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
UNIT
  $SUDO systemctl daemon-reload && $SUDO systemctl enable --now reconforge-web >/dev/null 2>&1 || warn "Could not start reconforge-web"
}

do_uninstall() {
  local prefix bin
  if [ "$MODE" = system ]; then prefix=$PREFIX_SYS; bin=$BIN_SYS; else prefix="${XDG_DATA_HOME:-$HOME/.local/share}/reconforge"; bin="$HOME/.local/bin/reconforge"; fi
  if [ -f /etc/systemd/system/reconforge-web.service ]; then
    $SUDO systemctl disable --now reconforge-web >/dev/null 2>&1 || true
    $SUDO rm -f /etc/systemd/system/reconforge-web.service; $SUDO systemctl daemon-reload || true
  fi
  $SUDO_IF_SYSTEM rm -rf "$prefix"; $SUDO_IF_SYSTEM rm -f "$bin"
  if [ "$PURGE" = 1 ]; then
    rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/reconforge" "${XDG_DATA_HOME:-$HOME/.local/share}/reconforge"
    log "Purged config, keys and scan results"
  else
    log "Kept your config/keys/results (use --purge to delete them)"
  fi
  log "Uninstalled. (Tor and other system packages were left in place.)"
}

main() {
  while [ $# -gt 0 ]; do case "$1" in
    --user) MODE=user;; --no-tor) DO_TOR=0;; --no-extras) DO_EXTRAS=0;; --service) DO_SERVICE=1;;
    --uninstall) UNINSTALL=1;; --purge) PURGE=1;; --yes|-y) ASSUME_YES=1;;
    -h|--help) sed -n '2,6p' "$0"; exit 0;;
    *) die "Unknown option: $1";; esac; shift; done
  [ "$(uname -s)" = Linux ] || die "ReconForge supports Linux only"
  SUDO_IF_SYSTEM=""; [ "$MODE" = system ] && SUDO_IF_SYSTEM="$SUDO"
  [ "$UNINSTALL" = 1 ] && { do_uninstall; exit 0; }
  do_install
}

# Allow tests to source the functions without running anything
if [ "${RF_SOURCE_ONLY:-0}" != 1 ]; then main "$@"; fi
