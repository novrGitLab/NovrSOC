#!/usr/bin/env bash
# Shows which scanning tools the worker user can run and their versions, and flags a common
# mistake: a Python "httpx" client on PATH instead of ProjectDiscovery's httpx. Read-only; scans
# nothing. Usage: ./verify-tools.sh   (as root or the novrsoc-vms user)
set -uo pipefail
RUN() { if [ "$(id -un)" = novrsoc-vms ]; then "$@"; else runuser -u novrsoc-vms -- "$@"; fi; }
printf '%-10s %-40s %s\n' tool path version
for t in subfinder dnsx httpx nmap nuclei; do
  p="$(RUN bash -c "command -v $t" 2>/dev/null || true)"
  if [ -z "$p" ]; then printf '%-10s %-40s %s\n' "$t" "-" "NOT INSTALLED"; continue; fi
  if [ "$t" = nmap ]; then v="$(RUN "$p" --version 2>&1 | head -1)"; else v="$(RUN "$p" -version 2>&1 | grep -iE 'version' | head -1)"; fi
  printf '%-10s %-40s %s\n' "$t" "$p" "${v:-unknown}"
  if [ "$t" = httpx ] && ! RUN "$p" -version 2>&1 | grep -qi 'current version'; then
    echo "           WARNING: this httpx does not look like ProjectDiscovery's; set VMS_HTTPX_PATH to the right binary"
  fi
done
if RUN python3 -c 'import gvm' 2>/dev/null; then
  echo "openvas    python-gvm $(RUN python3 -c 'import gvm; print(gvm.get_version())')"
  SOCK="${GVM_SOCKET:-/run/gvmd/gvmd.sock}"
  if [ ! -S "$SOCK" ]; then echo "           gvmd socket $SOCK NOT FOUND (is gvmd running? set GVM_SOCKET)";
  elif RUN test -r "$SOCK" -a -w "$SOCK"; then echo "           gvmd socket $SOCK usable by novrsoc-vms ($(stat -c '%U:%G %a' "$SOCK"))";
  else echo "           gvmd socket $SOCK NOT usable by novrsoc-vms ($(stat -c '%U:%G %a' "$SOCK")): usermod -aG $(stat -c %G "$SOCK") novrsoc-vms"; fi
  echo "           login, scan configuration and its safety: python3 worker.py --self-test"
else echo "openvas    NOT CONFIGURED (python-gvm absent: sudo apt-get install python3-gvm)"; fi
python3 --version
python3 -c 'import requests; print("requests", requests.__version__)'
