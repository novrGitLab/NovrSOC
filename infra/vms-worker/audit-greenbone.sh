#!/usr/bin/env bash
# READ-ONLY audit of the VPS against docs/runbooks/vms-openvas.md (native or container-based Greenbone).
# It installs nothing, changes no file or setting, restarts nothing, and starts no scan.
# Secrets are never printed: worker.env values are shown only for non-secret settings, and the
# Greenbone password and worker token only as "set"/"empty".
# Run as:  sudo bash audit-greenbone.sh 2>&1 | tee greenbone-audit.txt
#   --with-gvmd-queries  also list Greenbone users and scanners with `gvmd --get-users/--get-scanners`.
#                        Off by default: they only read, but they open gvmd's database as a helper,
#                        which writes a log line and a short-lived lock file.
set -u
GVMD_QUERIES=0; [ "${1:-}" = --with-gvmd-queries ] && GVMD_QUERIES=1
H() { printf '\n=== %s\n' "$*"; }
[ "$(id -u)" = 0 ] || { echo "run with sudo (read-only; needed for docker and the worker's env file)"; exit 2; }

H "1. Host"
echo "$(hostname) | $(. /etc/os-release; echo "$PRETTY_NAME") | $(nproc) vCPU | $(free -g | awk '/Mem:/{print $2}') GB RAM | disk free: $(df -h / | awk 'NR==2{print $4}')"

H "2. NovrSOC worker"
systemctl is-active novrsoc-vms-worker
systemctl show novrsoc-vms-worker -p User -p Group -p SupplementaryGroups -p ProtectSystem -p ReadWritePaths --no-pager
echo "version: $(grep -oP "^VERSION = '\K[^']+" /opt/novrsoc-vms/worker.py 2>/dev/null || echo unknown)"
ENVF=/opt/novrsoc-vms/worker.env
if [ -f "$ENVF" ]; then
  stat -c 'worker.env: %U:%G %a' "$ENVF"
  for k in VMS_WORKER_ID VMS_WORKER_KINDS VMS_WORKER_NETWORKS GVM_SOCKET GVM_USER GVM_CONFIG_ID GVM_SCANNER_ID GVM_PORT_LIST_ID GVM_OPENVAS_CONF GVM_ALIVE_TEST; do
    v="$(grep -E "^$k=" "$ENVF" | tail -1 | cut -d= -f2-)"; echo "  $k=${v:-<unset>}"
  done
  for k in GVM_PASSWORD VMS_WORKER_TOKEN; do
    v="$(grep -E "^$k=" "$ENVF" | tail -1 | cut -d= -f2-)"; echo "  $k: $([ -n "$v" ] && echo set || echo empty)"
  done
fi
id novrsoc-vms

H "3. No native Greenbone (the containers must be the only install)"
dpkg -l 2>/dev/null | awk '/^ii/ && /gvm|greenbone|openvas|ospd|gsad/ {print "  package:", $2, $3}'
for s in gvmd ospd-openvas gsad notus-scanner openvasd; do printf '  service %-14s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null)"; done
for p in /run/gvmd/gvmd.sock /run/ospd/ospd-openvas.sock /etc/openvas/openvas.conf; do [ -e "$p" ] && echo "  host path exists: $p"; done

H "4. Greenbone containers"
docker --version
docker compose version 2>/dev/null
docker ps -a --format '{{.Names}} | {{.Image}} | {{.Status}} | {{.Ports}}' | grep -iE 'gvm|greenbone|openvas|ospd|gsa|notus|redis|pg-gvm|vulnerability|scap|cert|data-objects|report-formats|gpg' || echo "  (no Greenbone containers found)"
GVMD="$(docker ps --format '{{.Names}}' | grep -E '(^|[-_])gvmd([-_][0-9]+)?$' | head -1)"
OSPD="$(docker ps --format '{{.Names}}' | grep -E '(^|[-_])ospd-openvas([-_][0-9]+)?$' | head -1)"
echo "gvmd container: ${GVMD:-NOT FOUND} | ospd-openvas container: ${OSPD:-NOT FOUND}"
if [ -n "$GVMD" ]; then
  echo "compose project: $(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$GVMD")"
  echo "compose dir:     $(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$GVMD")"
  echo "compose files:   $(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.config_files"}}' "$GVMD")"
  echo "gvmd image:      $(docker inspect -f '{{.Config.Image}}' "$GVMD")"
  echo "gvmd version:    $(docker exec -u gvmd "$GVMD" gvmd --version 2>&1 | head -2 | tr '\n' ' ')"
fi

H "5. gvmd socket: where it is and who may use it"
if [ -n "$GVMD" ]; then
  docker inspect -f '{{range .Mounts}}{{.Type}} {{.Name}} {{.Source}} -> {{.Destination}}{{"\n"}}{{end}}' "$GVMD" | sed 's/^/  mount: /'
  SRC="$(docker inspect -f '{{range .Mounts}}{{if eq .Destination "/run/gvmd"}}{{.Source}}{{end}}{{end}}' "$GVMD")"
  echo "socket dir on host: ${SRC:-<no /run/gvmd mount: socket not shared with the host>}"
  if [ -n "$SRC" ]; then
    SOCK="$SRC/gvmd.sock"
    stat -c '  %n: %F, owner %u(%U):%g(%G), mode %a' "$SOCK" 2>&1
    echo "  socket uid/gid inside the container: $(docker exec "$GVMD" stat -c '%u:%g %a' /run/gvmd/gvmd.sock 2>&1)"
    d="$SOCK"; while d="$(dirname "$d")"; [ "$d" != / ]; do stat -c '  path %n: %U:%G %a' "$d"; done
    if runuser -u novrsoc-vms -- test -r "$SOCK" -a -w "$SOCK" 2>/dev/null; then echo "  novrsoc-vms CAN use the socket"; else echo "  novrsoc-vms CANNOT use the socket"; fi
  fi
fi

H "6. Client library for the worker user (python-gvm)"
runuser -u novrsoc-vms -- python3 -c 'import gvm; print("  python-gvm", gvm.get_version())' 2>&1 | tail -1
python3 --version

H "7. Scanner settings (expand_vhosts, safe_checks) inside the ospd-openvas container"
if [ -n "$OSPD" ]; then
  docker exec "$OSPD" sh -c 'grep -nE "^\s*(expand_vhosts|safe_checks)\b" /etc/openvas/openvas.conf 2>/dev/null || echo "  openvas.conf does not set expand_vhosts/safe_checks: scanner defaults apply (expand_vhosts defaults to yes)"'
fi

H "8. Greenbone users and scanners (names and ids only)"
if [ "$GVMD_QUERIES" != 1 ]; then
  echo "  skipped (strictly read-only run); add --with-gvmd-queries to list them"
elif [ -n "$GVMD" ]; then
  docker exec -u gvmd "$GVMD" gvmd --get-users 2>&1 | sed 's/^/  user: /'
  docker exec -u gvmd "$GVMD" gvmd --get-scanners 2>&1 | sed 's/^/  scanner: /'
fi

H "9. Exposure: Greenbone ports must not listen publicly"
ss -tlnp 2>/dev/null | awk 'NR==1 || /:(80|443|9390|9392|5432|6379)\s/'
docker ps --format '{{.Names}}: {{.Ports}}' | grep -E '9390|9392|443|:80->' || echo "  no container publishes 80/443/9390/9392"
ufw status verbose 2>/dev/null | head -20
echo; echo "Audit finished. Nothing was installed, configured, restarted or scanned."
