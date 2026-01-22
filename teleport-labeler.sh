#!/usr/bin/env bash
set -euo pipefail

# Teleport label manager for Debian/Ubuntu/Rocky-compatible systems (systemd).
# Usage:
#   sudo ./teleport-labeler.sh list [--config PATH] [--service NAME]
#   sudo ./teleport-labeler.sh add KEY=VALUE [--config PATH] [--service NAME] [--dry-run]
#   sudo ./teleport-labeler.sh remove KEY [--config PATH] [--service NAME] [--dry-run]
#   sudo ./teleport-labeler.sh snapshot
#   sudo ./teleport-labeler.sh create-develop [--ssh-key "ssh-ed25519 AAA..."] [--no-sudo]
#
# Defaults: auto-detect config path and systemd service name.

SUPPORTED_OS=(ubuntu debian rocky almalinux centos rhel)
CANDIDATE_CONFIGS=(
  /etc/teleport.yaml
  /etc/teleport/teleport.yaml
  /etc/teleport.d/teleport.yaml
  /etc/teleport.d/config.yaml
  /etc/teleport/config.yaml
)
LOG_PATH=${LOG_PATH:-/var/log/teleport-labeler.log}

log() { printf '%s\n' "$*"; }
err() { printf 'ERROR: %s\n' "$*" >&2; }

ensure_log_file() {
  mkdir -p "$(dirname "$LOG_PATH")"
  touch "$LOG_PATH"
  chmod 600 "$LOG_PATH" 2>/dev/null || true
}

log_append() { printf '%s\n' "$*" >> "$LOG_PATH"; }

need_root() {
  if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
    err "Run as root (sudo)."
    exit 1
  fi
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    err "Missing required command: $cmd"
    exit 1
  fi
}

os_id() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    echo "${ID:-unknown}"
  else
    echo "unknown"
  fi
}

check_supported_os() {
  local id=$(os_id)
  for os in "${SUPPORTED_OS[@]}"; do
    if [[ "$id" == "$os" ]]; then
      return 0
    fi
  done
  err "Unsupported OS ($id). Tested on Ubuntu/Debian/Rocky-like systems from recent releases."
  exit 1
}

find_config() {
  local override="$1"
  if [[ -n "$override" ]]; then
    if [[ -f "$override" ]]; then
      echo "$override"
      return 0
    else
      err "Config not found at $override"
      exit 1
    fi
  fi
  for path in "${CANDIDATE_CONFIGS[@]}"; do
    if [[ -f "$path" ]]; then
      echo "$path"
      return 0
    fi
  done
  err "Could not locate teleport config (tried common paths). Use --config to set explicitly."
  exit 1
}

find_service() {
  local override="$1"
  if [[ -n "$override" ]]; then
    echo "$override"
    return 0
  fi
  if command -v systemctl >/dev/null 2>&1; then
    local svc
    # Prefer an active Teleport unit if present.
    svc=$(systemctl list-units --type=service --state=running --no-pager --no-legend 'teleport*.service' 2>/dev/null | awk '{print $1}' | head -n1 || true)
    if [[ -z "$svc" ]]; then
      svc=$(systemctl list-unit-files --type=service --no-pager --no-legend 'teleport*.service' 2>/dev/null | awk '{print $1}' | head -n1 || true)
    fi
    if [[ -n "$svc" ]]; then
      echo "$svc"
      return 0
    fi
  fi
  # Fallback
  echo "teleport.service"
}

snapshot_users_and_keys() {
  local ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local host=$(hostname -f 2>/dev/null || hostname)
  log_append "===== ${ts} ${host} ====="
  log_append "[Users]"
  getent passwd | awk -F: '{print $1":"$3":"$6":"$7}' >> "$LOG_PATH"
  log_append "[AuthorizedKeys]"
  while IFS=: read -r user _ uid gid home shell; do
    if [[ -f "$home/.ssh/authorized_keys" ]]; then
      log_append "-- ${user} (${home}/.ssh/authorized_keys)"
      sed 's/^/   /' "$home/.ssh/authorized_keys" >> "$LOG_PATH"
    fi
  done < <(getent passwd)
  log_append "[HostKeys]"
  for f in /etc/ssh/*.pub; do
    [[ -f "$f" ]] || continue
    log_append "-- $f"
    sed 's/^/   /' "$f" >> "$LOG_PATH"
  done
  log_append ""
}

ensure_pyyaml() {
  python3 - <<'PY' 2>/dev/null
import sys
try:
    import yaml  # type: ignore
except Exception:
    sys.exit(1)
PY
  if [[ $? -eq 0 ]]; then
    return 0
  fi
  log "python3-yaml not found; attempting install..."
  local id=$(os_id)
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y
    apt-get install -y python3-yaml
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y python3-pyyaml
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3-pyyaml
  else
    err "No supported package manager (apt/dnf/yum) found to install PyYAML."
    exit 1
  fi
}

backup_config() {
  local path="$1"
  local ts=$(date +%Y%m%d-%H%M%S)
  cp "$path" "${path}.bak.${ts}"
  log "Backup created: ${path}.bak.${ts}"
}

python_edit() {
  local action="$1" # list|add|remove
  local arg="$2"    # key=value or key or empty
  local path="$3"
  python3 - "$action" "$arg" "$path" <<'PY'
import sys
import yaml
from pathlib import Path

action, arg, path = sys.argv[1:4]
cfg_path = Path(path)
if not cfg_path.exists():
    sys.exit("Config not found: %s" % path)

data = yaml.safe_load(cfg_path.read_text()) or {}
ssh = data.get("ssh_service", {})
labels = ssh.get("labels", {})
if labels is None:
    labels = {}
if not isinstance(labels, dict):
    sys.exit("labels must be a mapping in ssh_service")

if action == "list":
    if labels:
        for k, v in labels.items():
            print(f"{k}={v}")
    else:
        print("(no labels set)")
    sys.exit(0)

if action == "add":
    if "=" not in arg:
        sys.exit("add expects KEY=VALUE")
    key, value = arg.split("=", 1)
    labels[key] = value
    ssh["labels"] = labels
    data["ssh_service"] = ssh
elif action == "remove":
    key = arg
    if key in labels:
        labels.pop(key)
    ssh["labels"] = labels
    data["ssh_service"] = ssh
else:
    sys.exit("unknown action")

cfg_path.write_text(yaml.safe_dump(data, default_flow_style=False, sort_keys=False))
PY
}

restart_service() {
  local svc="$1"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart "$svc"
    systemctl status "$svc" --no-pager --lines=5 || true
  else
    err "systemctl not available; restart manually (service: $svc)."
  fi
}

create_develop_user() {
  local ssh_key="$1"
  local grant_sudo="$2" # 1=yes 0=no
  require_cmd useradd
  require_cmd passwd
  require_cmd getent
  require_cmd usermod
  if ! id -u develop >/dev/null 2>&1; then
    useradd -m -s /bin/bash develop
  fi
  passwd -l develop || true
  if [[ "$grant_sudo" -eq 1 ]]; then
    if getent group sudo >/dev/null 2>&1; then
      usermod -aG sudo develop || true
    elif getent group wheel >/dev/null 2>&1; then
      usermod -aG wheel develop || true
    fi
  fi
  local key_set=0
  if [[ -n "$ssh_key" ]]; then
    mkdir -p /home/develop/.ssh
    chmod 700 /home/develop/.ssh
    printf '%s\n' "$ssh_key" >> /home/develop/.ssh/authorized_keys
    chmod 600 /home/develop/.ssh/authorized_keys
    chown -R develop:develop /home/develop/.ssh
    key_set=1
  fi
  log_append "create-develop: ensured user develop (sudo=${grant_sudo}, ssh_key_set=${key_set})"
}

main() {
  need_root
  check_supported_os
  ensure_log_file

  if [[ $# -lt 1 ]]; then
    err "Usage: $0 <list|add|remove|snapshot|create-develop> ..."
    exit 1
  fi

  local cmd="$1"; shift || true
  local cfg_override=""
  local svc_override=""
  local dry_run=0
  local ssh_key_arg=""
  local grant_sudo=1
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --config)
        cfg_override="$2"; shift 2;;
      --service)
        svc_override="$2"; shift 2;;
      --dry-run)
        dry_run=1; shift;;
      --ssh-key)
        ssh_key_arg="$2"; shift 2;;
      --no-sudo)
        grant_sudo=0; shift;;
      *) break;;
    esac
  done

  case "$cmd" in
    snapshot)
      require_cmd getent
      snapshot_users_and_keys
      log "Snapshot written to $LOG_PATH"
      exit 0;;
    create-develop)
      require_cmd getent
      snapshot_users_and_keys
      create_develop_user "$ssh_key_arg" "$grant_sudo"
      log "User develop ensured. Details logged to $LOG_PATH"
      exit 0;;
  esac

  require_cmd python3
  ensure_pyyaml
  require_cmd getent
  snapshot_users_and_keys

  local arg=""
  case "$cmd" in
    add)
      if [[ $# -lt 1 ]]; then err "add requires KEY=VALUE"; exit 1; fi
      arg="$1"; shift;;
    remove)
      if [[ $# -lt 1 ]]; then err "remove requires KEY"; exit 1; fi
      arg="$1"; shift;;
    list)
      :;;
    *)
      err "Unknown command: $cmd"
      exit 1;;
  esac

  local cfg=$(find_config "$cfg_override")
  local svc=$(find_service "$svc_override")

  if [[ "$cmd" == "list" ]]; then
    python_edit list "" "$cfg"
    exit 0
  fi

  backup_config "$cfg"
  python_edit "$cmd" "$arg" "$cfg"

  if [[ $dry_run -eq 1 ]]; then
    log "Dry run: changes written, service not restarted. (service: $svc)"
  else
    restart_service "$svc"
  fi
}

main "$@"
