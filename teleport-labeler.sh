#!/usr/bin/env bash
set -euo pipefail

# Teleport label manager for Debian/Ubuntu/Rocky-compatible systems (systemd).
# Usage:
#   sudo ./teleport-labeler.sh install [--proxy-server URL --token TOKEN --env ENV --project NAME --location LOC --access ACC]
#        (interactive prompts if flags omitted)
#   sudo ./teleport-labeler.sh list [--config PATH] [--service NAME] [--section ssh|app|windows|all]
#   sudo ./teleport-labeler.sh add KEY=VALUE [--config PATH] [--service NAME] [--section ssh|app|windows] [--dry-run]
#   sudo ./teleport-labeler.sh remove [KEY] [--config PATH] [--service NAME] [--section ssh|app|windows|all] [--dry-run]
#        (without KEY: interactive selection; --section all: pick section first)
#   sudo ./teleport-labeler.sh snapshot
#   sudo ./teleport-labeler.sh create-develop [--ssh-key "ssh-ed25519 AAA..."] [--no-sudo]
#   sudo ./teleport-labeler.sh set-standard [--env ENV --project NAME --location LOCATION --access ACCESS] [--config PATH] [--service NAME] [--section ssh|app|windows] [--dry-run]
#   sudo ./teleport-labeler.sh show-config [--config PATH]
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
ALLOWED_ENV=(prod stage dev lab)
ALLOWED_PROJECT_PLACEHOLDER="customer-xyz|bluepolicy|teleport|..."
ALLOWED_LOCATION=(col fra azure-westeu home)
ALLOWED_ACCESS=(dev admin-only)
SECTION_MAP_ssh="ssh_service"
SECTION_MAP_app="app_service"
SECTION_MAP_windows="windows_desktop_service"
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
  local id
  id=$(os_id)
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
    svc=$(systemctl list-units --type=service --state=running --no-pager --no-legend 'teleport*.service' 2>/dev/null | awk '{print $1}' | head -n1 || true)
    if [[ -z "$svc" ]]; then
      svc=$(systemctl list-unit-files --type=service --no-pager --no-legend 'teleport*.service' 2>/dev/null | awk '{print $1}' | head -n1 || true)
    fi
    if [[ -n "$svc" ]]; then
      echo "$svc"
      return 0
    fi
  fi
  echo "teleport.service"
}

require_in_set() {
  local value="$1"; shift
  for allowed in "$@"; do
    if [[ "$value" == "$allowed" ]]; then
      return 0
    fi
  done
  return 1
}

resolve_section() {
  local name="$1"
  case "$name" in
    ssh) echo "$SECTION_MAP_ssh";;
    app) echo "$SECTION_MAP_app";;
    windows) echo "$SECTION_MAP_windows";;
    ""|all) echo "all";;  # Default to all (interactive)
    *)
      err "Unknown section '$name'. Allowed: ssh, app, windows, all"
      exit 1;;
  esac
}

# List all sections that exist in config with labels
get_all_sections_with_labels() {
  local path="$1"
  python3 - "$path" <<'PYEOF'
import sys
import yaml
from pathlib import Path

path = sys.argv[1]
cfg_path = Path(path)
if not cfg_path.exists():
    sys.exit(1)
data = yaml.safe_load(cfg_path.read_text()) or {}

sections = ["ssh_service", "app_service", "windows_desktop_service"]
for sec in sections:
    svc = data.get(sec, {})
    labels = svc.get("labels", {})
    if labels and isinstance(labels, dict):
        print(sec)
PYEOF
}

# Get all sections that exist in config (with or without labels)
get_all_sections_in_config() {
  local path="$1"
  python3 - "$path" <<'PYEOF'
import sys
import yaml
from pathlib import Path

path = sys.argv[1]
cfg_path = Path(path)
if not cfg_path.exists():
    sys.exit(1)
data = yaml.safe_load(cfg_path.read_text()) or {}

sections = ["ssh_service", "app_service", "windows_desktop_service"]
for sec in sections:
    if sec in data:
        print(sec)
PYEOF
}

# Interactive section picker
prompt_section_choice() {
  local path="$1"
  local prompt_fd=0

  if [[ ! -t 0 ]]; then
    if [[ -e /dev/tty ]]; then
      exec 3</dev/tty
      prompt_fd=3
    else
      err "No TTY. Use --section ssh|app|windows"
      exit 1
    fi
  fi

  log "Available sections in config:"
  local -a available_sections=()
  local sec_i=1
  while IFS= read -r sec; do
    case "$sec" in
      ssh_service) log "  [$sec_i] SSH Tunnel";;
      app_service) log "  [$sec_i] App/Web Tunnel";;
      windows_desktop_service) log "  [$sec_i] Windows RDP";;
    esac
    available_sections+=("$sec")
    ((sec_i++))
  done < <(get_all_sections_in_config "$path")

  if [[ ${#available_sections[@]} -eq 0 ]]; then
    log "No tunnel sections found in config. Using ssh_service."
    SELECTED_SECTION="ssh_service"
    return
  fi

  if [[ ${#available_sections[@]} -eq 1 ]]; then
    SELECTED_SECTION="${available_sections[0]}"
    log "Only one section found, using: $SELECTED_SECTION"
    return
  fi

  log ""
  printf "Select section [1-${#available_sections[@]}]: "
  set +e
  IFS= read -r sec_choice <&"$prompt_fd"
  local rc=$?
  set -e
  if [[ $rc -ne 0 || -z "$sec_choice" ]]; then
    SELECTED_SECTION="${available_sections[0]}"
    log "No selection, defaulting to: $SELECTED_SECTION"
    return
  fi
  if [[ ! "$sec_choice" =~ ^[0-9]+$ ]] || (( sec_choice < 1 || sec_choice > ${#available_sections[@]} )); then
    err "Invalid selection"
    exit 1
  fi
  SELECTED_SECTION="${available_sections[$((sec_choice-1))]}"
}

# List labels from all sections
list_all_sections() {
  local path="$1"
  python3 - "$path" <<'PYEOF'
import sys
import yaml
from pathlib import Path

path = sys.argv[1]
cfg_path = Path(path)
if not cfg_path.exists():
    sys.exit(f"Config not found: {path}")
data = yaml.safe_load(cfg_path.read_text()) or {}

section_names = {
    "ssh_service": "SSH Tunnel",
    "app_service": "App/Web Tunnel", 
    "windows_desktop_service": "Windows RDP"
}

found_any = False
for sec, name in section_names.items():
    svc = data.get(sec, {})
    labels = svc.get("labels", {})
    if labels and isinstance(labels, dict):
        found_any = True
        print(f"\n[{name}] ({sec}):")
        for k, v in labels.items():
            print(f"  {k}={v}")

if not found_any:
    print("(no labels found in any section)")
PYEOF
}

prompt_standard_inputs() {
  local prompt_fd=0
  if [[ ! -t 0 ]]; then
    if [[ -e /dev/tty ]]; then
      exec 3</dev/tty
      prompt_fd=3
    else
      err "No TTY available for prompts. Provide --env/--project/--location/--access flags."
      exit 1
    fi
  fi

  log "Enter standard labels (leave blank to cancel):"
  log " env options: ${ALLOWED_ENV[*]}"
  printf " env: "
  set +e
  IFS= read -r env_arg <&"$prompt_fd"
  local rc=$?
  set -e
  if [[ $rc -ne 0 || -z "$env_arg" ]]; then
    err "env is required (pass --env if piping without TTY)"; exit 1
  fi

  log " project example: ${ALLOWED_PROJECT_PLACEHOLDER}"
  printf " project: "
  set +e
  IFS= read -r project_arg <&"$prompt_fd"
  rc=$?
  set -e
  if [[ $rc -ne 0 || -z "$project_arg" ]]; then
    err "project is required (pass --project if piping without TTY)"; exit 1
  fi

  log " location options: ${ALLOWED_LOCATION[*]}"
  printf " location: "
  set +e
  IFS= read -r location_arg <&"$prompt_fd"
  rc=$?
  set -e
  if [[ $rc -ne 0 || -z "$location_arg" ]]; then
    err "location is required (pass --location if piping without TTY)"; exit 1
  fi

  log " access options: ${ALLOWED_ACCESS[*]}"
  printf " access: "
  set +e
  IFS= read -r access_arg <&"$prompt_fd"
  rc=$?
  set -e
  if [[ $rc -ne 0 || -z "$access_arg" ]]; then
    err "access is required (pass --access if piping without TTY)"; exit 1
  fi
}

# Get labels as array via Python - returns "key=value" lines
get_labels_list() {
  local path="$1"
  local section="$2"
  python3 - "$path" "$section" <<'PYEOF'
import sys
import yaml
from pathlib import Path

path, section = sys.argv[1:3]
cfg_path = Path(path)
if not cfg_path.exists():
    sys.exit(1)
data = yaml.safe_load(cfg_path.read_text()) or {}
svc = data.get(section, {})
labels = svc.get("labels", {})
if labels and isinstance(labels, dict):
    for k, v in labels.items():
        print(f"{k}={v}")
PYEOF
}

prompt_remove_labels() {
  local path="$1"
  local section="$2"
  local prompt_fd=0

  if [[ ! -t 0 ]]; then
    if [[ -e /dev/tty ]]; then
      exec 3</dev/tty
      prompt_fd=3
    else
      err "No TTY available for interactive removal. Use: remove KEY --section ssh|app|windows"
      exit 1
    fi
  fi

  # If section is "all" or we want to show everything, let user pick section first
  if [[ "$section" == "all" ]]; then
    log "Sections with labels:"
    local -a available_sections=()
    local sec_i=1
    while IFS= read -r sec; do
      case "$sec" in
        ssh_service) log "  [$sec_i] SSH Tunnel (ssh_service)";;
        app_service) log "  [$sec_i] App/Web Tunnel (app_service)";;
        windows_desktop_service) log "  [$sec_i] Windows RDP (windows_desktop_service)";;
      esac
      available_sections+=("$sec")
      ((sec_i++))
    done < <(get_all_sections_with_labels "$path")

    if [[ ${#available_sections[@]} -eq 0 ]]; then
      log "No sections with labels found."
      exit 0
    fi

    log ""
    printf "Select section number: "
    set +e
    IFS= read -r sec_choice <&"$prompt_fd"
    local rc=$?
    set -e
    if [[ $rc -ne 0 || -z "$sec_choice" ]]; then
      log "No selection, exiting."
      exit 0
    fi
    if [[ ! "$sec_choice" =~ ^[0-9]+$ ]] || (( sec_choice < 1 || sec_choice > ${#available_sections[@]} )); then
      err "Invalid section selection"
      exit 1
    fi
    section="${available_sections[$((sec_choice-1))]}"
    SELECTED_SECTION="$section"
  fi

  # Get current labels for selected section
  local labels_output
  labels_output=$(get_labels_list "$path" "$section")
  if [[ -z "$labels_output" ]]; then
    log "No labels in $section."
    exit 0
  fi

  log ""
  log "Labels in $section:"
  # Build array of keys
  local -a keys=()
  local -a display=()
  local i=1
  while IFS= read -r line; do
    local key="${line%%=*}"
    keys+=("$key")
    display+=("$line")
    log "  [$i] $line"
    ((i++))
  done <<< "$labels_output"

  log ""
  log "Enter numbers to remove (comma-separated, e.g. 1,3) or 'all':"
  printf " selection: "
  set +e
  IFS= read -r selection <&"$prompt_fd"
  local rc=$?
  set -e

  if [[ $rc -ne 0 || -z "$selection" ]]; then
    log "No selection made, exiting."
    exit 0
  fi

  # Parse selection
  local -a to_remove=()
  if [[ "$selection" == "all" ]]; then
    to_remove=("${keys[@]}")
  else
    IFS=',' read -ra nums <<< "$selection"
    for num in "${nums[@]}"; do
      num="${num// /}"  # trim spaces
      if [[ "$num" =~ ^[0-9]+$ ]] && (( num >= 1 && num <= ${#keys[@]} )); then
        to_remove+=("${keys[$((num-1))]}")
      else
        err "Invalid selection: $num"
        exit 1
      fi
    done
  fi

  if [[ ${#to_remove[@]} -eq 0 ]]; then
    log "Nothing selected."
    exit 0
  fi

  # Return keys to remove
  REMOVE_KEYS=("${to_remove[@]}")
}

snapshot_users_and_keys() {
  local ts host
  ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  host=$(hostname -f 2>/dev/null || hostname)

  # Output to screen
  log "===== Snapshot: ${ts} ${host} ====="
  log ""
  log "[Users] (user:uid:home:shell)"
  getent passwd | awk -F: '$3 >= 1000 || $1 == "root" {print "  "$1":"$3":"$6":"$7}'
  log ""
  log "[Authorized SSH Keys]"
  local found_keys=0
  while IFS=: read -r user _ uid gid home shell; do
    if [[ -f "$home/.ssh/authorized_keys" ]]; then
      log "  -- ${user} (${home}/.ssh/authorized_keys):"
      sed 's/^/     /' "$home/.ssh/authorized_keys"
      found_keys=1
    fi
  done < <(getent passwd)
  if [[ $found_keys -eq 0 ]]; then
    log "  (no authorized_keys found)"
  fi
  log ""
  log "[Host SSH Keys]"
  for f in /etc/ssh/*.pub; do
    [[ -f "$f" ]] || continue
    log "  -- $f:"
    sed 's/^/     /' "$f"
  done
  log ""

  # Also write to log file
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
  if python3 -c 'import yaml' 2>/dev/null; then
    return 0
  fi
  log "python3-yaml not found; attempting install..."
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

# ============== INSTALL TELEPORT ==============

DEFAULT_PROXY="teleport.bluepolicy.ai:443"

prompt_install_inputs() {
  local prompt_fd=0
  if [[ ! -t 0 ]]; then
    if [[ -e /dev/tty ]]; then
      exec 3</dev/tty
      prompt_fd=3
    else
      err "No TTY. Use --proxy-server, --token, etc."
      exit 1
    fi
  fi

  if [[ -z "$INSTALL_PROXY" ]]; then
    log "Proxy server [${DEFAULT_PROXY}]:"
    printf " proxy: "
    set +e
    IFS= read -r INSTALL_PROXY <&"$prompt_fd"
    set -e
    if [[ -z "$INSTALL_PROXY" ]]; then
      INSTALL_PROXY="$DEFAULT_PROXY"
      log " → using default: $INSTALL_PROXY"
    fi
  fi

  if [[ -z "$INSTALL_TOKEN" ]]; then
    log "Enter join token:"
    printf " token: "
    set +e
    IFS= read -r INSTALL_TOKEN <&"$prompt_fd"
    set -e
    if [[ -z "$INSTALL_TOKEN" ]]; then
      err "Token is required"; exit 1
    fi
  fi

  # Standard labels
  if [[ -z "$env_arg" ]]; then
    log " env options: ${ALLOWED_ENV[*]}"
    printf " env: "
    set +e
    IFS= read -r env_arg <&"$prompt_fd"
    set -e
  fi

  if [[ -z "$project_arg" ]]; then
    log " project example: ${ALLOWED_PROJECT_PLACEHOLDER}"
    printf " project: "
    set +e
    IFS= read -r project_arg <&"$prompt_fd"
    set -e
  fi

  if [[ -z "$location_arg" ]]; then
    log " location options: ${ALLOWED_LOCATION[*]}"
    printf " location: "
    set +e
    IFS= read -r location_arg <&"$prompt_fd"
    set -e
  fi

  if [[ -z "$access_arg" ]]; then
    log " access options: ${ALLOWED_ACCESS[*]}"
    printf " access: "
    set +e
    IFS= read -r access_arg <&"$prompt_fd"
    set -e
  fi
}

install_teleport_package() {
  local os_type
  os_type=$(os_id)

  log "Installing Teleport package..."

  case "$os_type" in
    ubuntu|debian)
      # Add Teleport repo
      require_cmd curl
      curl -fsSL https://apt.releases.teleport.dev/gpg -o /usr/share/keyrings/teleport-archive-keyring.asc
      echo "deb [signed-by=/usr/share/keyrings/teleport-archive-keyring.asc] https://apt.releases.teleport.dev/ stable main" > /etc/apt/sources.list.d/teleport.list
      apt-get update -y
      apt-get install -y teleport
      ;;
    rocky|almalinux|centos|rhel)
      # Add Teleport repo
      cat > /etc/yum.repos.d/teleport.repo <<'REPOEOF'
[teleport]
name=Teleport
baseurl=https://yum.releases.teleport.dev/
enabled=1
gpgcheck=1
gpgkey=https://yum.releases.teleport.dev/gpg
REPOEOF
      if command -v dnf >/dev/null 2>&1; then
        dnf install -y teleport
      else
        yum install -y teleport
      fi
      ;;
    *)
      err "Unsupported OS for auto-install: $os_type"
      exit 1
      ;;
  esac

  log "Teleport package installed."
}

generate_teleport_config() {
  local proxy="$1"
  local token="$2"
  local env_val="$3"
  local project_val="$4"
  local location_val="$5"
  local access_val="$6"
  local nodename
  nodename=$(hostname -f 2>/dev/null || hostname)

  local config_path="/etc/teleport.yaml"

  log "Generating Teleport config at $config_path..."

  cat > "$config_path" <<CFGEOF
version: v3
teleport:
  nodename: ${nodename}
  data_dir: /var/lib/teleport
  proxy_server: ${proxy}
  auth_token: ${token}
  log:
    output: stderr
    severity: INFO

ssh_service:
  enabled: true
  labels:
    env: ${env_val:-unknown}
    project: ${project_val:-unknown}
    location: ${location_val:-unknown}
    access: ${access_val:-dev}

auth_service:
  enabled: false

proxy_service:
  enabled: false
CFGEOF

  chmod 600 "$config_path"
  log "Config created: $config_path"
}

start_teleport_service() {
  log "Enabling and starting Teleport service..."
  systemctl daemon-reload
  systemctl enable teleport.service
  systemctl start teleport.service
  sleep 2
  systemctl status teleport.service --no-pager --lines=10 || true
  log "Teleport service started."
}

do_install() {
  log "=== Teleport Installation ==="

  # Check if already installed
  if command -v teleport >/dev/null 2>&1; then
    log "Teleport is already installed: $(teleport version 2>/dev/null || echo 'unknown version')"
    printf "Reinstall/reconfigure? [y/N]: "
    local prompt_fd=0
    if [[ ! -t 0 ]] && [[ -e /dev/tty ]]; then
      exec 3</dev/tty
      prompt_fd=3
    fi
    set +e
    IFS= read -r confirm <&"$prompt_fd"
    set -e
    if [[ ! "$confirm" =~ ^[Yy] ]]; then
      log "Aborted."
      exit 0
    fi
  fi

  prompt_install_inputs

  # Validate labels
  if [[ -n "$env_arg" ]] && ! require_in_set "$env_arg" "${ALLOWED_ENV[@]}"; then
    err "Invalid env '$env_arg'. Allowed: ${ALLOWED_ENV[*]}"; exit 1
  fi
  if [[ -n "$location_arg" ]] && ! require_in_set "$location_arg" "${ALLOWED_LOCATION[@]}"; then
    err "Invalid location '$location_arg'. Allowed: ${ALLOWED_LOCATION[*]}"; exit 1
  fi
  if [[ -n "$access_arg" ]] && ! require_in_set "$access_arg" "${ALLOWED_ACCESS[@]}"; then
    err "Invalid access '$access_arg'. Allowed: ${ALLOWED_ACCESS[*]}"; exit 1
  fi

  install_teleport_package
  generate_teleport_config "$INSTALL_PROXY" "$INSTALL_TOKEN" "$env_arg" "$project_arg" "$location_arg" "$access_arg"
  start_teleport_service

  log ""
  log "=== Installation complete ==="
  log "Node should appear in Teleport cluster shortly."
  log "Config: /etc/teleport.yaml"
  log "Check status: systemctl status teleport"
}

# ============== END INSTALL ==============

backup_config() {
  local path="$1"
  local ts
  ts=$(date +%Y%m%d-%H%M%S)
  cp "$path" "${path}.bak.${ts}"
  log "Backup created: ${path}.bak.${ts}"
}

python_edit() {
  local action="$1"
  local arg="$2"
  local path="$3"
  local section="$4"
  python3 - "$action" "$arg" "$path" "$section" <<'PYEOF'
import sys
import yaml
from pathlib import Path

action, arg, path, section = sys.argv[1:5]
cfg_path = Path(path)
if not cfg_path.exists():
    sys.exit("Config not found: %s" % path)

data = yaml.safe_load(cfg_path.read_text()) or {}
svc = data.get(section, {})
labels = svc.get("labels", {})
if labels is None:
    labels = {}
if not isinstance(labels, dict):
    sys.exit(f"labels must be a mapping in {section}")

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
    svc["labels"] = labels
    data[section] = svc
elif action == "remove":
    key = arg
    if key in labels:
        labels.pop(key)
    svc["labels"] = labels
    data[section] = svc
else:
    sys.exit("unknown action")

cfg_path.write_text(yaml.safe_dump(data, default_flow_style=False, sort_keys=False))
PYEOF
}

python_set_standard() {
  local env_val="$1"
  local project_val="$2"
  local location_val="$3"
  local access_val="$4"
  local path="$5"
  local section="$6"
  python3 - "$env_val" "$project_val" "$location_val" "$access_val" "$path" "$section" <<'PYEOF'
import sys
import yaml
from pathlib import Path

env_val, project_val, location_val, access_val, path, section = sys.argv[1:7]
cfg_path = Path(path)
if not cfg_path.exists():
    sys.exit(f"Config not found: {path}")

data = yaml.safe_load(cfg_path.read_text()) or {}
svc = data.get(section, {})
labels = svc.get("labels", {})
if labels is None:
    labels = {}
if not isinstance(labels, dict):
    sys.exit(f"labels must be a mapping in {section}")

labels.update({
    "env": env_val,
    "project": project_val,
    "location": location_val,
    "access": access_val,
})
svc["labels"] = labels
data[section] = svc

cfg_path.write_text(yaml.safe_dump(data, default_flow_style=False, sort_keys=False))
PYEOF
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
  local grant_sudo="$2"
  require_cmd useradd
  require_cmd getent
  require_cmd usermod
  if ! id -u develop >/dev/null 2>&1; then
    useradd -m -s /bin/bash develop
    log "User 'develop' created."
  else
    log "User 'develop' already exists."
  fi
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
    err "Usage: $0 <install|list|add|remove|set-standard|snapshot|create-develop|show-config> ..."
    exit 1
  fi

  local cmd="$1"; shift || true
  local cfg_override=""
  local svc_override=""
  local dry_run=0
  local ssh_key_arg=""
  local grant_sudo=1
  local env_arg=""
  local project_arg=""
  local location_arg=""
  local access_arg=""
  local section_name=""
  INSTALL_PROXY=""
  INSTALL_TOKEN=""
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
      --env)
        env_arg="$2"; shift 2;;
      --project)
        project_arg="$2"; shift 2;;
      --location)
        location_arg="$2"; shift 2;;
      --access)
        access_arg="$2"; shift 2;;
      --section)
        section_name="$2"; shift 2;;
      --proxy-server)
        INSTALL_PROXY="$2"; shift 2;;
      --token)
        INSTALL_TOKEN="$2"; shift 2;;
      *) break;;
    esac
  done

  case "$cmd" in
    install)
      do_install
      exit 0;;
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
    show-config)
      local cfg_show
      cfg_show=$(find_config "$cfg_override")
      log "Config: $cfg_show"
      cat "$cfg_show"
      exit 0;;
  esac

  require_cmd python3
  ensure_pyyaml
  require_cmd getent
  snapshot_users_and_keys

  local arg=""
  local interactive_remove=0
  case "$cmd" in
    add)
      if [[ $# -lt 1 ]]; then err "add requires KEY=VALUE"; exit 1; fi
      arg="$1"; shift;;
    remove)
      if [[ $# -lt 1 ]]; then
        interactive_remove=1
      else
        arg="$1"; shift
      fi;;
    set-standard)
      :;;
    list)
      :;;
    *)
      err "Unknown command: $cmd"
      exit 1;;
  esac

  local cfg svc section
  cfg=$(find_config "$cfg_override")
  svc=$(find_service "$svc_override")
  section=$(resolve_section "$section_name")

  # For add/set-standard with section=all, prompt for section choice
  if [[ "$section" == "all" && ( "$cmd" == "add" || "$cmd" == "set-standard" ) ]]; then
    SELECTED_SECTION=""
    prompt_section_choice "$cfg"
    section="$SELECTED_SECTION"
  fi

  if [[ "$cmd" == "set-standard" ]]; then
    if [[ -z "$env_arg" || -z "$project_arg" || -z "$location_arg" || -z "$access_arg" ]]; then
      prompt_standard_inputs
    fi
    if ! require_in_set "$env_arg" "${ALLOWED_ENV[@]}"; then
      err "Invalid env '$env_arg'. Allowed: ${ALLOWED_ENV[*]}"; exit 1
    fi
    if ! require_in_set "$location_arg" "${ALLOWED_LOCATION[@]}"; then
      err "Invalid location '$location_arg'. Allowed: ${ALLOWED_LOCATION[*]}"; exit 1
    fi
    if ! require_in_set "$access_arg" "${ALLOWED_ACCESS[@]}"; then
      err "Invalid access '$access_arg'. Allowed: ${ALLOWED_ACCESS[*]}"; exit 1
    fi
    if [[ -z "$project_arg" ]]; then
      err "project cannot be empty (e.g., bluepolicy|teleport|customer-xyz)"; exit 1
    fi
    backup_config "$cfg"
    python_set_standard "$env_arg" "$project_arg" "$location_arg" "$access_arg" "$cfg" "$section"
    if [[ $dry_run -eq 1 ]]; then
      log "Dry run: standard labels written, service not restarted. (service: $svc)"
    else
      restart_service "$svc"
    fi
    exit 0
  fi

  if [[ "$cmd" == "list" ]]; then
    if [[ "$section" == "all" ]]; then
      list_all_sections "$cfg"
    else
      python_edit list "" "$cfg" "$section"
    fi
    exit 0
  fi

  if [[ "$cmd" == "remove" && $interactive_remove -eq 1 ]]; then
    REMOVE_KEYS=()
    SELECTED_SECTION=""
    prompt_remove_labels "$cfg" "$section"
    if [[ ${#REMOVE_KEYS[@]} -eq 0 ]]; then
      exit 0
    fi
    # Use selected section if user picked one interactively
    if [[ -n "$SELECTED_SECTION" ]]; then
      section="$SELECTED_SECTION"
    fi
    backup_config "$cfg"
    for key in "${REMOVE_KEYS[@]}"; do
      log "Removing: $key from $section"
      python_edit remove "$key" "$cfg" "$section"
    done
    if [[ $dry_run -eq 1 ]]; then
      log "Dry run: changes written, service not restarted. (service: $svc)"
    else
      restart_service "$svc"
    fi
    exit 0
  fi

  # For add with section=all (shouldn't happen after prompt, but fallback)
  if [[ "$section" == "all" ]]; then
    section="ssh_service"
  fi

  backup_config "$cfg"
  python_edit "$cmd" "$arg" "$cfg" "$section"

  if [[ $dry_run -eq 1 ]]; then
    log "Dry run: changes written, service not restarted. (service: $svc)"
  else
    restart_service "$svc"
  fi
}

main "$@"
