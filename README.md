# Teleport Labeler

Bash helper for Debian/Ubuntu/Rocky (systemd) to list/add/remove Teleport static SSH labels, log users/keys, and optionally create a `develop` user. It auto-detects Teleport config and service, backs up the config before edits, and restarts Teleport unless `--dry-run` is set.

## Quick one-liner (run as root)

```bash
curl -fsSL https://raw.githubusercontent.com/bluepolicy/TeleportScript/main/teleport-labeler.sh \
  | sudo bash -s -- list
```

Swap `list` for other commands below. Set `LOG_PATH` env to override the log location (default `/var/log/teleport-labeler.log`).

## Commands

- List labels: `sudo ./teleport-labeler.sh list [--config PATH] [--service NAME]`
- Add label: `sudo ./teleport-labeler.sh add env=prod [--config PATH] [--service NAME] [--dry-run]`
- Remove label: `sudo ./teleport-labeler.sh remove env [--config PATH] [--service NAME] [--dry-run]`
- Snapshot users and SSH keys to log: `sudo ./teleport-labeler.sh snapshot`
- Ensure `develop` user: `sudo ./teleport-labeler.sh create-develop [--ssh-key "ssh-ed25519 AAA..."] [--no-sudo]`
- Apply standard label set: `sudo ./teleport-labeler.sh set-standard --env ENV --project NAME --location LOCATION --access ACCESS [--config PATH] [--service NAME] [--dry-run]`

## What it does

- Finds Teleport config in common paths or a provided `--config`.
- Backs up the config before label changes.
- Uses Python+PyYAML to edit `ssh_service.labels`.
- Restarts the Teleport systemd unit (or skip with `--dry-run`).
- Writes a snapshot of local users, their `authorized_keys`, and host SSH pubkeys to the log file.

## Standard label set

Keys and allowed values:

- env: prod | stage | dev | lab
- project: free text (e.g., bluepolicy | teleport | customer-xyz)
- location: col | fra | azure-westeu | home
- access: dev | admin-only

Examples:

- Jens-only homelab: env=lab, location=home, project=bluepolicy, access=admin-only
- Dev usable (non-prod): env=dev, location=azure-westeu, project=customer-xyz, access=dev
- Prod (admin-only): env=prod, location=azure-westeu, project=customer-xyz, access=admin-only

RBAC rule of thumb:
- Dev role matches only when access=dev and env in (dev, stage); everything else is not usable for Dev.

## Requirements

- Run as root (sudo).
- systemd-based Debian/Ubuntu/Rocky/Alma/CentOS/RHEL (recent releases).
- `python3` and PyYAML (`python3-yaml` or `python3-pyyaml`); script will install via apt/dnf/yum if missing.

## Notes

- Restarting Teleport will drop active Teleport tunnels/sessions; reconnect after it restarts.
- Sudo group resolution prefers `sudo`, falls back to `wheel`.
- Log path defaults to `/var/log/teleport-labeler.log`; only root-readable (chmod 600).
