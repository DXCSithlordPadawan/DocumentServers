#!/usr/bin/env bash
# rhel_inventory.sh — System documentation for air‑gapped RHEL 8+
# Generates a Markdown report named <hostname>_system_inventory.md in the same directory.
# Recommended: run with root privileges (sudo) to collect full details (dmidecode, sosreport, firewall, RAID CLI) and avoid permission denials.

set -euo pipefail
export LC_ALL=C

HOSTNAME=$(hostname -s)
OUTFILE="${HOSTNAME}_system_inventory.md"
START_TS=$(date -u +"%Y-%m-%d %H:%M:%S %Z")
SCRIPT_NAME=$(basename "$0")

have_dnf() { command -v dnf >/dev/null 2>&1; }
have_yum() { command -v yum >/dev/null 2>&1; }
cmd_ok() { command -v "$1" >/dev/null 2>&1; }

append() { echo -e "$1" >> "$OUTFILE"; }

# Initialize Markdown
cat > "$OUTFILE" <<EOF
# System Inventory Report — ${HOSTNAME}

- **Generated:** ${START_TS}
- **Hostname:** $(hostname -f 2>/dev/null || echo "$HOSTNAME")
- **OS:** $(cat /etc/redhat-release 2>/dev/null || rpm -q --qf '%{NAME} %{VERSION}' redhat-release 2>/dev/null || echo 'Unknown')
- **Kernel (running):** $(uname -r)
- **Script:** ${SCRIPT_NAME}

---
EOF

# =========================
# Kernel packages section
# =========================
append "## Kernel Packages\n"
if rpm -q kernel >/dev/null 2>&1; then
  append "| Package | Version | Release | Arch | Install Date | Build Date | Vendor |\n|---|---|---|---|---|---|---|"
  for pkg in $(rpm -q kernel); do
    rpm -q --qf '|%{NAME}|%{VERSION}|%{RELEASE}|%{ARCH}|%{INSTALLTIME}|%{BUILDTIME}|%{VENDOR}|\n' "$pkg" |
    while IFS='|' read -r _ name ver rel arch inst build vendor _; do
      inst_human=$(date -d @"$inst" +"%Y-%m-%d %H:%M:%S %Z" 2>/dev/null || echo "$inst")
      build_human=$(date -d @"$build" +"%Y-%m-%d" 2>/dev/null || echo "$build")
      append "|${name}|${ver}|${rel}|${arch}|${inst_human}|${build_human}|${vendor:-N/A}|"
    done
  done
else
  append "_No kernel packages found via rpm._\n"
fi
append "\n"

# ==================================
# Installed packages with details
# ==================================
append "## Installed Packages\n"
append "Total packages: $(rpm -qa | wc -l)\n\n"
append "| Name | Epoch | Version | Release | Arch | Install Date | Build Date | Vendor | Summary |\n|---|---|---|---|---|---|---|---|---|"
# Use rpm queryformat to extract fields, convert times, escape summary
rpm -qa --qf '%{NAME}|%{EPOCH}|%{VERSION}|%{RELEASE}|%{ARCH}|%{INSTALLTIME}|%{BUILDTIME}|%{VENDOR}|%{SUMMARY}\n' |
while IFS='|' read -r name epoch ver rel arch inst build vendor summary; do
  inst_human=$(date -d @"$inst" +"%Y-%m-%d %H:%M:%S %Z" 2>/dev/null || echo "$inst")
  build_human=$(date -d @"$build" +"%Y-%m-%d" 2>/dev/null || echo "$build")
  [[ "$epoch" == "(none)" ]] && epoch=""
  # Replace vertical bars in summary to avoid breaking Markdown table
  summary_safe=$(echo "$summary" | tr '|' '-')
  append "|${name}|${epoch}|${ver}|${rel}|${arch}|${inst_human}|${build_human}|${vendor:-N/A}|${summary_safe}|"
done
append "\n"

# ==================================
# Security updates — installed/missing
# ==================================
append "## Security Updates\n\n### Installed security advisories\n"
if have_dnf; then
  if dnf -q updateinfo list security installed >/tmp/sec_inst 2>/tmp/sec_inst.err; then
    append "\n\n```text\n$(cat /tmp/sec_inst)\n```\n"
  elif dnf -q updateinfo --installed >/tmp/sec_inst 2>/tmp/sec_inst.err; then
    append "\n\n```text\n$(cat /tmp/sec_inst)\n```\n"
  else
    append "_No updateinfo advisories found, or repositories unavailable. Ensure local repos are configured._\n"
  fi
elif have_yum; then
  if yum -q updateinfo list security installed >/tmp/sec_inst 2>/tmp/sec_inst.err; then
    append "\n\n```text\n$(cat /tmp/sec_inst)\n```\n"
  else
    append "_No updateinfo advisories found via yum._\n"
  fi
else
  append "_Neither dnf nor yum found._\n"
fi

append "\n### Missing security patches (available updates)\n"
if have_dnf; then
  if dnf -q updateinfo list security >/tmp/sec_missing 2>/tmp/sec_missing.err; then
    append "\n\n```text\n$(cat /tmp/sec_missing)\n```\n"
  elif dnf -q check-update --security >/tmp/sec_missing 2>/tmp/sec_missing.err; then
    append "\n\n```text\n$(cat /tmp/sec_missing)\n```\n"
  else
    append "_Security update information not available (no configured repositories?)._\n"
  fi
elif have_yum; then
  if yum -q updateinfo list security >/tmp/sec_missing 2>/tmp/sec_missing.err; then
    append "\n\n```text\n$(cat /tmp/sec_missing)\n```\n"
  elif yum -q check-update --security >/tmp/sec_missing 2>/tmp/sec_missing.err; then
    append "\n\n```text\n$(cat /tmp/sec_missing)\n```\n"
  else
    append "_Security update information not available via yum._\n"
  fi
fi
append "\n"

# ==================================
# Update history
# ==================================
append "## Update History\n"
if have_dnf; then
  append "### DNF transaction history\n\n````text\n$(dnf history 2>/dev/null || true)\n````\n"
  # Enumerate transactions with details
  txids=$(dnf history list --reverse 2>/dev/null | awk 'NR>2 {print $1}' | grep -E '^[0-9]+$' || true)
  for tx in $txids; do
    append "\n#### Transaction ${tx}\n\n```text\n$(dnf history info "$tx" 2>/dev/null || echo "info not available")\n```\n"
  done
elif have_yum; then
  append "### YUM transaction history\n\n```text\n$(yum history 2>/dev/null || true)\n```\n"
  txids=$(yum history list 2>/dev/null | awk 'NR>2 {print $1}' | grep -E '^[0-9]+$' || true)
  for tx in $txids; do
    append "\n#### Transaction ${tx}\n\n```text\n$(yum history info "$tx" 2>/dev/null || echo "info not available")\n```\n"
  done
else
  append "_No package manager history available (dnf/yum not found)._\n"
fi
append "\n"

# ==================================
# Users and groups
# ==================================
append "## Users\n"
append "### Local users (getent passwd)\n"
append "| Username | UID | GID | GECOS | Home | Shell | System Account | Groups | Sudo Privileges |\n|---|---|---|---|---|---|---|---|---|"
getent passwd | while IFS=: read -r user pass uid gid gecos home shell; do
  [[ -z "$user" ]] && continue
  system="No"; [[ "$uid" -lt 1000 ]] && system="Yes"
  groups=$(id -nG "$user" 2>/dev/null | tr ' ' ',')
  sudo_perm="No"
  if command -v sudo >/dev/null 2>&1; then
    if sudo -n -l -U "$user" >/dev/null 2>&1; then sudo_perm="Yes"; fi
  fi
  # Group-based sudo (wheel/sudo)
  if id -nG "$user" 2>/dev/null | grep -qw wheel || id -nG "$user" 2>/dev/null | grep -qw sudo; then
    [[ "$sudo_perm" == "No" ]] && sudo_perm="Group"
  fi
  gecos_safe=$(echo "$gecos" | tr '|' '-')
  append "|${user}|${uid}|${gid}|${gecos_safe}|${home}|${shell}|${system}|${groups:-}|${sudo_perm}|"
done
append "\n"

append "## Groups\n"
append "| Group | GID | Members |\n|---|---|---|"
getent group | while IFS=: read -r grp _ gid members; do
  members_clean=$(echo ${members:-} | tr ',' ', ')
  append "|${grp}|${gid}|${members_clean:-}|"
done
append "\n"

append "### Sudoers configuration\n"
if [[ -f /etc/sudoers ]]; then
  append "```text\n$(grep -vE '^\s*#' /etc/sudoers | sed '/^\s*$/d')\n```\n"
fi
if [[ -d /etc/sudoers.d ]]; then
  for f in /etc/sudoers.d/*; do
    [[ -f "$f" ]] || continue
    append "#### $(basename "$f")\n\n```text\n$(grep -vE '^\s*#' "$f" | sed '/^\s*$/d')\n```\n"
  done
fi
append "\n"

# ==================================
# Shares: NFS / Samba / mounts
# ==================================
append "## Shares\n"
append "### NFS exports\n"
if cmd_ok exportfs; then
  nfsexports=$(exportfs -v 2>/dev/null || true)
  if [[ -n "$nfsexports" ]]; then
    append "```text\n${nfsexports}\n```\n"
  else
    append "_No NFS exports defined._\n"
  fi
else
  append "_exportfs not found._\n"
fi

append "\n### Samba (SMB/CIFS) shares\n"
if cmd_ok testparm; then
  smbinfo=$(testparm -s -v 2>/dev/null || true)
  if [[ -n "$smbinfo" ]]; then
    append "```text\n${smbinfo}\n```\n"
  else
    append "_Samba installed but no shares detected._\n"
  fi
else
  if [[ -f /etc/samba/smb.conf ]]; then
    append "```ini\n$(cat /etc/samba/smb.conf)\n```\n"
  else
    append "_Samba not installed or no smb.conf present._\n"
  fi
fi

append "\n### Mounted network filesystems\n"
netmounts=$(mount | grep -E "type (nfs|cifs)" || true)
if [[ -n "$netmounts" ]]; then
  append "```text\n${netmounts}\n```\n"
else
  append "_No NFS/CIFS mounts currently._\n"
fi

append "\n### fstab entries for NFS/CIFS\n"
fstab_net=$(awk '$3 ~ /(nfs|cifs)/' /etc/fstab 2>/dev/null || true)
if [[ -n "$fstab_net" ]]; then
  append "```text\n${fstab_net}\n```\n"
else
  append "_No NFS/CIFS entries in /etc/fstab._\n"
fi
append "\n"

# ==================================
# Hardware Inventory & System State
# ==================================
append "## Hardware & System Inventory\n"

append "### CPU\n"
if cmd_ok lscpu; then
  append "```text\n$(lscpu 2>/dev/null)\n```\n"
else
  append "```text\n$(grep -E 'model name|cpu MHz|processor' /proc/cpuinfo 2>/dev/null || true)\n```\n"
fi

append "### Memory\n"
append "```text\n$(free -h 2>/dev/null || true)\n```\n"
if cmd_ok dmidecode; then
  append "#### DIMMs (dmidecode -t memory)\n"
  append "```text\n$(dmidecode -t memory 2>/dev/null || echo 'dmidecode requires root')\n```\n"
fi

append "### System / BIOS / Board\n"
if cmd_ok dmidecode; then
  append "```text\n$(dmidecode -t system -t bios -t baseboard 2>/dev/null || echo 'dmidecode requires root')\n```\n"
fi

append "### Disks & Filesystems\n"
if cmd_ok lsblk; then
  append "#### Block devices (lsblk)\n"
  append "```text\n$(lsblk -e7 -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,LABEL,UUID,MODEL,SERIAL 2>/dev/null)\n```\n"
fi
append "#### Filesystem usage (df -h)\n"
append "```text\n$(df -h 2>/dev/null)\n```\n"
if cmd_ok lsblk; then
  append "#### Filesystem attributes (lsblk -f)\n"
  append "```text\n$(lsblk -f 2>/dev/null)\n```\n"
fi

append "### Networking\n"
append "#### Interfaces (ip -br addr)\n"
if cmd_ok ip; then
  append "```text\n$(ip -br addr show 2>/dev/null)\n```\n"
fi
if cmd_ok nmcli; then
  append "#### NetworkManager connections (nmcli)\n"
  append "```text\n$(nmcli -t -f NAME,UUID,TYPE,DEVICE connection show 2>/dev/null)\n```\n"
fi
if cmd_ok ethtool; then
  append "#### Link settings (ethtool -i)\n"
  for nic in $(ls /sys/class/net 2>/dev/null | grep -vE '^(lo|bonding_masters)$' || true); do
    append "##### ${nic}\n"
    append "```text\n$(ethtool -i "$nic" 2>/dev/null || true)\n```\n"
  done
fi

if cmd_ok lspci; then
  append "#### PCI devices (lspci)\n"
  append "```text\n$(lspci 2>/dev/null)\n```\n"
fi

append "### Tuned profile\n"
if cmd_ok tuned-adm; then
  append "```text\n$(tuned-adm active 2>/dev/null)\n```\n"
else
  append "_tuned-adm not installed._\n"
fi

append "### Swap\n"
append "```text\n$(swapon --show 2>/dev/null || echo 'No swap devices')\n```\n"

# ==================================
# Hardware RAID (controllers/arrays)
# ==================================
append "## RAID Inventory\n"
append "### Linux Software RAID (md)\n"
if cmd_ok mdadm; then
  append "#### /proc/mdstat\n"
  append "```text\n$(cat /proc/mdstat 2>/dev/null || true)\n```\n"
  append "#### mdadm --detail --scan\n"
  append "```text\n$(mdadm --detail --scan 2>/dev/null || true)\n```\n"
  for md in $(ls /dev/md* 2>/dev/null || true); do
    [[ -b "$md" ]] || continue
    append "#### mdadm --detail ${md}\n"
    append "```text\n$(mdadm --detail "$md" 2>/dev/null || true)\n```\n"
  done
else
  append "_mdadm not installed or no md arrays present._\n"
fi

append "\n### Hardware RAID (vendor utilities)\n"
# storcli (Broadcom/LSI MegaRAID successor)
STORCLI_BIN=""
if cmd_ok storcli; then STORCLI_BIN=storcli; fi
if [[ -z "$STORCLI_BIN" ]] && cmd_ok storcli64; then STORCLI_BIN=storcli64; fi
if [[ -n "$STORCLI_BIN" ]]; then
  append "#### ${STORCLI_BIN} controllers (storcli /call show)\n"
  append "```text\n$($STORCLI_BIN /call show 2>/dev/null || true)\n```\n"
  # Attempt details for all controllers
  for ctrl in $($STORCLI_BIN /call show 2>/dev/null | awk '/^Controller/ {print $2}' | sed 's/://'); do
    append "##### Controller ${ctrl} summary\n"
    append "```text\n$($STORCLI_BIN /c${ctrl} show all 2>/dev/null || true)\n```\n"
    append "##### Virtual disks (LDs)\n"
    append "```text\n$($STORCLI_BIN /c${ctrl}/vall show all 2>/dev/null || true)\n```\n"
    append "##### Physical disks (PDs)\n"
    append "```text\n$($STORCLI_BIN /c${ctrl}/eall/sall show all 2>/dev/null || true)\n```\n"
  done
fi

# MegaCli (legacy Broadcom/LSI)
MEGACLI_BIN=""
for c in MegaCli megacli MegaCli64; do
  if cmd_ok "$c"; then MEGACLI_BIN="$c"; break; fi
done
if [[ -n "$MEGACLI_BIN" ]]; then
  append "#### ${MEGACLI_BIN} adapter info\n"
  append "```text\n$($MEGACLI_BIN -AdpAllInfo -aAll 2>/dev/null || true)\n```\n"
  append "#### Logical drives\n"
  append "```text\n$($MEGACLI_BIN -LDInfo -Lall -aAll 2>/dev/null || true)\n```\n"
  append "#### Physical drives\n"
  append "```text\n$($MEGACLI_BIN -PDList -aAll 2>/dev/null || true)\n```\n"
fi

# HPE Smart Array (hpssacli/hpacucli)
if cmd_ok hpssacli; then
  append "#### hpssacli config\n"
  append "```text\n$(hpssacli ctrl all show config detail 2>/dev/null || true)\n```\n"
elif cmd_ok hpacucli; then
  append "#### hpacucli config\n"
  append "```text\n$(hpacucli ctrl all show config detail 2>/dev/null || true)\n```\n"
fi

# Adaptec/PMC-Sierra (arcconf)
if cmd_ok arcconf; then
  append "#### arcconf controllers\n"
  append "```text\n$(arcconf GETCONFIG 1 AD 2>/dev/null || arcconf getconfig 1 2>/dev/null || true)\n```\n"
fi

append "\n_If none of the vendor utilities are installed, only software RAID (md) details will be shown._\n\n"

# ==================================
# Time sync (Chrony/NTP) and scheduled tasks (cron/systemd timers)
# ==================================
append "## Time Synchronization & Scheduled Tasks\n"

append "### Chrony (chronyd)\n"
if cmd_ok chronyc; then
  append "#### Configured sources (chrony.conf)\n"
  if [[ -f /etc/chrony.conf ]]; then
    append "```text\n$(grep -E '^(server|pool|peer|refclock|sourcedir|include)' /etc/chrony.conf 2>/dev/null || cat /etc/chrony.conf)\n```\n"
  else
    append "_No /etc/chrony.conf found._\n"
  fi
  append "#### Tracking\n"
  append "```text\n$(chronyc tracking 2>/dev/null || true)\n```\n"
  append "#### Sources (verbose)\n"
  append "```text\n$(chronyc sources -v 2>/dev/null || true)\n```\n"
  append "#### Source statistics\n"
  append "```text\n$(chronyc sourcestats -v 2>/dev/null || true)\n```\n"
  append "#### Activity\n"
  append "```text\n$(chronyc activity 2>/dev/null || true)\n```\n"
  append "#### Service status\n"
  append "```text\n$(systemctl status chronyd 2>/dev/null || true)\n```\n"
else
  append "_chronyc not found. Checking for ntpd/ntpq._\n"
fi

append "### NTP (ntpd/timesyncd)\n"
if cmd_ok ntpq; then
  append "#### ntpq peers\n"
  append "```text\n$(ntpq -p -n 2>/dev/null || true)\n```\n"
  append "#### ntpq variables\n"
  append "```text\n$(ntpq -c rv 2>/dev/null || true)\n```\n"
fi
if cmd_ok ntpstat; then
  append "#### ntpstat\n"
  append "```text\n$(ntpstat 2>/dev/null || true)\n```\n"
fi
append "#### timedatectl\n"
append "```text\n$(timedatectl 2>/dev/null || true)\n```\n"

append "### Cron tasks (cronie)\n"
append "#### crond service status\n"
append "```text\n$(systemctl status crond 2>/dev/null || true)\n```\n"
append "#### /etc/crontab\n"
if [[ -f /etc/crontab ]]; then
  append "```text\n$(cat /etc/crontab 2>/dev/null)\n```\n"
else
  append "_No /etc/crontab present._\n"
fi

for d in /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
  if [[ -d "$d" ]]; then
    append "#### ${d} entries\n"
    append "```text\n$(ls -lah "$d" 2>/dev/null)\n```\n"
  fi
done

append "#### User crontabs (/var/spool/cron)\n"
if [[ -d /var/spool/cron ]]; then
  for f in /var/spool/cron/*; do
    [[ -f "$f" ]] || continue
    u=$(basename "$f")
    append "##### ${u}\n"
    append "```text\n$(cat "$f" 2>/dev/null)\n```\n"
  done
else
  append "_No user crontabs directory found._\n"
fi

append "### Systemd timers\n"
append "#### list-timers --all\n"
append "```text\n$(systemctl list-timers --all 2>/dev/null || true)\n```\n"

# ==================================
# Firewall rules (enhancements)
# ==================================
append "## Firewall\n"
if cmd_ok firewall-cmd; then
  append "### firewalld\n"
  append "```text\nState: $(firewall-cmd --state 2>/dev/null || true)\nDefault zone: $(firewall-cmd --get-default-zone 2>/dev/null || true)\n```\n"
  zones=$(firewall-cmd --get-zones 2>/dev/null || echo "")
  for z in $zones; do
    append "#### Zone: ${z}\n"
    append "```text\n$(firewall-cmd --zone="$z" --list-all 2>/dev/null || true)\n```\n"
  done
elif cmd_ok nft; then
  append "### nftables\n"
  append "```text\n$(nft list ruleset 2>/dev/null || true)\n```\n"
elif cmd_ok iptables; then
  append "### iptables\n"
  append "```text\nIPv4 rules:\n$(iptables -S 2>/dev/null || true)\n\nIPv6 rules:\n$(ip6tables -S 2>/dev/null || true)\n```\n"
else
  append "_No firewall command found (firewalld/nftables/iptables).\n"
fi

# ==================================
# Listening ports (enhancements)
# ==================================
append "## Listening Ports\n"
if cmd_ok ss; then
  append "```text\n$(ss -tulpn 2>/dev/null || true)\n```\n"
else
  append "_ss not available._\n"
fi

# ==================================
# SELinux state (enhancements)
# ==================================
append "## SELinux\n"
if cmd_ok getenforce; then
  append "- **getenforce:** $(getenforce 2>/dev/null)\n"
fi
if cmd_ok sestatus; then
  append "```text\n$(sestatus 2>/dev/null)\n```\n"
fi

# ==================================
# Services (enhancements)
# ==================================
append "## Services\n"
append "### Enabled unit files\n"
append "```text\n$(systemctl list-unit-files --state=enabled 2>/dev/null || echo 'systemd not available')\n```\n"
append "### Active services\n"
append "```text\n$(systemctl list-units --type=service 2>/dev/null || true)\n```\n"
append "### Failed services\n"
append "```text\n$(systemctl --failed 2>/dev/null || true)\n```\n"

# ==================================
# sosreport generation
# ==================================
append "## SOS Report\n"
if cmd_ok sosreport; then
  # --batch prevents prompts; --quiet reduces noise; --no-archive-check avoids contacting Red Hat
  SOS_OUT=$(sosreport --batch --quiet --name "$HOSTNAME" --no-archive-check 2>&1 || true)
  SOS_PATH=$(echo "$SOS_OUT" | grep -Eo '/[^ ]+\.(tar|tar\.xz|tar\.bz2)' | tail -n1)
  if [[ -n "$SOS_PATH" ]]; then
    append "Generated sosreport archive: \`${SOS_PATH}\`\n"
  else
    append "_sosreport ran but archive path not detected. Output:_\n\n```text\n${SOS_OUT}\n```\n"
  fi
else
  append "_sosreport not installed. Install package **sos** to enable diagnostic archive generation._\n"
fi

append "\n---\n\n_Report generated by ${SCRIPT_NAME} on ${START_TS}_\n"

printf '\nReport written to %s\n' "$OUTFILE"
