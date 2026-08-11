#!/bin/zsh
#=============================================================================
# Preinstall-Remove-Webex.sh
#
# SYNOPSIS
#   Fully removes ALL Cisco Webex products from macOS:
#     - Webex (Teams / unified app), Cisco Webex Meetings, Cisco Spark
#     - Machine-level and per-user app copies (~/Applications)
#     - LaunchAgents / LaunchDaemons, pkg receipts
#     - Per-user caches, preferences, containers, logs
#
#   macOS counterpart of the Windows Detect/Remediate-Webex.ps1 pair
#   (full-removal standard). Also usable as a PatchMyPC-style pre-install
#   cleanup if Webex is ever re-deployed.
#
# CONTEXT
#   Run as root (Intune shell script or pkg preinstall script).
#
# EXIT CODES
#   0 = Webex not present, or removed successfully
#   1 = One or more items could not be removed
#=============================================================================

setopt NULL_GLOB
SCRIPT_NAME="Preinstall-Remove-Webex"
LOG_DIR="/Library/Logs/Monster"
LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}.log"
mkdir -p "$LOG_DIR"

FAILURES=0
REMOVED=0

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $1" | tee -a "$LOG_FILE"
}

remove_path() {
    local target="$1"
    if [[ -e "$target" ]]; then
        log "Removing: $target"
        rm -rf "$target"
        if [[ -e "$target" ]]; then
            log "ERROR: Failed to remove $target"
            (( FAILURES++ ))
        else
            (( REMOVED++ ))
        fi
    fi
}

log "===== ${SCRIPT_NAME} started ====="

if [[ $EUID -ne 0 ]]; then
    log "ERROR: This script must run as root."
    exit 1
fi

#--- 1. Kill all Webex processes ----------------------------------------------
WEBEX_PROCESSES=(
    "Webex"
    "Webex Teams"
    "Cisco Webex Meetings"
    "CiscoWebexStart"
    "WebexHelper"
    "webexmta"
    "CiscoCollabHost"
    "WebexAppLauncher"
)
for proc in "${WEBEX_PROCESSES[@]}"; do
    if pgrep -f "$proc" > /dev/null 2>&1; then
        log "Killing process: $proc"
        pkill -9 -f "$proc" 2>/dev/null
    fi
done
sleep 2

#--- 2. Unload and remove LaunchAgents / LaunchDaemons -------------------------
for plist in /Library/LaunchDaemons/com.webex.*.plist /Library/LaunchDaemons/com.cisco.webex*.plist; do
    log "Unloading LaunchDaemon: $plist"
    launchctl bootout system "$plist" >> "$LOG_FILE" 2>&1
    remove_path "$plist"
done
for plist in /Library/LaunchAgents/com.webex.*.plist /Library/LaunchAgents/com.cisco.webex*.plist; do
    remove_path "$plist"
done

#--- 3. Remove machine-level applications and support files --------------------
MACHINE_PATHS=(
    "/Applications/Webex.app"
    "/Applications/Webex Teams.app"
    "/Applications/Cisco Webex Meetings.app"
    "/Applications/Cisco Spark.app"
    "/Library/Application Support/WebEx Folder"
    "/Library/Application Support/Cisco/WebEx"
)
for path in "${MACHINE_PATHS[@]}"; do
    remove_path "$path"
done

#--- 4. Forget pkg receipts -----------------------------------------------------
pkgutil --pkgs | grep -iE '^(com\.webex\.|com\.cisco\.webex)' | while read -r receipt; do
    log "Forgetting pkg receipt: $receipt"
    pkgutil --forget "$receipt" >> "$LOG_FILE" 2>&1
done

#--- 5. Per-user cleanup --------------------------------------------------------
USER_PATHS=(
    "Applications/Webex.app"
    "Applications/Cisco Webex Meetings.app"
    "Library/Application Support/WebEx Folder"
    "Library/Application Support/Cisco Spark"
    "Library/Application Support/Webex"
    "Library/Caches/com.webex.meetingmanager"
    "Library/Caches/com.cisco.webexmeetingsapp"
    "Library/Caches/Cisco-Systems.Spark"
    "Library/Logs/webexmta"
    "Library/Logs/WebexTeams"
    "Library/WebKit/com.webex.meetingmanager"
    "Library/Group Containers/group.com.cisco.webex.helper"
    "Library/Containers/com.cisco.webexmeetingsapp"
    "Library/LaunchAgents/com.webex.pt.plist"
    "Library/LaunchAgents/com.cisco.webexmta.plist"
)
for userhome in /Users/*(N/); do
    username="${userhome:t}"
    [[ "$username" == "Shared" ]] && continue
    for rel in "${USER_PATHS[@]}"; do
        remove_path "${userhome}/${rel}"
    done
    for plist in "${userhome}"/Library/Preferences/com.webex.*.plist \
                 "${userhome}"/Library/Preferences/com.cisco.webex*.plist \
                 "${userhome}"/Library/Preferences/Cisco-Systems.Spark.plist; do
        remove_path "$plist"
    done
done

#--- Result ----------------------------------------------------------------------
if (( FAILURES > 0 )); then
    log "===== Completed with ${FAILURES} failure(s) ====="
    exit 1
fi

if (( REMOVED == 0 )); then
    log "===== No Webex components found. Device is clean. ====="
else
    log "===== Removed ${REMOVED} Webex item(s) successfully ====="
fi
exit 0
