#!/bin/zsh
#=============================================================================
# Preinstall-RemoveApp.sh
#
# SYNOPSIS
#   Generic pre-install cleanup: removes a previous/legacy version of an app
#   before the new version is installed. Handles:
#     - Killing running processes
#     - Unloading and deleting LaunchAgents / LaunchDaemons
#     - Deleting the .app bundle(s) and other machine-level paths
#     - Forgetting pkg receipts (so the new install is treated as fresh)
#     - Cleaning per-user leftovers in every local user's home folder
#
# USAGE
#   Copy this script per app and fill in the CONFIGURE block.
#   macOS port of the PatchMyPC Community-Scripts Pre-Install pattern.
#
# CONTEXT
#   Run as root (Intune shell script or pkg preinstall script).
#
# EXIT CODES
#   0 = Cleanup completed (including "nothing found to remove")
#   1 = One or more items could not be removed
#=============================================================================

#--- CONFIGURE ---------------------------------------------------------------
APP_NAME="ExampleApp"                        # For logging only

PROCESS_PATTERNS=(
    "ExampleApp"
)

MACHINE_PATHS=(
    "/Applications/ExampleApp.app"
    "/Library/Application Support/ExampleApp"
)

# Globs matched against /Library/LaunchAgents and /Library/LaunchDaemons
LAUNCH_ITEM_PATTERNS=(
    "com.example.exampleapp*"
)

# Regex patterns matched against `pkgutil --pkgs`
PKG_RECEIPT_PATTERNS=(
    "com\.example\.exampleapp.*"
)

# Paths relative to each user's home folder
USER_PATHS=(
    "Library/Application Support/ExampleApp"
    "Library/Caches/com.example.exampleapp"
    "Library/Preferences/com.example.exampleapp.plist"
)
#-----------------------------------------------------------------------------

setopt NULL_GLOB
SCRIPT_NAME="Preinstall-RemoveApp-${APP_NAME}"
LOG_DIR="/Library/Logs/Monster"
LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}.log"
mkdir -p "$LOG_DIR"

FAILURES=0

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
        fi
    fi
}

log "===== ${SCRIPT_NAME} started ====="

if [[ $EUID -ne 0 ]]; then
    log "ERROR: This script must run as root."
    exit 1
fi

#--- 1. Kill running processes ----------------------------------------------
for proc in "${PROCESS_PATTERNS[@]}"; do
    if pgrep -f "$proc" > /dev/null 2>&1; then
        log "Killing process matching: $proc"
        pkill -9 -f "$proc" 2>/dev/null
    fi
done
sleep 2

#--- 2. Unload and remove LaunchAgents / LaunchDaemons -----------------------
for pattern in "${LAUNCH_ITEM_PATTERNS[@]}"; do
    for plist in /Library/LaunchDaemons/${~pattern}.plist /Library/LaunchDaemons/${~pattern}; do
        [[ -f "$plist" ]] || continue
        log "Unloading LaunchDaemon: $plist"
        launchctl bootout system "$plist" >> "$LOG_FILE" 2>&1
        remove_path "$plist"
    done
    for plist in /Library/LaunchAgents/${~pattern}.plist /Library/LaunchAgents/${~pattern}; do
        [[ -f "$plist" ]] || continue
        log "Removing LaunchAgent: $plist"
        remove_path "$plist"
    done
done

#--- 3. Remove machine-level paths -------------------------------------------
for path in "${MACHINE_PATHS[@]}"; do
    remove_path "$path"
done

#--- 4. Forget pkg receipts ---------------------------------------------------
for pattern in "${PKG_RECEIPT_PATTERNS[@]}"; do
    pkgutil --pkgs | grep -E "^${pattern}$" | while read -r receipt; do
        log "Forgetting pkg receipt: $receipt"
        pkgutil --forget "$receipt" >> "$LOG_FILE" 2>&1
    done
done

#--- 5. Clean per-user leftovers ----------------------------------------------
for userhome in /Users/*(N/); do
    username="${userhome:t}"
    [[ "$username" == "Shared" ]] && continue
    for rel in "${USER_PATHS[@]}"; do
        remove_path "${userhome}/${rel}"
    done
    # Per-user app copies (some apps install into ~/Applications)
    remove_path "${userhome}/Applications/${APP_NAME}.app"
done

#--- Result -------------------------------------------------------------------
if (( FAILURES > 0 )); then
    log "===== Completed with ${FAILURES} failure(s) ====="
    exit 1
fi

log "===== Completed successfully ====="
exit 0
