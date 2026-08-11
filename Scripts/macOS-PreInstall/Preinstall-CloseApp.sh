#!/bin/zsh
#=============================================================================
# Preinstall-CloseApp.sh
#
# SYNOPSIS
#   Gracefully quits a running application before an install/upgrade, then
#   force-kills it if it does not exit within the timeout.
#
# USAGE
#   Edit APP_NAME / PROCESS_PATTERNS below, or pass the app name as $1:
#     sudo ./Preinstall-CloseApp.sh "Google Chrome"
#
# CONTEXT
#   Run as root (Intune shell script or pkg preinstall script).
#   macOS port of the PatchMyPC Community-Scripts Pre-Install pattern.
#
# EXIT CODES
#   0 = App not running, or closed successfully
#   1 = App still running after graceful quit + force kill
#=============================================================================

#--- CONFIGURE ---------------------------------------------------------------
APP_NAME="${1:-Webex}"          # Display name as seen in /Applications
QUIT_TIMEOUT=30                 # Seconds to wait after graceful quit request
#-----------------------------------------------------------------------------

setopt NULL_GLOB
SCRIPT_NAME="Preinstall-CloseApp"
LOG_DIR="/Library/Logs/Monster"
LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}.log"
mkdir -p "$LOG_DIR"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $1" | tee -a "$LOG_FILE"
}

log "===== ${SCRIPT_NAME} started for '${APP_NAME}' ====="

if [[ $EUID -ne 0 ]]; then
    log "ERROR: This script must run as root."
    exit 1
fi

if ! pgrep -xq "$APP_NAME" && ! pgrep -fq "${APP_NAME}.app"; then
    log "'${APP_NAME}' is not running. Nothing to do."
    exit 0
fi

# Ask the app to quit gracefully in the logged-in user's session
CONSOLE_USER=$(echo "show State:/Users/ConsoleUser" | scutil | awk '/Name :/ && !/loginwindow/ {print $3}')
if [[ -n "$CONSOLE_USER" ]]; then
    CONSOLE_UID=$(id -u "$CONSOLE_USER")
    log "Requesting graceful quit as user '${CONSOLE_USER}' (uid ${CONSOLE_UID})..."
    launchctl asuser "$CONSOLE_UID" sudo -u "$CONSOLE_USER" \
        osascript -e "tell application \"${APP_NAME}\" to quit" >> "$LOG_FILE" 2>&1
else
    log "No console user logged in; skipping graceful quit."
fi

# Wait for the app to exit
elapsed=0
while (( elapsed < QUIT_TIMEOUT )); do
    if ! pgrep -xq "$APP_NAME" && ! pgrep -fq "${APP_NAME}.app"; then
        log "'${APP_NAME}' quit gracefully after ${elapsed}s."
        exit 0
    fi
    sleep 2
    (( elapsed += 2 ))
done

# Force kill anything still matching
log "Timeout reached. Force-killing '${APP_NAME}'..."
pkill -9 -x "$APP_NAME" 2>/dev/null
pkill -9 -f "${APP_NAME}.app" 2>/dev/null
sleep 2

if pgrep -xq "$APP_NAME" || pgrep -fq "${APP_NAME}.app"; then
    log "ERROR: '${APP_NAME}' is still running after force kill."
    exit 1
fi

log "'${APP_NAME}' terminated."
exit 0
