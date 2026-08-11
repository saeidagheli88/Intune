#!/bin/zsh
#=============================================================================
# Preinstall-Remove-JRE8.sh
#
# SYNOPSIS
#   Removes legacy Oracle Java 8 (JRE) from macOS before installing a
#   replacement Java runtime (e.g. Temurin / Corretto / newer Oracle Java).
#
#   macOS equivalent of PatchMyPC Community-Scripts "Remove-JRE8":
#     - Oracle JRE 8 browser plugin (JavaAppletPlugin)
#     - Java Control Panel preference pane
#     - Oracle Java updater LaunchAgent/Daemon + helper tool
#     - pkg receipts, per-user caches/preferences
#     - OPTIONAL: Oracle JDK 1.8 under /Library/Java/JavaVirtualMachines
#
# CONTEXT
#   Run as root (Intune shell script or pkg preinstall script).
#
# EXIT CODES
#   0 = JRE 8 not present, or removed successfully
#   1 = One or more items could not be removed
#=============================================================================

#--- CONFIGURE ---------------------------------------------------------------
REMOVE_JDK8="false"    # "true" also removes Oracle JDK 1.8.0_* installs
#-----------------------------------------------------------------------------

setopt NULL_GLOB
SCRIPT_NAME="Preinstall-Remove-JRE8"
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

#--- 1. Stop Oracle Java updater / helper -------------------------------------
pkill -9 -f "Java Updater" 2>/dev/null
pkill -9 -f "JavaControlPanel" 2>/dev/null

DAEMON="/Library/LaunchDaemons/com.oracle.java.Helper-Tool.plist"
if [[ -f "$DAEMON" ]]; then
    log "Unloading LaunchDaemon: $DAEMON"
    launchctl bootout system "$DAEMON" >> "$LOG_FILE" 2>&1
fi
remove_path "$DAEMON"
remove_path "/Library/LaunchAgents/com.oracle.java.Java-Updater.plist"
remove_path "/Library/PrivilegedHelperTools/com.oracle.java.Helper-Tool"

#--- 2. Remove JRE 8 machine components ---------------------------------------
remove_path "/Library/Internet Plug-Ins/JavaAppletPlugin.plugin"
remove_path "/Library/PreferencePanes/JavaControlPanel.prefPane"
remove_path "/Library/Application Support/Oracle/Java"

#--- 3. Optionally remove Oracle JDK 1.8 --------------------------------------
if [[ "$REMOVE_JDK8" == "true" ]]; then
    for jdk in /Library/Java/JavaVirtualMachines/jdk1.8.0_*.jdk; do
        remove_path "$jdk"
    done
else
    for jdk in /Library/Java/JavaVirtualMachines/jdk1.8.0_*.jdk; do
        log "NOTE: Found $jdk (JDK removal disabled, leaving in place)"
    done
fi

#--- 4. Forget pkg receipts ----------------------------------------------------
pkgutil --pkgs | grep -E '^com\.oracle\.jre$|^com\.oracle\.jdk8u[0-9]+$' | while read -r receipt; do
    if [[ "$receipt" == com.oracle.jdk8u* && "$REMOVE_JDK8" != "true" ]]; then
        continue
    fi
    log "Forgetting pkg receipt: $receipt"
    pkgutil --forget "$receipt" >> "$LOG_FILE" 2>&1
done

#--- 5. Per-user leftovers ------------------------------------------------------
for userhome in /Users/*(N/); do
    username="${userhome:t}"
    [[ "$username" == "Shared" ]] && continue
    remove_path "${userhome}/Library/Application Support/Oracle/Java"
    remove_path "${userhome}/Library/Caches/Oracle.MacJREInstaller"
    for plist in "${userhome}"/Library/Preferences/com.oracle.java*.plist \
                 "${userhome}"/Library/Preferences/com.oracle.javadeployment*.plist; do
        remove_path "$plist"
    done
done

#--- Result ---------------------------------------------------------------------
if (( FAILURES > 0 )); then
    log "===== Completed with ${FAILURES} failure(s) ====="
    exit 1
fi

if (( REMOVED == 0 )); then
    log "===== Oracle JRE 8 not found. Nothing removed. ====="
else
    log "===== Removed ${REMOVED} item(s) successfully ====="
fi
exit 0
