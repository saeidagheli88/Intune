#!/bin/zsh
#=============================================================================
# Preinstall-ExtractZip.sh
#
# SYNOPSIS
#   Extracts a .zip archive to a destination folder before an install runs.
#   macOS equivalent of PatchMyPC Community-Scripts "Extract Zip".
#   Uses `ditto`, which preserves macOS resource forks, extended attributes,
#   and code-signing metadata (unlike plain `unzip`).
#
# USAGE
#   Edit ZIP_PATH / DEST_DIR below, or pass them as arguments:
#     sudo ./Preinstall-ExtractZip.sh "/path/to/archive.zip" "/destination"
#
# CONTEXT
#   Run as root (Intune shell script or pkg preinstall script).
#
# EXIT CODES
#   0 = Extracted successfully
#   1 = Zip missing, extraction failed, or destination not writable
#=============================================================================

#--- CONFIGURE ---------------------------------------------------------------
ZIP_PATH="${1:-/Library/Monster/Staging/payload.zip}"
DEST_DIR="${2:-/Library/Monster/Staging/extracted}"
CLEAN_DEST="true"     # "true" empties DEST_DIR before extraction
#-----------------------------------------------------------------------------

SCRIPT_NAME="Preinstall-ExtractZip"
LOG_DIR="/Library/Logs/Monster"
LOG_FILE="${LOG_DIR}/${SCRIPT_NAME}.log"
mkdir -p "$LOG_DIR"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') | $1" | tee -a "$LOG_FILE"
}

log "===== ${SCRIPT_NAME} started ====="
log "Source: ${ZIP_PATH}"
log "Destination: ${DEST_DIR}"

if [[ $EUID -ne 0 ]]; then
    log "ERROR: This script must run as root."
    exit 1
fi

if [[ ! -f "$ZIP_PATH" ]]; then
    log "ERROR: Zip file not found: ${ZIP_PATH}"
    exit 1
fi

if [[ "$CLEAN_DEST" == "true" && -d "$DEST_DIR" ]]; then
    log "Cleaning existing destination folder."
    rm -rf "$DEST_DIR"
fi

mkdir -p "$DEST_DIR"
if [[ ! -d "$DEST_DIR" ]]; then
    log "ERROR: Could not create destination: ${DEST_DIR}"
    exit 1
fi

log "Extracting..."
if ditto -x -k "$ZIP_PATH" "$DEST_DIR" >> "$LOG_FILE" 2>&1; then
    ITEM_COUNT=$(find "$DEST_DIR" -mindepth 1 | wc -l | tr -d ' ')
    log "Extraction successful. ${ITEM_COUNT} item(s) in destination."
    exit 0
else
    log "ERROR: Extraction failed. See log for ditto output."
    exit 1
fi
