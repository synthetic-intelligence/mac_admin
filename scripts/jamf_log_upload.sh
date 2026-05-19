#!/bin/bash
# =============================================================================
# jamf_log_upload.sh
# Description : Allows users to select and upload diagnostic logs to Jamf Pro
#               via swiftDialog for consent, selection, and status feedback.
#               Uses Jamf Pro API with OAuth2 bearer token auth — no hardcoded
#               username/password. Client secret retrieved from macOS Keychain.
#
# API Role Privileges Required (Settings > API Roles and Clients):
#   - Read Computers      — computer lookup by serial + reading existing attachments
#   - Update Computers    — uploading via POST /v3/computers-inventory/{id}/attachments
#
# Version     : 4.2
# =============================================================================

# -----------------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------------
JSS_URL="https://pantheon.jamfcloud.com"

# OAuth2 Client ID — passed in as Jamf script Parameter 4.
# In the Jamf policy: Scripts → Parameter 4 label = "Jamf API Client ID"
OAUTH_CLIENT_ID="$4"

# Keychain entry where the Client Secret was stored during enrollment setup.
# Written to the logged-in user's login Keychain by the prepare-log-upload policy
# running as Current User. Read back here by resolving the console user at runtime.
# To create (run as the logged-in user, not root):
#   security add-generic-password -a "jamf-log-upload" \
#     -s "jamf-api-client" -w "CLIENT_SECRET" -U
KEYCHAIN_ACCOUNT="jamf-log-upload"
KEYCHAIN_SERVICE="jamf-api-client"

# Resolved at runtime — the login Keychain of whoever is logged in at the console
CONSOLE_USER=$(stat -f "%Su" /dev/console)
CONSOLE_USER_HOME=$(dscl . -read /Users/"$CONSOLE_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')
USER_KEYCHAIN="${CONSOLE_USER_HOME}/Library/Keychains/login.keychain-db"

# How recently (in seconds) an upload must have occurred to trigger the
# duplicate warning. Default: 600 = 10 minutes.
RECENT_UPLOAD_THRESHOLD_SECONDS=600

SCRIPT_VERSION="5.3"
SCRIPT_NAME="jamf_log_upload"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_DIR="/private/var/log"
SCRIPT_LOG="${LOG_DIR}/${SCRIPT_NAME}.log"
DIALOG_BIN="/usr/local/bin/dialog"
STAGING_DIR=$(mktemp -d /var/tmp/log_upload_staging.XXXXXX)

# Bearer token (populated at runtime — never persisted to disk)
BEARER_TOKEN=""
TOKEN_EXPIRY=0

# Populated after get_jamf_id()
JSS_ID=""

# -----------------------------------------------------------------------------
# AVAILABLE LOGS
# Format: "display_label|source_path|description"
# Use "GENERATED" as source_path for runtime-generated content.
# -----------------------------------------------------------------------------
declare -a LOG_DEFINITIONS=(
    "System Log|/private/var/log/system.log|macOS system-wide syslog"
    "Jamf Pro Agent Log|/private/var/log/jamf.log|Jamf management agent activity"
    "DEPNotify / Enrollment Log|/var/tmp/depnotify.log|Jamf Connect enrollment status"
    "Install Log|/private/var/log/install.log|macOS software installation history"
    "WiFi Log|/private/var/log/wifi.log|Wi-Fi connection and diagnostic events"
    "Bluetooth Log|/private/var/log/bluetooth.log|Bluetooth pairing and connection events"
    "Jamf Connect Log|/private/var/log/jamfconnect.log|Jamf Connect authentication events"
    "Unified Log Snapshot|GENERATED|Recent 30-min compressed snapshot from macOS unified log"
    "Crash Reporter Logs|/Library/Logs/DiagnosticReports|Application and kernel crash reports (folder)"
    "Software Update Log|/private/var/log/softwareupdate.log|macOS software update history"
)

# -----------------------------------------------------------------------------
# LOGGING
# -----------------------------------------------------------------------------
log()       { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [INFO]  $*" | tee -a "$SCRIPT_LOG" >&2; }
log_warn()  { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [WARN]  $*" | tee -a "$SCRIPT_LOG" >&2; }
log_error() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERROR] $*" | tee -a "$SCRIPT_LOG" >&2; }

# -----------------------------------------------------------------------------
# CLEANUP
# -----------------------------------------------------------------------------
cleanup() {
    log "Cleaning up staging directory and temp files..."
    [[ -d "$STAGING_DIR" ]] && rm -rf "$STAGING_DIR"
    BEARER_TOKEN=""
}
trap cleanup EXIT

# -----------------------------------------------------------------------------
# PREFLIGHT CHECKS
# -----------------------------------------------------------------------------
preflight_checks() {
    log "Running preflight checks..."

    # Must run as root
    if [[ $EUID -ne 0 ]]; then
        log_error "Script must run as root. Exiting."
        osascript -e 'display alert "Permission Error" message "This script must run as root via Jamf Self Service." as critical'
        exit 1
    fi

    # Check for swiftDialog — trigger install policy if missing, then recheck
    if [[ ! -x "$DIALOG_BIN" ]]; then
        log_warn "swiftDialog not found. Triggering install policy (install-swiftdialog)..."
        /usr/local/jamf/bin/jamf policy -event "install-swiftdialog"
        # Recheck after policy runs
        if [[ ! -x "$DIALOG_BIN" ]]; then
            log_error "swiftDialog still not found after install policy. Exiting."
            osascript -e 'display alert "Installation Failed" message "swiftDialog could not be installed automatically. Please email itsupport@pantheon.io for assistance." as critical'
            exit 1
        fi
        log "swiftDialog installed successfully."
    fi

    # Verify we can resolve the console user and their Keychain path
    if [[ -z "$CONSOLE_USER" || "$CONSOLE_USER" == "root" || -z "$USER_KEYCHAIN" ]]; then
        log_error "Could not resolve console user or their Keychain path. Is anyone logged in?"
        osascript -e 'display alert "Setup Error" message "No user is logged in at the console. Please log in and try again." as critical'
        exit 1
    fi
    log "Console user: $CONSOLE_USER — Keychain: $USER_KEYCHAIN"

    # Check for Keychain item in user login Keychain — trigger setup policy if missing, then recheck
    if ! sudo -u "$CONSOLE_USER" security find-generic-password \
            -a "$KEYCHAIN_ACCOUNT" \
            -s "$KEYCHAIN_SERVICE" \
            -w "$USER_KEYCHAIN" &>/dev/null; then
        log_warn "Keychain item not found for $CONSOLE_USER. Triggering setup policy (prepare-log-upload)..."
        /usr/local/jamf/bin/jamf policy -event "prepare-log-upload"
        # Recheck after policy runs
        if ! sudo -u "$CONSOLE_USER" security find-generic-password \
                -a "$KEYCHAIN_ACCOUNT" \
                -s "$KEYCHAIN_SERVICE" \
                -w "$USER_KEYCHAIN" &>/dev/null; then
            log_error "Keychain item still not found after setup policy. Exiting."
            osascript -e 'display alert "Setup Failed" message "This Mac could not be configured for log upload automatically. Please email itsupport@pantheon.io for assistance." as critical'
            exit 1
        fi
        log "Keychain item found after setup policy."
    fi

    # Confirm Client ID has been passed as Parameter 4
    if [[ -z "$OAUTH_CLIENT_ID" ]]; then
        log_error "OAUTH_CLIENT_ID is empty — has Parameter 4 been set in the Jamf policy? Exiting."
        exit 1
    fi

    log "Preflight checks passed."
}

# -----------------------------------------------------------------------------
# OAUTH2: RETRIEVE CLIENT SECRET FROM KEYCHAIN
# -----------------------------------------------------------------------------
get_client_secret() {
    log "Retrieving client secret from login Keychain for user: $CONSOLE_USER..."
    local secret
    secret=$(sudo -u "$CONSOLE_USER" security find-generic-password \
        -a "$KEYCHAIN_ACCOUNT" \
        -s "$KEYCHAIN_SERVICE" \
        -w "$USER_KEYCHAIN" 2>/dev/null)

    if [[ -z "$secret" ]]; then
        log_error "Client secret not found in login Keychain (account: $KEYCHAIN_ACCOUNT, service: $KEYCHAIN_SERVICE, user: $CONSOLE_USER)."
        show_info_dialog \
            "Authentication Error" \
            "This Mac is missing required IT credentials in its Keychain.\n\nPlease email **itsupport@pantheon.io** to re-run the enrollment setup policy." \
            "SF=exclamationmark.lock.fill,color=red"
        exit 1
    fi

    log "Client secret retrieved from login Keychain."
    echo "$secret"
}

# -----------------------------------------------------------------------------
# OAUTH2: REQUEST BEARER TOKEN
# -----------------------------------------------------------------------------
request_bearer_token() {
    local client_secret="$1"
    # Strip any accidental whitespace/newlines introduced by subshell capture
    client_secret=$(echo "$client_secret" | tr -d '[:space:]')
    log "Requesting OAuth2 bearer token from Jamf Pro (secret length: ${#client_secret})..."

    local response
    response=$(curl \
        --silent \
        --request POST \
        --url "${JSS_URL}/api/oauth/token" \
        --header "Content-Type: application/x-www-form-urlencoded" \
        --data-urlencode "grant_type=client_credentials" \
        --data-urlencode "client_id=${OAUTH_CLIENT_ID}" \
        --data-urlencode "client_secret=${client_secret}")

    if [[ -z "$response" ]]; then
        log_error "Empty response from token endpoint. Check JSS_URL and network connectivity."
        exit 1
    fi

    BEARER_TOKEN=$(echo "$response" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); print(d.get('access_token',''))" 2>/dev/null)

    local expires_in
    expires_in=$(echo "$response" | python3 -c \
        "import sys,json; d=json.load(sys.stdin); print(d.get('expires_in', 0))" 2>/dev/null)

    if [[ -z "$BEARER_TOKEN" || "$BEARER_TOKEN" == "None" ]]; then
        log_error "Failed to parse bearer token. Response: $response"
        show_info_dialog \
            "Authentication Failed" \
            "Could not authenticate with Jamf Pro. Please email **itsupport@pantheon.io** for assistance." \
            "SF=xmark.shield.fill,color=red"
        exit 1
    fi

    TOKEN_EXPIRY=$(( $(date +%s) + expires_in - 60 ))
    log "Bearer token acquired. Expires in ~${expires_in}s."
    client_secret=""
}

# -----------------------------------------------------------------------------
# OAUTH2: ENSURE TOKEN IS STILL VALID
# -----------------------------------------------------------------------------
ensure_valid_token() {
    local now
    now=$(date +%s)
    if [[ $now -ge $TOKEN_EXPIRY ]]; then
        log_warn "Bearer token expired — requesting new token."
        local secret
        secret=$(get_client_secret)
        request_bearer_token "$secret"
        secret=""
    fi
}

# -----------------------------------------------------------------------------
# OAUTH2: INVALIDATE TOKEN ON COMPLETION
# -----------------------------------------------------------------------------
invalidate_token() {
    [[ -z "$BEARER_TOKEN" ]] && return
    log "Invalidating bearer token server-side..."
    curl \
        --silent \
        --output /dev/null \
        --request POST \
        --url "${JSS_URL}/api/v1/auth/invalidate-token" \
        --header "Authorization: Bearer ${BEARER_TOKEN}" 2>/dev/null
    log "Token invalidated."
    BEARER_TOKEN=""
}

# -----------------------------------------------------------------------------
# DIALOG HELPERS
# -----------------------------------------------------------------------------

show_info_dialog() {
    local title="$1"
    local message="$2"
    local icon="${3:-SF=info.circle.fill,color=blue}"
    "$DIALOG_BIN" \
        --title "$title" \
        --message "$message" \
        --icon "$icon" \
        --button1text "OK" \
        --messagefont "size=13" \
        --width 500 \
        --height 300 \
        --ontop \
        2>/dev/null
}

# -----------------------------------------------------------------------------
# STEP 1: CONSENT DIALOG
# -----------------------------------------------------------------------------
show_consent_dialog() {
    log "Displaying consent dialog..."
    local msg="**IT Support — Diagnostic Log Upload**\n\nYou are about to upload diagnostic logs from this Mac to Pantheon's IT system (Jamf Pro) for troubleshooting purposes.\n\n**What is collected:**\n• Only logs you explicitly select on the next screen\n• Files are transferred over HTTPS to your company Jamf instance\n• Logs may contain application activity, network events, and system messages\n\n**Who can access them:**\nOnly members of the IT team with Jamf Pro access.\n\nClick **Continue** to select which logs to upload, or **Cancel** to exit."

    "$DIALOG_BIN" \
        --title "Log Upload — IT Diagnostics" \
        --message "$msg" \
        --icon "SF=lock.shield.fill,color=blue" \
        --button1text "Continue" \
        --button2text "Cancel" \
        --messagefont "size=13" \
        --width 540 \
        --height 420 \
        --ontop \
        2>/dev/null

    if [[ $? -ne 0 ]]; then
        log "User declined consent. Exiting."
        exit 0
    fi
    log "User accepted consent."
}

# -----------------------------------------------------------------------------
# STEP 2: LOG SELECTION DIALOG
# -----------------------------------------------------------------------------
show_selection_dialog() {
    log "Building log selection dialog..."
    local checkbox_args=()
    local index=0
    AVAILABLE_INDICES=()

    for entry in "${LOG_DEFINITIONS[@]}"; do
        IFS='|' read -r label path description <<< "$entry"
        local exists=false
        [[ "$path" == "GENERATED" ]] && exists=true
        [[ -e "$path" ]] && exists=true

        if $exists; then
            local checked="false"
            [[ "$label" == "System Log" || "$label" == "Jamf Pro Agent Log" ]] && checked="true"
            checkbox_args+=(--checkbox "${label}: ${description},checked=${checked}")
            AVAILABLE_INDICES+=("$index")
        else
            log_warn "Skipping '$label' — not found at: $path"
        fi
        ((index++))
    done

    if [[ ${#checkbox_args[@]} -eq 0 ]]; then
        log_error "No logs found on this system."
        show_info_dialog "No Logs Found" "No diagnostic logs were found on this Mac. Please email itsupport@pantheon.io for assistance." "SF=exclamationmark.triangle.fill,color=orange"
        exit 1
    fi

    SELECTION_OUTPUT=$("$DIALOG_BIN" \
        --title "Select Logs to Upload" \
        --message "Choose the logs you'd like to upload to IT for analysis. Only checked items will be sent." \
        --icon "SF=doc.badge.arrow.up,color=blue" \
        --button1text "Upload Selected" \
        --button2text "Cancel" \
        --messagefont "size=13" \
        --width 580 \
        --height 540 \
        --ontop \
        "${checkbox_args[@]}" \
        2>/dev/null)

    if [[ $? -ne 0 ]]; then
        log "User cancelled log selection. Exiting."
        exit 0
    fi

    log "Raw swiftDialog output: $SELECTION_OUTPUT"

    SELECTED_LOGS=()

    # swiftDialog 3.x returns flat quoted key:value pairs, one per line e.g.:
    # "System Log: macOS system-wide syslog" : "true"
    for avail_idx in "${AVAILABLE_INDICES[@]}"; do
        IFS='|' read -r label path description <<< "${LOG_DEFINITIONS[$avail_idx]}"
        local key="${label}: ${description}"
        local value
        value=$(echo "$SELECTION_OUTPUT" | grep -F "\"${key}\"" | awk -F'"' '{print $4}' | tr -d '[:space:]')
        if [[ "$value" == "true" ]]; then
            SELECTED_LOGS+=("$avail_idx")
            log "Selected: $label"
        fi
    done

    if [[ ${#SELECTED_LOGS[@]} -eq 0 ]]; then
        log_warn "No logs selected."
        show_info_dialog "Nothing Selected" "No logs were selected. Nothing was uploaded." "SF=tray.fill,color=gray"
        exit 0
    fi

    log "${#SELECTED_LOGS[@]} log(s) selected."
}

# -----------------------------------------------------------------------------
# STEP 3: GET JAMF COMPUTER ID
# Uses Jamf Pro API v3 (current stable, no deprecation date).
# Requires: Read Computers
# -----------------------------------------------------------------------------
get_jamf_id() {
    log "Looking up computer record via Jamf Pro API (v3)..."
    ensure_valid_token

    local serial
    serial=$(system_profiler SPHardwareDataType | awk '/Serial Number/ {print $NF}')
    log "Serial number: $serial"

    local response
    response=$(curl \
        --silent \
        --request GET \
        --url "${JSS_URL}/api/v3/computers-inventory?filter=hardware.serialNumber==%22${serial}%22&section=GENERAL" \
        --header "Authorization: Bearer ${BEARER_TOKEN}" \
        --header "Accept: application/json")

    JSS_ID=$(echo "$response" | python3 -c \
        "import sys,json; results=json.load(sys.stdin).get('results',[]); print(results[0]['id'] if results else '')" 2>/dev/null)

    if [[ -z "$JSS_ID" ]]; then
        log_error "Could not find computer record in Jamf Pro for serial: $serial"
        show_info_dialog \
            "Computer Not Found" \
            "This Mac could not be found in Jamf Pro. Please email **itsupport@pantheon.io** for assistance." \
            "SF=desktopcomputer.trianglebadge.exclamationmark,color=red"
        exit 1
    fi

    log "Jamf computer ID: $JSS_ID"
}

# -----------------------------------------------------------------------------
# STEP 4: CHECK FOR RECENT UPLOADS
# Fetches the attachment list for this computer and warns the user if any
# attachment was uploaded within the last RECENT_UPLOAD_THRESHOLD_SECONDS.
#
# Requires: Read Computers
# Endpoint:  GET /api/v3/computers-inventory/{id}/attachments/{attachmentId}
#
# Note: The v3 attachment list endpoint returns attachment metadata including
# the upload timestamp in the 'createdAt' field (ISO 8601 format).
# -----------------------------------------------------------------------------
check_recent_uploads() {
    log "Checking for recent attachments on computer ID: $JSS_ID"
    ensure_valid_token

    # Fetch attachment list via v3 inventory detail (attachments are in the
    # ATTACHMENTS section of the computer inventory detail response)
    local response
    response=$(curl \
        --silent \
        --request GET \
        --url "${JSS_URL}/api/v3/computers-inventory-detail/${JSS_ID}" \
        --header "Authorization: Bearer ${BEARER_TOKEN}" \
        --header "Accept: application/json")

    # Parse attachments array — extract names and createdAt timestamps
    local recent_files
    recent_files=$(echo "$response" | python3 -c "
import sys, json
from datetime import datetime, timezone

data = json.load(sys.stdin)
attachments = data.get('attachments', [])
now = datetime.now(timezone.utc).timestamp()
threshold = ${RECENT_UPLOAD_THRESHOLD_SECONDS}
recent = []

for a in attachments:
    created_str = a.get('createdAt', '')
    name = a.get('name', 'Unknown file')
    if not created_str:
        continue
    try:
        # Parse ISO 8601 — handle both Z and +00:00 suffix
        created_str = created_str.replace('Z', '+00:00')
        dt = datetime.fromisoformat(created_str)
        age = now - dt.timestamp()
        if age <= threshold:
            minutes_ago = int(age // 60)
            seconds_ago = int(age % 60)
            if minutes_ago > 0:
                age_str = f'{minutes_ago}m {seconds_ago}s ago'
            else:
                age_str = f'{seconds_ago}s ago'
            recent.append(f'• {name} (uploaded {age_str})')
    except Exception:
        pass

print('\n'.join(recent))
" 2>/dev/null)

    if [[ -z "$recent_files" ]]; then
        log "No recent uploads found within the last ${RECENT_UPLOAD_THRESHOLD_SECONDS}s."
        return 0
    fi

    local threshold_minutes=$(( RECENT_UPLOAD_THRESHOLD_SECONDS / 60 ))
    log "Recent uploads detected within ${threshold_minutes} minutes: $recent_files"

    # Show warning dialog — user can proceed or cancel
    local warn_msg="⚠️  **Logs were already uploaded in the last ${threshold_minutes} minutes:**\n\n${recent_files}\n\nUploading again will create duplicate attachments in Jamf Pro.\n\nDo you want to continue anyway, or cancel and let IT review the existing upload first?"

    "$DIALOG_BIN" \
        --title "Recent Upload Detected" \
        --message "$warn_msg" \
        --icon "SF=clock.badge.exclamationmark.fill,color=orange" \
        --button1text "Upload Anyway" \
        --button2text "Cancel" \
        --messagefont "size=13" \
        --width 560 \
        --height 420 \
        --ontop \
        2>/dev/null

    if [[ $? -ne 0 ]]; then
        log "User chose to cancel after recent upload warning."
        exit 0
    fi

    log "User chose to proceed despite recent upload warning."
}

# -----------------------------------------------------------------------------
# STEP 5: STAGE FILES (copy + timestamp rename)
# -----------------------------------------------------------------------------
stage_log_file() {
    local label="$1"
    local source_path="$2"
    local ts
    ts=$(date +"%Y%m%d_%H%M%S")
    local safe_label
    safe_label=$(echo "$label" | tr ' /' '__' | tr -dc '[:alnum:]_-')

    if [[ "$source_path" == "GENERATED" ]]; then
        local dest="${STAGING_DIR}/${safe_label}_${ts}.log.gz"
        log "Generating unified log snapshot (last 30 min, compressed) -> $dest"
        /usr/bin/log show --last 30m 2>/dev/null | gzip > "$dest"
        echo "$dest"
    elif [[ -d "$source_path" ]]; then
        local dest="${STAGING_DIR}/${safe_label}_${ts}.zip"
        log "Zipping $source_path -> $dest"
        zip -qr "$dest" "$source_path" 2>/dev/null
        echo "$dest"
    elif [[ -f "$source_path" ]]; then
        local ext="${source_path##*.}"
        local dest="${STAGING_DIR}/${safe_label}_${ts}.${ext}"
        log "Copying $source_path -> $dest"
        cp "$source_path" "$dest"
        echo "$dest"
    else
        log_warn "Source not found, skipping: $source_path"
        echo ""
    fi
}

# -----------------------------------------------------------------------------
# STEP 6: UPLOAD WITH PROGRESS DIALOG
#
# Uses the Jamf Pro API v3 attachment endpoint:
#   POST /api/v3/computers-inventory/{id}/attachments
# Requires: Update Computers
#
# This replaces the Classic API fileuploads endpoint and has no deprecation
# date. Multipart form upload — identical curl syntax.
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# STEP 6: UPLOAD LOGS
# Shows a static "please wait" dialog during uploads, then a summary on completion.
# -----------------------------------------------------------------------------
upload_logs() {
    local total=${#SELECTED_LOGS[@]}
    local current=0
    local failed=0
    local succeeded=0

    log "Starting upload of $total file(s) via Jamf Pro API v3..."

    # Show static waiting dialog in the foreground while uploads run in background
    "$DIALOG_BIN" \
        --title "Uploading Logs to IT" \
        --message "Uploading **${total}** log file(s) to IT. Please wait, this should only take a moment..." \
        --icon "SF=arrow.up.doc.fill,color=blue" \
        --button1text "Please Wait" \
        --button1disabled \
        --width 520 \
        --height 240 \
        --ontop \
        2>/dev/null &

    DIALOG_PID=$!

    for idx in "${SELECTED_LOGS[@]}"; do
        IFS='|' read -r label source_path description <<< "${LOG_DEFINITIONS[$idx]}"
        ((current++))

        log "Processing $current/$total: $label"

        local staged_file
        staged_file=$(stage_log_file "$label" "$source_path")

        if [[ -z "$staged_file" || ! -e "$staged_file" ]]; then
            log_warn "Staging failed for: $label"
            ((failed++))
            continue
        fi

        ensure_valid_token

        local http_code
        http_code=$(curl \
            --silent \
            --output /dev/null \
            --write-out "%{http_code}" \
            --request POST \
            --url "${JSS_URL}/api/v3/computers-inventory/${JSS_ID}/attachments" \
            --header "Authorization: Bearer ${BEARER_TOKEN}" \
            --form "file=@${staged_file}")

        if [[ "$http_code" =~ ^2 ]]; then
            log "Upload succeeded (HTTP $http_code): $label"
            ((succeeded++))
        else
            log_error "Upload failed (HTTP $http_code): $label"
            ((failed++))
        fi
    done

    invalidate_token

    # Dismiss the waiting dialog
    kill "$DIALOG_PID" 2>/dev/null
    wait "$DIALOG_PID" 2>/dev/null

    log "Upload complete — Succeeded: $succeeded | Failed: $failed"

    local summary_icon summary_title summary_msg
    if [[ $failed -eq 0 ]]; then
        summary_icon="SF=checkmark.circle.fill,color=green"
        summary_title="Upload Complete"
        summary_msg="**${succeeded}** log file(s) were successfully uploaded to IT.\n\nIf you have an open support ticket, please reply to it to let IT know logs have been uploaded.\n\nIf you're proactively sending logs, please email **itsupport@pantheon.io** to open a ticket."
    elif [[ $succeeded -eq 0 ]]; then
        summary_icon="SF=xmark.circle.fill,color=red"
        summary_title="Upload Failed"
        summary_msg="No logs could be uploaded (**${failed}** file(s) failed).\n\nPlease email **itsupport@pantheon.io** for assistance."
    else
        summary_icon="SF=exclamationmark.triangle.fill,color=orange"
        summary_title="Upload Partially Complete"
        summary_msg="**${succeeded}** log(s) uploaded successfully, **${failed}** failed or were skipped.\n\nIf you have an open support ticket, please reply to it to let IT know logs have been uploaded.\n\nFor any failures, please email **itsupport@pantheon.io** for assistance."
    fi

    "$DIALOG_BIN" \
        --title "$summary_title" \
        --message "$summary_msg" \
        --icon "$summary_icon" \
        --button1text "Done" \
        --messagefont "size=13" \
        --width 520 \
        --height 340 \
        --ontop \
        2>/dev/null
}

# -----------------------------------------------------------------------------
# MAIN
# -----------------------------------------------------------------------------
main() {
    log "======================================================="
    log "  $SCRIPT_NAME v${SCRIPT_VERSION} — started"
    log "  Timestamp : $TIMESTAMP"
    log "  Running as: $(id)"
    log "======================================================="

    preflight_checks
    show_consent_dialog
    show_selection_dialog

    # Authenticate before touching Jamf API
    local client_secret
    client_secret=$(get_client_secret)
    request_bearer_token "$client_secret"
    client_secret=""

    get_jamf_id
    check_recent_uploads   # Warn user if logs uploaded in last 10 minutes
    upload_logs

    log "Script completed."
    exit 0
}

main "$@"
