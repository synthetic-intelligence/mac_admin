#!/bin/bash
# =============================================================================
# jamf_rename_account_v2.sh
# macOS Account Short Name Change — Jamf Self Service  ·  macOS 26.4 (Tahoe)+
#
# WHAT CHANGED FROM v1
# ────────────────────
#  • Minimum OS gate: macOS 26.4 (Tahoe) or later
#  • Bootstrap admin removed — sole admin renames themselves via secureToken
#    self-grant (same GUID/UID, new short name; sysadminctl accepts self-ref)
#  • osascript dialogs replaced with swiftDialog for rich, live-updating UI
#  • Dual credential verification before any changes are made:
#      1. Local admin password  →  dscl -authonly
#      2. Okta password         →  POST /api/v1/authn (Primary Auth API)
#    Both displayed as real-time traffic-light status items; Continue is
#    locked until both return green
#  • Password lives ONLY in a bash variable — never written to any file;
#    zeroed and unset immediately after the FileVault fdesetup call
#
# OKTA API CHOICE
# ───────────────
#  POST https://{domain}/api/v1/authn  (Classic / Primary Authentication API)
#  • No API key or OAuth token required — accepts plain username + password
#  • Returns HTTP 200 for any state where the password was accepted:
#      SUCCESS, MFA_REQUIRED, MFA_ENROLL, PASSWORD_WARN, PASSWORD_EXPIRED …
#  • Returns HTTP 401 (errorCode E0000004) for wrong password
#  • Works for both Classic Engine and Identity Engine (OIE) orgs
#  NOTE: If your org has explicitly disabled /api/v1/authn for OIE, the Okta
#  check will return POLICY_BLOCK. The dialog flags it in amber and allows
#  a supervised IT override if OKTA_VERIFY_REQUIRED=$5 is "false".
#
# DEPENDENCIES
# ────────────
#  swiftDialog >= 2.3  at /usr/local/bin/dialog
#  Python 3 (ships with macOS 26; used for JSON handling and Okta HTTP call)
#  Pre-stage swiftDialog via a scoped Jamf policy before users trigger this.
#
# JAMF PARAMETERS
# ───────────────
#  $4 — Okta domain           e.g. "acme.okta.com"   (required if not
#                                                       auto-detectable)
#  $5 — Okta verify required  "true" | "false"  (default: true)
#        Set false to allow rename when Okta check cannot complete, e.g.
#        OIE orgs that have disabled /api/v1/authn. Local check is always
#        mandatory regardless of this setting.
#
# SECURITY NOTES
# ──────────────
#  • Credentials sent to Okta via Python urllib using env-var injection —
#    password never appears in ps / proc output
#  • CURRENT_PASS is zeroed (overwritten from /dev/zero) then unset after
#    the last fdesetup call; the EXIT trap also zeroes it on unexpected exit
#  • swiftDialog secure text fields surface values only in the JSON blob
#    returned on stdout; that blob is captured, parsed, and immediately
#    overwritten with zero-bytes and unset
#  • No credential data ever written to any temp file
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── Jamf Parameters ────────────────────────────────────────────────────────
OKTA_DOMAIN="${4:-}"
OKTA_VERIFY_REQUIRED="${5:-true}"

# ── Constants ──────────────────────────────────────────────────────────────
readonly SCRIPT_NAME="Account Rename Utility"
readonly SCRIPT_VERSION="2.0"
readonly MIN_MACOS_MAJOR=26
readonly MIN_MACOS_MINOR=4
readonly LOG_FILE="/var/log/jamf_account_rename.log"
readonly DIALOG_BIN="/usr/local/bin/dialog"
readonly SD_CMD_PREFIX="/var/tmp/jamf_ar_cmd"
readonly SD_RES_PREFIX="/var/tmp/jamf_ar_res"
readonly REBOOT_DELAY=30

# swiftDialog status icon tokens (renders as traffic-light circles)
readonly ICON_WAIT="wait"
readonly ICON_OK="success"
readonly ICON_FAIL="fail"
readonly ICON_WARN="error"

# ── Runtime globals ─────────────────────────────────────────────────────────
CONSOLE_USER=""
NEW_USERNAME=""
CURRENT_PASS=""      # SENSITIVE — zeroed + unset in sync_filevault and cleanup
OKTA_USERNAME=""
FV_ENABLED=false
CONSOLE_USER_HAD_TOKEN=false
OKTA_DOMAIN_FROM_JC=""      # domain as read from Jamf Connect config
OKTA_DOMAIN_VERIFIED=false  # true when $4 and JC config agree

# =============================================================================
# LOGGING
# =============================================================================
log()  { printf '%s [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "${*:2}" \
             | tee -a "$LOG_FILE"; }
info() { log "INFO " "$@"; }
warn() { log "WARN " "$@"; }
error(){ log "ERROR" "$@"; }

# =============================================================================
# CLEANUP TRAP
# Zeroes sensitive variables and removes temp files on any exit path.
# =============================================================================
cleanup() {
    local code=$?
    CURRENT_PASS="$(head -c "${#CURRENT_PASS}" /dev/zero 2>/dev/null || true)"
    unset CURRENT_PASS OKTA_USERNAME
    rm -f "${SD_CMD_PREFIX}."* "${SD_RES_PREFIX}."* 2>/dev/null || true
    [[ $code -ne 0 && $code -ne 130 ]] && \
        error "Script exited with code $code — review $LOG_FILE"
}
trap cleanup EXIT

# =============================================================================
# HELPERS
# =============================================================================

run_as_user() {
    local user="$1"; shift
    local uid; uid=$(id -u "$user")
    launchctl asuser "$uid" sudo -u "$user" "$@"
}

verify_local_password() {
    dscl /Local/Default -authonly "$1" "$2" 2>/dev/null
}

has_secure_token() {
    sysadminctl -secureTokenStatus "$1" 2>&1 | grep -q "ENABLED"
}

in_filevault() {
    fdesetup list 2>/dev/null | grep -qw "$1"
}

# Returns 0 if (inst_major.inst_minor) >= (req_major.req_minor)
version_ge() {
    [[ "$1" -gt "$3" ]] || { [[ "$1" -eq "$3" ]] && [[ "$2" -ge "$4" ]]; }
}

# =============================================================================
# OKTA: verify password via Primary Authentication API
#
# Credentials injected via environment variables to keep them out of the
# process list. Python 3 is used for the HTTP call (no curl args exposure).
#
# Stdout tokens:
#   VERIFIED        HTTP 200 — password accepted (MFA / expiry states included)
#   DENIED          HTTP 401 errorCode E0000004 — wrong password
#   LOCKED          HTTP 401 errorCode E0000069 — account locked
#   POLICY_BLOCK    HTTP 403 — /api/v1/authn disabled for this OIE org
#   RATE_LIMITED    HTTP 429
#   NETWORK_ERROR   TCP / DNS failure
#   NO_DOMAIN       OKTA_DOMAIN variable not set
#   SCRIPT_ERROR    unexpected Python exception
# =============================================================================
verify_okta_password() {
    local okta_user="$1"
    local okta_pass="$2"
    local domain="${3:-$OKTA_DOMAIN}"

    [[ -z "$domain" ]] && { echo "NO_DOMAIN"; return; }

    OKTA_U="$okta_user" OKTA_P="$okta_pass" \
    python3 - "$domain" <<'PYEOF'
import os, sys, json

# All HTTP-200 statuses mean the password itself was accepted.
# Post-auth requirements (MFA, enrollment, expiry) don't affect validity here.
PASSWORD_OK_STATUSES = {
    "SUCCESS", "MFA_REQUIRED", "MFA_ENROLL", "MFA_CHALLENGE",
    "PASSWORD_WARN", "PASSWORD_EXPIRED", "RECOVERY", "UNAUTHENTICATED",
}

try:
    from urllib import request as R, error as E

    domain = sys.argv[1]
    user   = os.environ.get("OKTA_U", "")
    passwd = os.environ.get("OKTA_P", "")

    payload = json.dumps({
        "username": user,
        "password": passwd,
        "options": {
            "multiOptionalFactorEnroll": False,
            "warnBeforePasswordExpired": False,
        }
    }).encode("utf-8")

    req = R.Request(
        f"https://{domain}/api/v1/authn",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept":        "application/json",
            "User-Agent":    "JamfAccountRenameScript/2.0 macOS",
        },
        method="POST",
    )

    try:
        with R.urlopen(req, timeout=25) as resp:
            body   = json.loads(resp.read())
            status = body.get("status", "UNKNOWN")
            print("VERIFIED" if status in PASSWORD_OK_STATUSES else "DENIED")

    except E.HTTPError as e:
        code = e.code
        try:
            body = json.loads(e.read())
            ec   = body.get("errorCode", "")
        except Exception:
            ec = ""
        if code == 401:
            print("LOCKED" if ec == "E0000069" else "DENIED")
        elif code == 403:
            print("POLICY_BLOCK")
        elif code == 429:
            print("RATE_LIMITED")
        else:
            print(f"HTTP_{code}")

    except E.URLError:
        print("NETWORK_ERROR")

except Exception:
    print("SCRIPT_ERROR")
PYEOF
}

# =============================================================================
# OKTA CONFIG AUTO-DETECTION
# =============================================================================
detect_okta_config() {
    info "=== Detecting Okta configuration via Jamf Connect ==="

    # ── Read domain from Jamf Connect config (source of truth on the endpoint)
    local jc_domain=""
    local jc_plists=(
        "/Library/Managed Preferences/com.jamf.connect.plist"
        "/Library/Managed Preferences/com.jamf.connect.login.plist"
        "/Library/Preferences/com.jamf.connect.plist"
    )
    for plist in "${jc_plists[@]}"; do
        [[ -f "$plist" ]] || continue

        # OIDCIssuer is a full URL — extract the hostname
        local issuer
        issuer=$(defaults read "$plist" OIDCIssuer 2>/dev/null || true)
        if [[ -n "$issuer" ]]; then
            jc_domain=$(echo "$issuer" \
                | grep -oE '[A-Za-z0-9-]+\.okta(preview)?\.com' | head -1)
            [[ -n "$jc_domain" ]] && { info "JC domain (OIDCIssuer) from $plist: $jc_domain"; break; }
        fi

        # Fallback: OIDCTenant may be a bare shortname or FQDN
        local tenant
        tenant=$(defaults read "$plist" OIDCTenant 2>/dev/null || true)
        if [[ -n "$tenant" ]]; then
            if echo "$tenant" | grep -qE '\.okta(preview)?\.com'; then
                jc_domain="$tenant"
            else
                jc_domain="${tenant}.okta.com"
            fi
            [[ -n "$jc_domain" ]] && { info "JC domain (OIDCTenant) from $plist: $jc_domain"; break; }
        fi
    done

    OKTA_DOMAIN_FROM_JC="${jc_domain:-}"

    # ── Cross-check Jamf $4 against Jamf Connect config ───────────────────
    # $4 is the IT-controlled authoritative value; JC config is the validation
    # reference. A mismatch is a policy configuration error, not a user error —
    # log it prominently and continue (using $4), but make it easy to audit.
    if [[ -n "$OKTA_DOMAIN" && -n "$OKTA_DOMAIN_FROM_JC" ]]; then
        if [[ "$OKTA_DOMAIN" == "$OKTA_DOMAIN_FROM_JC" ]]; then
            OKTA_DOMAIN_VERIFIED=true
            info "Domain cross-check PASSED: Jamf \$4 matches Jamf Connect config ✓ ($OKTA_DOMAIN)"
        else
            OKTA_DOMAIN_VERIFIED=false
            warn "!!! DOMAIN MISMATCH !!!"
            warn "  Jamf policy \$4 : $OKTA_DOMAIN"
            warn "  Jamf Connect   : $OKTA_DOMAIN_FROM_JC"
            warn "Using Jamf \$4 as authoritative. Update the policy parameter if the JC domain is correct."
        fi
    elif [[ -n "$OKTA_DOMAIN" && -z "$OKTA_DOMAIN_FROM_JC" ]]; then
        warn "Jamf Connect config unreadable — cannot cross-check Okta domain. Using \$4 unverified."
        OKTA_DOMAIN_VERIFIED=false
    elif [[ -z "$OKTA_DOMAIN" && -n "$OKTA_DOMAIN_FROM_JC" ]]; then
        # $4 not set — fall back to JC config value
        OKTA_DOMAIN="$OKTA_DOMAIN_FROM_JC"
        OKTA_DOMAIN_VERIFIED=true
        info "Okta domain sourced entirely from Jamf Connect config: $OKTA_DOMAIN"
    else
        warn "Okta domain not found in Jamf \$4 or Jamf Connect config — user will be prompted"
    fi

    # ── Okta username / email ─────────────────────────────────────────────
    local email=""

    # 1. dscl EMailAddress — Jamf Connect syncs the Okta email attribute here
    email=$(dscl . -read "/Users/$CONSOLE_USER" EMailAddress 2>/dev/null \
        | awk '/^EMailAddress:/{print $2}' | head -1) || true

    # 2. Jamf Connect user-level pref may store OIDCUsername
    if [[ -z "$email" ]]; then
        email=$(defaults read \
            "/Users/$CONSOLE_USER/Library/Preferences/com.jamf.connect.plist" \
            OIDCUsername 2>/dev/null || true)
    fi

    # 3. Last-resort guess
    if [[ -z "$email" && -n "$OKTA_DOMAIN" ]]; then
        local org; org=$(echo "$OKTA_DOMAIN" | sed 's/\.okta.*$//')
        email="${CONSOLE_USER}@${org}.com"
        warn "Guessed Okta email: $email — user should verify in dialog"
    fi

    OKTA_USERNAME="${email:-}"
    [[ -n "$OKTA_USERNAME" ]] \
        && info "Okta username: $OKTA_USERNAME" \
        || warn "Okta username not detected — user will enter it"
}

# =============================================================================
# PRE-FLIGHT
# =============================================================================
preflight_checks() {
    info "=== Pre-flight checks ==="

    [[ $(id -u) -eq 0 ]] || { error "Must run as root."; exit 1; }

    # macOS 26.4+
    local os_ver; os_ver=$(sw_vers -productVersion)
    local major minor
    major=$(echo "$os_ver" | cut -d. -f1)
    minor=$(echo "$os_ver" | cut -d. -f2); minor="${minor:-0}"
    version_ge "$major" "$minor" "$MIN_MACOS_MAJOR" "$MIN_MACOS_MINOR" || {
        error "Requires macOS ${MIN_MACOS_MAJOR}.${MIN_MACOS_MINOR}+. Detected: $os_ver"
        exit 1
    }
    info "macOS $os_ver ✓"

    # APFS
    diskutil info / 2>/dev/null | grep -q "APFS" \
        || { error "Boot volume is not APFS."; exit 1; }
    info "APFS ✓"

    # Console user
    CONSOLE_USER=$(stat -f "%Su" /dev/console)
    [[ -n "$CONSOLE_USER" && "$CONSOLE_USER" != "root" ]] \
        || { error "No non-root console user."; exit 1; }
    dscl . -read "/Users/$CONSOLE_USER" UniqueID &>/dev/null \
        || { error "Console user not in local directory."; exit 1; }
    info "Console user: $CONSOLE_USER ✓"

    # Local admin
    dsmemberutil checkmembership -U "$CONSOLE_USER" -G admin 2>/dev/null \
        | grep -q "is a member" \
        || { error "'$CONSOLE_USER' is not a local admin."; exit 1; }
    info "Local admin ✓"

    # swiftDialog
    [[ -x "$DIALOG_BIN" ]] \
        || { error "swiftDialog not found at $DIALOG_BIN — pre-stage it via Jamf."; exit 1; }
    info "swiftDialog ✓"

    # Python 3
    command -v python3 &>/dev/null \
        || { error "python3 not found."; exit 1; }
    info "python3 ✓"

    # Warn if no Okta domain anywhere yet (may be auto-detected later)
    [[ -n "$OKTA_DOMAIN" ]] \
        || warn "Okta domain not in Jamf \$4 — will attempt auto-detect"

    # Pre-rename token and FV state
    has_secure_token "$CONSOLE_USER" && CONSOLE_USER_HAD_TOKEN=true
    fdesetup status 2>/dev/null | grep -q "FileVault is On" && FV_ENABLED=true || true
    info "secureToken before rename: $CONSOLE_USER_HAD_TOKEN | FV enabled: $FV_ENABLED"

    info "=== Pre-flight passed ==="
}

# =============================================================================
# DIALOG: Intro
# =============================================================================
show_intro_dialog() {
    local ec=0
    run_as_user "$CONSOLE_USER" "$DIALOG_BIN" \
        --title        "$SCRIPT_NAME" \
        --icon         "sf=person.badge.key.fill" \
        --iconsize     100 \
        --message      "This utility renames your macOS account **short name** — the username used to log in and the name of your home folder.\n\n**Before you continue:**\n\n- Close all open applications\n- Connect to the network (Okta verification requires it)\n- Your Mac **will restart** when complete\n\nYou will need your **current login password**. Your password itself is not changed — only the account name." \
        --messagefont  "size=14" \
        --button1text  "Continue" \
        --button2text  "Cancel" \
        --width        660 \
        --height       420 \
        || ec=$?
    [[ $ec -eq 0 ]] || { info "User cancelled at intro."; exit 0; }
}

# =============================================================================
# DIALOG: Input collection
# Sets: NEW_USERNAME, CURRENT_PASS, OKTA_USERNAME
# Returns 0 on "Check Credentials", 1 on Cancel
# $1 = optional error message to prepend to dialog body
# =============================================================================
show_input_dialog() {
    local error_prefix="${1:-}"
    local body

    if [[ -n "$error_prefix" ]]; then
        body="${error_prefix}\n\n---\n\nEnter the details below and click **Check Credentials**."
    else
        body="Enter the details below. Your credentials will be verified against your local account **and** Okta before any changes are made."
    fi

    local -a args=(
        --title        "$SCRIPT_NAME"
        --icon         "sf=person.circle.fill"
        --iconsize     80
        --message      "$body"
        --messagefont  "size=13"
        --textfield    "New username,prompt=lowercase · letters · numbers · hyphens · underscores"
        --textfield    "Current password,secure,required"
        --button1text  "Check Credentials"
        --button2text  "Cancel"
        --width        640
        --height       460
        --json
    )

    if [[ -n "$OKTA_USERNAME" ]]; then
        args+=(--textfield "Okta email,value=${OKTA_USERNAME},prompt=you@company.com")
    else
        args+=(--textfield "Okta email,required,prompt=you@company.com")
    fi

    local raw_json ec=0
    raw_json=$(run_as_user "$CONSOLE_USER" "$DIALOG_BIN" "${args[@]}" 2>/dev/null) \
        || ec=$?
    [[ $ec -eq 0 ]] || return 1

    # Parse via Python — handles JSON special characters safely
    NEW_USERNAME=$(python3 -c "
import json,sys; d=json.loads(sys.argv[1])
print(d.get('New username','').strip().lower())" "$raw_json" 2>/dev/null || echo "")

    CURRENT_PASS=$(python3 -c "
import json,sys; d=json.loads(sys.argv[1])
print(d.get('Current password',''))" "$raw_json" 2>/dev/null || echo "")

    local entered_email
    entered_email=$(python3 -c "
import json,sys; d=json.loads(sys.argv[1])
print(d.get('Okta email','').strip())" "$raw_json" 2>/dev/null || echo "")

    # Overwrite the raw JSON blob before unsetting
    raw_json="$(head -c "${#raw_json}" /dev/zero 2>/dev/null || true)"
    unset raw_json

    [[ -n "$entered_email" ]] && OKTA_USERNAME="$entered_email"
    return 0
}

# =============================================================================
# DIALOG: Jamf Connect password sync required
#
# Called when the local account password verifies successfully but Okta
# returns DENIED for the same password. This is the fingerprint of a
# Jamf Connect sync lag — a recent Okta password change hasn't propagated
# to the local account yet (or vice versa).
#
# Always exits the script. The rename must not proceed until both passwords
# are in agreement.
# =============================================================================
show_password_mismatch_dialog() {
    info "Password mismatch detected (local OK, Okta DENIED) — showing Jamf Connect sync dialog"

    local ec=0
    run_as_user "$CONSOLE_USER" "$DIALOG_BIN" \
        --title        "Password Sync Required" \
        --icon         "sf=arrow.triangle.2.circlepath.circle.fill" \
        --iconsize     100 \
        --iconcolour   "orange" \
        --message      "**Your Mac password and Okta password are out of sync.**\n\nYour local Mac password was verified successfully, but Okta rejected the same password. This usually means a recent Okta password change has not yet been synced to your Mac by Jamf Connect — or a local password change was made outside of Jamf Connect.\n\n**You must sync your passwords before renaming your account:**\n\n1. Click **Open Self Service** below\n2. Locate and run the **Sync Password** (or equivalent) item\n3. Re-launch the Account Rename tool from Self Service\n\n⚠️  Do not attempt the rename until both passwords match." \
        --messagefont  "size=13" \
        --button1text  "Open Self Service" \
        --button2text  "Cancel" \
        --width        660 \
        --height       500 \
        || ec=$?

    if [[ $ec -eq 0 ]]; then
        info "User clicked 'Open Self Service' — launching app"
        # Try Self Service+ by bundle ID first, then fall back by app name
        run_as_user "$CONSOLE_USER" \
            open -b "com.jamf.selfserviceplus" 2>/dev/null \
            || run_as_user "$CONSOLE_USER" \
                open -b "com.jamfsoftware.selfservice.mac" 2>/dev/null \
            || run_as_user "$CONSOLE_USER" \
                open -a "Self Service" 2>/dev/null \
            || warn "Could not locate Self Service app — user will need to open it manually"
    else
        info "User dismissed password mismatch dialog without opening Self Service"
    fi

    info "Exiting — account rename cannot proceed until password sync is confirmed."
    exit 0
}

# =============================================================================
# DIALOG: Real-time traffic-light credential verification
#
# Architecture:
#   A background subshell runs both checks, writes pass/fail results to
#   root-only temp files, and pushes live status updates to the swiftDialog
#   command file. swiftDialog runs in the foreground (user GUI context);
#   its Continue button starts disabled and is enabled only when both checks
#   pass. The parent reads result files after swiftDialog exits.
#
# Returns 0 if user clicks Continue with both checks green (or soft-skip OK)
# Returns 1 if user cancels, or checks fail
# =============================================================================
show_verification_dialog() {
    local cmd_file res_local res_okta
    cmd_file=$(mktemp "${SD_CMD_PREFIX}.XXXXXX")
    res_local=$(mktemp "${SD_RES_PREFIX}.local.XXXXXX")
    res_okta=$(mktemp  "${SD_RES_PREFIX}.okta.XXXXXX")

    chmod 644 "$cmd_file"           # swiftDialog (console user) must read it
    chmod 600 "$res_local" "$res_okta"   # root only

    echo "PENDING" > "$res_local"
    echo "PENDING" > "$res_okta"

    # ── Background verification subshell ──────────────────────────────────
    # Inherits all required globals from parent process
    (
        sleep 0.9  # Allow swiftDialog to render before first update

        # 1. Local password
        if verify_local_password "$CONSOLE_USER" "$CURRENT_PASS"; then
            echo "LOCAL_OK" > "$res_local"
            printf 'listitem: index: 0, status: %s, statustext: Verified ✓\n' \
                "$ICON_OK" >> "$cmd_file"
            info "Local password: VERIFIED"
        else
            echo "LOCAL_FAIL" > "$res_local"
            printf 'listitem: index: 0, status: %s, statustext: Incorrect password\n' \
                "$ICON_FAIL" >> "$cmd_file"
            info "Local password: FAILED"
        fi

        # 2. Okta password
        if [[ -z "$OKTA_DOMAIN" ]]; then
            printf 'listitem: index: 1, status: %s, statustext: Okta domain not configured\n' \
                "$ICON_WARN" >> "$cmd_file"
            echo "OKTA_WARN_NO_DOMAIN" > "$res_okta"
            warn "No Okta domain — check skipped"

        elif [[ -z "$OKTA_USERNAME" ]]; then
            printf 'listitem: index: 1, status: %s, statustext: Okta email not entered\n' \
                "$ICON_WARN" >> "$cmd_file"
            echo "OKTA_WARN_NO_USER" > "$res_okta"
            warn "No Okta username — check skipped"

        else
            local okta_r
            okta_r=$(verify_okta_password "$OKTA_USERNAME" "$CURRENT_PASS" "$OKTA_DOMAIN")
            info "Okta API result: $okta_r"

            case "$okta_r" in
                VERIFIED)
                    printf 'listitem: index: 1, status: %s, statustext: Verified ✓\n' \
                        "$ICON_OK" >> "$cmd_file"
                    echo "OKTA_OK" > "$res_okta"
                    ;;
                LOCKED)
                    printf 'listitem: index: 1, status: %s, statustext: Account locked in Okta — contact IT\n' \
                        "$ICON_FAIL" >> "$cmd_file"
                    echo "OKTA_FAIL_LOCKED" > "$res_okta"
                    ;;
                DENIED)
                    printf 'listitem: index: 1, status: %s, statustext: Password does not match Okta\n' \
                        "$ICON_FAIL" >> "$cmd_file"
                    echo "OKTA_FAIL_DENIED" > "$res_okta"
                    ;;
                RATE_LIMITED)
                    printf 'listitem: index: 1, status: %s, statustext: Rate limited — wait a few minutes and retry\n' \
                        "$ICON_WARN" >> "$cmd_file"
                    echo "OKTA_WARN_RATE" > "$res_okta"
                    ;;
                POLICY_BLOCK)
                    printf 'listitem: index: 1, status: %s, statustext: /api/v1/authn disabled (OIE policy)\n' \
                        "$ICON_WARN" >> "$cmd_file"
                    echo "OKTA_WARN_POLICY" > "$res_okta"
                    warn "Okta /api/v1/authn policy-blocked — OIE org may require OKTA_VERIFY_REQUIRED=false"
                    ;;
                NETWORK_ERROR)
                    printf 'listitem: index: 1, status: %s, statustext: Cannot reach Okta — check network\n' \
                        "$ICON_WARN" >> "$cmd_file"
                    echo "OKTA_WARN_NET" > "$res_okta"
                    ;;
                *)
                    printf 'listitem: index: 1, status: %s, statustext: Unexpected result (%s)\n' \
                        "$ICON_WARN" "$okta_r" >> "$cmd_file"
                    echo "OKTA_WARN_UNKNOWN" > "$res_okta"
                    ;;
            esac
        fi

        # Evaluate combined result and update dialog message + button
        local l_res o_res local_pass=false okta_pass=false
        l_res=$(cat "$res_local")
        o_res=$(cat "$res_okta")

        [[ "$l_res" == "LOCAL_OK" ]] && local_pass=true
        if   [[ "$o_res" == "OKTA_OK" ]]; then
            okta_pass=true
        elif [[ "$OKTA_VERIFY_REQUIRED" != "true" && "$o_res" == OKTA_WARN* ]]; then
            okta_pass=true   # soft-skip permitted via $5
        fi

        if [[ "$local_pass" == "true" && "$okta_pass" == "true" ]]; then
            if [[ "$o_res" == OKTA_WARN* ]]; then
                printf 'message: ⚠️  Local credentials verified. Okta check was skipped (see status above). Proceeding is logged. Click **Continue** or **Cancel** to abort.\n' \
                    >> "$cmd_file"
            else
                printf 'message: ✅ Both credentials verified. Click **Continue** to begin the rename.\n' \
                    >> "$cmd_file"
            fi
            printf 'button1: enable\n' >> "$cmd_file"

        elif [[ "$local_pass" == "false" ]]; then
            printf 'message: ❌ Local password is incorrect. Click **Cancel** to try again.\n' \
                >> "$cmd_file"
        else
            printf 'message: ❌ Okta verification failed. Ensure you are on the network and your password is correct, then click **Cancel** to try again.\n' \
                >> "$cmd_file"
        fi
    ) &
    local bg_pid=$!

    # ── Foreground: swiftDialog blocks here until the user acts ───────────
    local dlg_exit=0
    run_as_user "$CONSOLE_USER" "$DIALOG_BIN" \
        --title        "Verifying Credentials" \
        --icon         "sf=lock.shield.fill" \
        --iconsize     80 \
        --message      "Checking your credentials — please wait…" \
        --listitem     "Local admin account,status=${ICON_WAIT},statustext=Checking…" \
        --listitem     "Okta authentication,status=${ICON_WAIT},statustext=Checking…" \
        --button1text  "Continue" \
        --button1disabled \
        --button2text  "Cancel" \
        --commandfile  "$cmd_file" \
        --width        580 \
        --height       400 \
        || dlg_exit=$?

    wait "$bg_pid" 2>/dev/null || true  # Ensure bg subshell has written results

    local l_final o_final
    l_final=$(cat "$res_local" 2>/dev/null || echo "PENDING")
    o_final=$(cat "$res_okta"  2>/dev/null || echo "PENDING")
    rm -f "$cmd_file" "$res_local" "$res_okta"

    info "Verification result — dialog exit: $dlg_exit | local: $l_final | okta: $o_final"

# ── Intercept password mismatch before generic return ─────────────────
    # local=OK + Okta=DENIED is the specific fingerprint of a Jamf Connect
    # sync issue. Show a targeted dialog with a Self Service shortcut rather
    # than dropping the user back to the generic retry loop.
    if [[ "$l_final" == "LOCAL_OK" && "$o_final" == "OKTA_FAIL_DENIED" ]]; then
        show_password_mismatch_dialog   # always calls exit — never returns
    fi

    # Proceed only if user clicked Continue (exit 0) AND both checks satisfied
    if [[ $dlg_exit -eq 0 ]]; then
        local local_pass=false okta_pass=false
        [[ "$l_final" == "LOCAL_OK" ]] && local_pass=true
        if   [[ "$o_final" == "OKTA_OK" ]]; then
            okta_pass=true
        elif [[ "$OKTA_VERIFY_REQUIRED" != "true" && "$o_final" == OKTA_WARN* ]]; then
            okta_pass=true
        fi
        [[ "$local_pass" == "true" && "$okta_pass" == "true" ]] && return 0
    fi

    return 1
}

# =============================================================================
# INPUT + VERIFY LOOP
# =============================================================================
collect_and_verify() {
    info "=== Input collection + verification loop ==="

    local attempt=0 max_attempts=5 error_msg=""

    while true; do
        (( attempt++ )) || true
        [[ $attempt -le $max_attempts ]] \
            || { error "Max attempts ($max_attempts) exceeded."; exit 1; }

        show_input_dialog "$error_msg" || { info "User cancelled."; exit 0; }
        error_msg=""

        # Username format gate
        if [[ -z "$NEW_USERNAME" ]]; then
            error_msg="⚠️ **Username cannot be empty.**"
            continue
        fi

        if ! printf '%s' "$NEW_USERNAME" | grep -qE '^[a-z_][a-z0-9_-]{0,30}$'; then
            error_msg="⚠️ **Invalid username format.**\n\nMust start with a lowercase letter or underscore, contain only lowercase letters, numbers, hyphens or underscores, and be ≤ 32 characters."
            continue
        fi

        if [[ "$NEW_USERNAME" == "$CONSOLE_USER" ]]; then
            error_msg="⚠️ **New username is the same as the current one.** Choose a different name."
            continue
        fi

        if dscl . -list /Users 2>/dev/null | grep -qxF "$NEW_USERNAME"; then
            error_msg="⚠️ **Username \"${NEW_USERNAME}\" is already taken** by another local account."
            continue
        fi

        if [[ -d "/Users/$NEW_USERNAME" ]]; then
            error_msg="⚠️ **A home folder already exists at /Users/${NEW_USERNAME}.** Contact IT to resolve this conflict before proceeding."
            continue
        fi

        if [[ -z "$CURRENT_PASS" ]]; then
            error_msg="⚠️ **Password cannot be empty.**"
            continue
        fi

        # Dual verification dialog — loop back with error on failure
        if show_verification_dialog; then
            info "Credentials verified. Proceeding."
            break
        else
            error_msg="⚠️ **Credential verification did not pass.** Review the status indicators and try again."
        fi
    done
}

# =============================================================================
# STEP 1 — Rename dscl account record
# =============================================================================
rename_account_record() {
    info "=== Step 1: dscl account rename ==="

    dscl . -change "/Users/$CONSOLE_USER" RecordName \
        "$CONSOLE_USER" "$NEW_USERNAME"
    info "RecordName: $CONSOLE_USER → $NEW_USERNAME"

    # macOS 15+ (and Tahoe) gate NFSHomeDirectory changes behind TCC consent.
    # Ensure /usr/bin/dscl has an Apple Events PPPC entry before this runs.
    dscl . -change "/Users/$NEW_USERNAME" NFSHomeDirectory \
        "/Users/$CONSOLE_USER" "/Users/$NEW_USERNAME"
    info "NFSHomeDirectory updated"

    dscacheutil -flushcache
    killall -HUP opendirectoryd 2>/dev/null || true
    sleep 3
    info "Directory Services cache flushed"
}

# =============================================================================
# STEP 2 — Move home folder
# =============================================================================
rename_home_folder() {
    info "=== Step 2: Home folder rename ==="
    local old="/Users/$CONSOLE_USER" new="/Users/$NEW_USERNAME"

    if [[ ! -d "$old" ]]; then
        error "Old home '$old' not found. Attempting dscl rollback."
        dscl . -change "/Users/$NEW_USERNAME" RecordName \
            "$NEW_USERNAME" "$CONSOLE_USER" 2>/dev/null || true
        dscl . -change "/Users/$CONSOLE_USER" NFSHomeDirectory \
            "$new" "$old" 2>/dev/null || true
        exit 1
    fi

    mv "$old" "$new"
    ln -sf "$new" "$old"   # compatibility symlink for in-flight processes
    info "Moved $old → $new; symlink left at $old"
}

# =============================================================================
# STEP 3 — Ownership
# =============================================================================
fix_ownership() {
    info "=== Step 3: Top-level home folder ownership ==="
    local uid gid
    uid=$(dscl . -read "/Users/$NEW_USERNAME" UniqueID       | awk '{print $2}')
    gid=$(dscl . -read "/Users/$NEW_USERNAME" PrimaryGroupID | awk '{print $2}')
    chown "${uid}:${gid}" "/Users/$NEW_USERNAME"
    # UID/GID unchanged — recursive chown not needed and would be disruptive
    info "chown ${uid}:${gid} /Users/$NEW_USERNAME (top-level only)"
}

# =============================================================================
# STEP 4 — Keychain migration
# =============================================================================
migrate_keychain() {
    info "=== Step 4: Keychain migration ==="
    local kc_dir="/Users/$NEW_USERNAME/Library/Keychains"
    local login_kc="$kc_dir/login.keychain-db"
    local meta_kc="$kc_dir/metadata.keychain-db"

    [[ -f "$login_kc" ]] || { warn "Login keychain not found — skipping."; return 0; }

    # Metadata DB is stale after home rename; macOS rebuilds on next login
    [[ -f "$meta_kc" ]] && rm -f "$meta_kc" && info "Removed stale metadata.keychain-db"
    find "$kc_dir" -maxdepth 1 -name "*.plist" -delete 2>/dev/null || true
    info "Cleared stale keychain UUID plists"

    # Re-register keychain path with Security framework (runs as new username)
    # Password unchanged — vault contents remain accessible at next login
    run_as_user "$NEW_USERNAME" \
        security set-keychain-settings "$login_kc" 2>/dev/null || true
    info "Login keychain path re-registered"
}

# =============================================================================
# STEP 5 — secureToken self-grant
#
# No secondary admin available, so the renamed account grants the token to
# itself. This is valid because:
#   • The account's GeneratedUID (GUID) is unchanged by the RecordName rename
#   • sysadminctl accepts -adminUser == target user when the account already
#     holds secureToken and provides the correct password for auth
#   • The system resolves both "adminUser" and target by GUID, not short name
# =============================================================================
restore_secure_token_self() {
    info "=== Step 5: secureToken self-grant ==="

    if has_secure_token "$NEW_USERNAME"; then
        info "secureToken still ENABLED on '$NEW_USERNAME' — no action needed."
        return 0
    fi

    if [[ "$CONSOLE_USER_HAD_TOKEN" == "false" ]]; then
        info "Account did not hold secureToken before rename — skipping."
        return 0
    fi

    info "secureToken lost after rename — attempting self-grant…"
    sysadminctl \
        -secureTokenOn  "$NEW_USERNAME" \
        -password       "$CURRENT_PASS" \
        -adminUser      "$NEW_USERNAME" \
        -adminPassword  "$CURRENT_PASS" 2>&1 | tee -a "$LOG_FILE" || true

    if has_secure_token "$NEW_USERNAME"; then
        info "secureToken confirmed ENABLED on '$NEW_USERNAME'"
    else
        error "secureToken self-grant FAILED."
        error "Manual path: Recovery → Terminal → sysadminctl -secureTokenOn $NEW_USERNAME"
    fi
}

# =============================================================================
# STEP 6 — FileVault / APFS preboot sync
# NOTE: CURRENT_PASS is zeroed + unset inside this function — last use.
# =============================================================================
sync_filevault() {
    info "=== Step 6: FileVault / APFS preboot sync ==="

    if [[ "$FV_ENABLED" != "true" ]]; then
        info "FileVault not enabled — skipping."
        # Still zero the password since this is the designated cleanup point
        CURRENT_PASS="$(head -c "${#CURRENT_PASS}" /dev/zero 2>/dev/null || true)"
        unset CURRENT_PASS
        return 0
    fi

    if in_filevault "$NEW_USERNAME"; then
        info "'$NEW_USERNAME' already listed in FileVault."
    elif in_filevault "$CONSOLE_USER"; then
        warn "FV still lists '$CONSOLE_USER' — re-enrolling under new name…"

        fdesetup remove -user "$CONSOLE_USER" 2>&1 | tee -a "$LOG_FILE" || \
            warn "fdesetup remove returned non-zero"

        printf '<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
    "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Username</key><string>%s</string>
    <key>Password</key><string>%s</string>
</dict>
</plist>\n' "$NEW_USERNAME" "$CURRENT_PASS" \
            | fdesetup add -inputplist 2>&1 | tee -a "$LOG_FILE" \
            || warn "fdesetup add returned non-zero — verify FV enrollment after reboot"
    else
        warn "Neither '$CONSOLE_USER' nor '$NEW_USERNAME' in FV list — manual re-enrollment may be needed after reboot."
    fi

    # ── Zero and unset password — final use complete ───────────────────────
    info "Zeroing CURRENT_PASS from memory"
    CURRENT_PASS="$(head -c "${#CURRENT_PASS}" /dev/zero 2>/dev/null || true)"
    unset CURRENT_PASS

    # Update APFS Preboot so EFI boot picker and pre-boot auth reflect the new name
    info "Updating APFS Preboot volume…"
    diskutil apfs updatePreboot / 2>&1 | tail -5 | tee -a "$LOG_FILE"
    info "FileVault sync complete."
}

# =============================================================================
# STEP 7 — Jamf inventory
# =============================================================================
update_jamf_inventory() {
    info "=== Step 7: Jamf inventory update ==="
    command -v jamf &>/dev/null \
        && jamf recon 2>&1 | tail -3 | tee -a "$LOG_FILE" && info "Inventory updated." \
        || warn "jamf binary not found — skipping."
}

# =============================================================================
# STEP 8 — Notify and reboot
# =============================================================================
notify_and_reboot() {
    info "=== Step 8: Notification and reboot ==="

    run_as_user "$CONSOLE_USER" "$DIALOG_BIN" \
        --title        "Rename Complete — Restarting" \
        --icon         "sf=checkmark.circle.fill" \
        --iconsize     100 \
        --message      "Your account has been renamed successfully.\n\n| | |\n|---|---|\n| **Old username** | \`${CONSOLE_USER}\` |\n| **New username** | \`${NEW_USERNAME}\` |\n\nYour Mac will restart in **${REBOOT_DELAY} seconds** to apply all changes.\n\nAfter restart, log in with your **new username** and your **existing password** — your password has not changed." \
        --button1text  "Restart Now" \
        --button2text  "Wait" \
        --timer        "$REBOOT_DELAY" \
        --width        620 \
        --height       400 \
        || true   # timer expiry / Wait click are expected non-zero exits

    info "Scheduling reboot…"
    shutdown -r "+$(( REBOOT_DELAY / 60 + 1 ))" \
        "Account rename complete." 2>/dev/null \
        || ( sleep "$REBOOT_DELAY" && reboot ) &

    info "=== $SCRIPT_NAME v$SCRIPT_VERSION done: '$CONSOLE_USER' → '$NEW_USERNAME' ==="
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    exec > >(tee -a "$LOG_FILE") 2>&1
    info "========================================================"
    info "  $SCRIPT_NAME  v$SCRIPT_VERSION  —  starting"
    info "========================================================"

    preflight_checks
    detect_okta_config

    show_intro_dialog
    collect_and_verify     # → NEW_USERNAME, CURRENT_PASS, OKTA_USERNAME now set

    info "Rename intent confirmed: '$CONSOLE_USER' → '$NEW_USERNAME'  (Okta: $OKTA_USERNAME)"

    rename_account_record
    rename_home_folder
    fix_ownership
    migrate_keychain
    restore_secure_token_self
    sync_filevault          # CURRENT_PASS zeroed + unset inside here
    update_jamf_inventory
    notify_and_reboot
}

main "$@"
