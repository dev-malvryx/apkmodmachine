#!/usr/bin/env bash

# ==============================================================================
# Script Name:  genkey.sh
# Description:  Interactive Android Keystore Generation Wizard
# Author:       dev-malvryx
# Version:      2.0.0
# Compatibility: Ubuntu 24.04 LTS / Debian / macOS / WSL / Termux
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ------------------------------------------------------------------------------
# Color & Symbol Definitions
# ------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

TICK="${GREEN}✔${NC}"
CROSS="${RED}✘${NC}"
ARROW="${CYAN}➜${NC}"
WARN="${YELLOW}⚠${NC}"

# ------------------------------------------------------------------------------
# Globals
# ------------------------------------------------------------------------------
SCRIPT_VERSION="2.0.0"
LOG_FILE=""
FILENAME=""
ALIAS=""
PASS_1=""
CN="" OU="" O="" L="" ST="" C=""
VALIDITY=10000
KEYSIZE=4096
KEYALG="RSA"
STORETYPE="PKCS12"
TEMP_FILES=()

# ------------------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------------------
log_setup() {
    LOG_FILE="$(mktemp /tmp/genkey_XXXXXX.log)"
    TEMP_FILES+=("$LOG_FILE")
    exec 3>&1                          # save original stdout
    exec 2> >(tee -a "$LOG_FILE" >&2)  # mirror stderr to log
}

log_info()    { echo -e "${DIM}[$(date '+%H:%M:%S')] INFO  $*${NC}" >> "$LOG_FILE"; }
log_warn()    { echo -e "${WARN} ${YELLOW}$*${NC}"; echo "[$(date '+%H:%M:%S')] WARN  $*" >> "$LOG_FILE"; }
log_error()   { echo -e "${CROSS} ${RED}$*${NC}"; echo "[$(date '+%H:%M:%S')] ERROR $*" >> "$LOG_FILE"; }
log_success() { echo -e "${TICK} ${GREEN}$*${NC}"; echo "[$(date '+%H:%M:%S')] OK    $*" >> "$LOG_FILE"; }

# ------------------------------------------------------------------------------
# Cleanup trap — runs on exit, INT, TERM
# ------------------------------------------------------------------------------
cleanup() {
    local exit_code=$?
    # Scrub password from memory (best-effort in bash)
    PASS_1=""
    # Remove temp files
    for f in "${TEMP_FILES[@]:-}"; do
        [[ -f "$f" ]] && rm -f "$f"
    done
    if [[ $exit_code -ne 0 && $exit_code -ne 130 ]]; then
        echo -e "\n${RED}Unexpected exit (code $exit_code). Check log: $LOG_FILE${NC}" >&2
    fi
}
trap cleanup EXIT
trap 'echo -e "\n${YELLOW}Interrupted by user.${NC}"; exit 130' INT TERM

# ------------------------------------------------------------------------------
# Terminal width helper
# ------------------------------------------------------------------------------
COLS=$(tput cols 2>/dev/null || echo 60)
divider() { printf '%*s\n' "$COLS" '' | tr ' ' "${1:-─}"; }

# ------------------------------------------------------------------------------
# Banner
# ------------------------------------------------------------------------------
print_banner() {
    clear
    echo -e "${BLUE}"
    divider "═"
    printf "%*s\n" $(( (COLS + 42) / 2 )) "ANDROID CRYPTOGRAPHIC KEYSTORE WIZARD"
    printf "%*s\n" $(( (COLS + 26) / 2 )) "v${SCRIPT_VERSION} · dev-malvryx"
    divider "═"
    echo -e "${NC}"
}

# ------------------------------------------------------------------------------
# Dependency & environment checks
# ------------------------------------------------------------------------------
check_dependencies() {
    local missing=()

    for cmd in keytool openssl; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        echo -e "${YELLOW}Install with one of:${NC}"
        echo -e "  ${DIM}sudo apt install default-jdk openssl   # Debian/Ubuntu/WSL${NC}"
        echo -e "  ${DIM}brew install openjdk openssl            # macOS${NC}"
        echo -e "  ${DIM}pkg install openjdk-17 openssl          # Termux${NC}"
        exit 1
    fi

    log_info "Dependencies OK: keytool=$(keytool -version 2>&1 | head -1), openssl=$(openssl version)"
}

check_write_permission() {
    local dir
    dir="$(dirname "$(realpath -m "$FILENAME" 2>/dev/null || echo "$FILENAME")")"
    if [[ ! -w "$dir" ]]; then
        log_error "No write permission in directory: $dir"
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# Input helpers
# ------------------------------------------------------------------------------
prompt() {
    # Usage: prompt VAR "Label" "default"
    local -n _ref=$1
    local label="$2"
    local default="${3:-}"
    local prompt_str
    if [[ -n "$default" ]]; then
        prompt_str="${ARROW} ${label} ${DIM}[${default}]${NC}: "
    else
        prompt_str="${ARROW} ${label}: "
    fi
    printf '%b' "$prompt_str"
    read -r _ref
    _ref="${_ref:-$default}"
}

prompt_password() {
    # Reads a password twice, validates min length, populates PASS_1
    local min_len=8
    local pass2

    while true; do
        printf '%b' "${ARROW} Keystore password ${DIM}(min ${min_len} chars, hidden)${NC}: "
        read -rs PASS_1; echo

        if [[ ${#PASS_1} -lt $min_len ]]; then
            log_error "Password must be at least ${min_len} characters."
            continue
        fi

        # Strength hint (non-blocking)
        local strength=0
        [[ "$PASS_1" =~ [A-Z] ]]   && (( strength++ )) || true
        [[ "$PASS_1" =~ [a-z] ]]   && (( strength++ )) || true
        [[ "$PASS_1" =~ [0-9] ]]   && (( strength++ )) || true
        [[ "$PASS_1" =~ [^a-zA-Z0-9] ]] && (( strength++ )) || true
        case $strength in
            1|2) echo -e "  ${YELLOW}Strength: Weak — consider mixing upper/lower/digits/symbols${NC}" ;;
            3)   echo -e "  ${CYAN}Strength: Moderate${NC}" ;;
            4)   echo -e "  ${GREEN}Strength: Strong${NC}" ;;
        esac

        printf '%b' "${ARROW} Confirm password: "
        read -rs pass2; echo

        if [[ "$PASS_1" != "$pass2" ]]; then
            log_error "Passwords do not match. Try again."
            pass2=""
        else
            break
        fi
    done
    unset pass2
}

validate_country_code() {
    local code="$1"
    if [[ ! "$code" =~ ^[A-Za-z]{2}$ ]]; then
        log_warn "Country code '${code}' is not a valid 2-letter ISO code."
        return 1
    fi
    return 0
}

validate_validity() {
    if ! [[ "$VALIDITY" =~ ^[0-9]+$ ]] || (( VALIDITY < 1 || VALIDITY > 36500 )); then
        log_error "Validity must be a number between 1 and 36500 days."
        exit 1
    fi
}

# ------------------------------------------------------------------------------
# Advanced options menu
# ------------------------------------------------------------------------------
advanced_options() {
    echo -e "\n${MAGENTA}${BOLD}[Advanced Options]${NC}"

    # Key algorithm
    echo -e "  ${DIM}1) RSA-4096 (default, widest compatibility)${NC}"
    echo -e "  ${DIM}2) RSA-2048 (legacy/faster)${NC}"
    echo -e "  ${DIM}3) EC (P-256, modern/compact)${NC}"
    printf '%b' "${ARROW} Key algorithm ${DIM}[1]${NC}: "
    read -r alg_choice
    case "${alg_choice:-1}" in
        2) KEYALG="RSA"; KEYSIZE=2048 ;;
        3) KEYALG="EC";  KEYSIZE=256  ;;
        *) KEYALG="RSA"; KEYSIZE=4096 ;;
    esac

    # Validity
    prompt VALIDITY "Certificate validity in days" "10000"
    validate_validity

    log_info "Advanced: KEYALG=$KEYALG KEYSIZE=$KEYSIZE VALIDITY=$VALIDITY"
}

# ------------------------------------------------------------------------------
# Step 1 — Output file
# ------------------------------------------------------------------------------
step_filename() {
    echo -e "\n${CYAN}${BOLD}[1/6] Output Keystore File${NC}"
    prompt FILENAME "Filename" "release-key.p12"

    # Normalize extension
    if [[ "$FILENAME" != *.p12 && "$FILENAME" != *.jks && "$FILENAME" != *.keystore ]]; then
        FILENAME="${FILENAME}.p12"
        echo -e "  ${DIM}→ Extension '.p12' appended: ${FILENAME}${NC}"
    fi

    # Warn if file already exists
    if [[ -e "$FILENAME" ]]; then
        log_warn "File '${FILENAME}' already exists and will be OVERWRITTEN."
        printf '%b' "${ARROW} Continue anyway? (y/N): "
        read -r overwrite_confirm
        if [[ ! "$overwrite_confirm" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Aborted. Rename your output file and retry.${NC}"
            exit 0
        fi
        rm -f "$FILENAME"
    fi

    log_info "Output file: $FILENAME"
}

# ------------------------------------------------------------------------------
# Step 2 — Alias
# ------------------------------------------------------------------------------
step_alias() {
    echo -e "\n${CYAN}${BOLD}[2/6] Key Alias${NC}"
    prompt ALIAS "Cryptographic alias" "production-alias"
    # Strip whitespace and disallow special shell chars
    ALIAS="${ALIAS//[^a-zA-Z0-9_\-]/-}"
    log_info "Alias: $ALIAS"
}

# ------------------------------------------------------------------------------
# Step 3 — Password
# ------------------------------------------------------------------------------
step_password() {
    echo -e "\n${CYAN}${BOLD}[3/6] Security Credentials${NC}"
    prompt_password
    log_info "Password captured (redacted)"
}

# ------------------------------------------------------------------------------
# Step 4 — X.509 metadata
# ------------------------------------------------------------------------------
step_certificate() {
    echo -e "\n${CYAN}${BOLD}[4/6] X.509 Certificate Distinguished Name${NC}"
    echo -e "  ${DIM}These fields appear in your app's signing certificate.${NC}\n"

    prompt CN "Common Name / Developer Name"   "Android Developer"
    prompt OU "Organizational Unit"            "Mobile Security Lab"
    prompt O  "Organization Name"              "Malvryx Corp"
    prompt L  "City / Locality"                "San Francisco"
    prompt ST "State / Province"               "California"

    while true; do
        prompt C "Two-Letter Country Code (ISO 3166-1)" "US"
        C="${C^^}"  # uppercase
        validate_country_code "$C" && break
    done

    log_info "DN: CN=$CN, OU=$OU, O=$O, L=$L, ST=$ST, C=$C"
}

# ------------------------------------------------------------------------------
# Step 5 — Advanced (optional)
# ------------------------------------------------------------------------------
step_advanced() {
    echo -e "\n${CYAN}${BOLD}[5/6] Advanced Key Parameters${NC}"
    printf '%b' "${ARROW} Configure advanced options? (y/N): "
    read -r adv
    if [[ "$adv" =~ ^[Yy]$ ]]; then
        advanced_options
    else
        echo -e "  ${DIM}Using defaults: RSA-${KEYSIZE}, validity=${VALIDITY} days${NC}"
    fi
}

# ------------------------------------------------------------------------------
# Step 6 — Review & confirm
# ------------------------------------------------------------------------------
step_confirm() {
    echo -e "\n${CYAN}${BOLD}[6/6] Review Parameters${NC}"
    echo -e "${BLUE}"; divider "─"; echo -e "${NC}"
    echo -e "  ${YELLOW}Output File    :${NC} ${BOLD}${FILENAME}${NC}"
    echo -e "  ${YELLOW}Key Alias      :${NC} ${ALIAS}"
    echo -e "  ${YELLOW}Algorithm      :${NC} ${KEYALG}-${KEYSIZE}"
    echo -e "  ${YELLOW}Validity       :${NC} ${VALIDITY} days (~$(( VALIDITY / 365 )) years)"
    echo -e "  ${YELLOW}Store Type     :${NC} ${STORETYPE}"
    echo -e "  ${YELLOW}Common Name    :${NC} ${CN}"
    echo -e "  ${YELLOW}Org Unit       :${NC} ${OU}"
    echo -e "  ${YELLOW}Organization   :${NC} ${O}"
    echo -e "  ${YELLOW}Locality       :${NC} ${L}"
    echo -e "  ${YELLOW}State          :${NC} ${ST}"
    echo -e "  ${YELLOW}Country        :${NC} ${C}"
    echo -e "${BLUE}"; divider "─"; echo -e "${NC}"

    printf '%b' "${ARROW} Generate keystore now? (y/N): "
    read -r CONFIRM
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        echo -e "\n${YELLOW}[Aborted] No files were created.${NC}"
        exit 0
    fi
}

# ------------------------------------------------------------------------------
# Core generation
# ------------------------------------------------------------------------------
generate_keystore() {
    echo -e "\n${GREEN}${BOLD}Executing keytool pipeline...${NC}\n"

    local dname="CN=${CN}, OU=${OU}, O=${O}, L=${L}, ST=${ST}, C=${C}"

    local keytool_args=(
        -genkeypair
        -v
        -keystore  "$FILENAME"
        -storetype "$STORETYPE"
        -alias     "$ALIAS"
        -keyalg    "$KEYALG"
        -keysize   "$KEYSIZE"
        -validity  "$VALIDITY"
        -storepass "$PASS_1"
        -keypass   "$PASS_1"
        -dname     "$dname"
    )

    # EC keys don't use -keysize, they use -groupname
    if [[ "$KEYALG" == "EC" ]]; then
        keytool_args=(
            -genkeypair
            -v
            -keystore  "$FILENAME"
            -storetype "$STORETYPE"
            -alias     "$ALIAS"
            -keyalg    "$KEYALG"
            -groupname secp256r1
            -validity  "$VALIDITY"
            -storepass "$PASS_1"
            -keypass   "$PASS_1"
            -dname     "$dname"
        )
    fi

    if ! keytool "${keytool_args[@]}" >> "$LOG_FILE" 2>&1; then
        log_error "keytool failed. Partial file removed."
        rm -f "$FILENAME"
        echo -e "${DIM}Full error log: ${LOG_FILE}${NC}"
        exit 1
    fi

    log_info "keytool completed successfully"
}

# ------------------------------------------------------------------------------
# Post-generation: verify & fingerprint
# ------------------------------------------------------------------------------
post_verify() {
    echo -e "\n${CYAN}${BOLD}Verifying generated keystore...${NC}"

    local verify_output
    verify_output=$(keytool -list -v \
        -keystore "$FILENAME" \
        -storepass "$PASS_1" \
        -alias "$ALIAS" 2>/dev/null) || {
        log_error "Keystore verification failed — file may be corrupt."
        exit 1
    }

    local sha256 sha1
    sha256=$(echo "$verify_output" | awk '/SHA256:/{print $2}' | head -1)
    sha1=$(echo  "$verify_output" | awk '/SHA1:/{print $2}'   | head -1)
    local size_kb
    size_kb=$(du -k "$FILENAME" | cut -f1)

    echo -e "${BLUE}"; divider "═"; echo -e "${NC}"
    echo -e "  ${GREEN}${BOLD}✔  KEYSTORE CREATED SUCCESSFULLY${NC}"
    echo -e "${BLUE}"; divider "─"; echo -e "${NC}"
    echo -e "  ${YELLOW}Location :${NC} $(realpath "$FILENAME")"
    echo -e "  ${YELLOW}Size     :${NC} ${size_kb} KB"
    echo -e "  ${YELLOW}SHA-256  :${NC} ${sha256:-<unavailable>}"
    echo -e "  ${YELLOW}SHA-1    :${NC} ${sha1:-<unavailable>}"
    echo -e "  ${YELLOW}Log file :${NC} ${LOG_FILE}"
    echo -e "${BLUE}"; divider "─"; echo -e "${NC}"

    echo -e "${DIM}Next steps:"
    echo -e "  • Add to build.gradle (signingConfigs) or use with 'jarsigner'"
    echo -e "  • Back up this .p12 file and your password securely"
    echo -e "  • ${BOLD}Never commit keystores or passwords to version control${NC}${DIM}"
    echo -e "${NC}"

    # Persist a non-secret summary alongside the keystore
    local summary_file="${FILENAME%.p12}_summary.txt"
    {
        echo "=== Keystore Summary — generated by genkey.sh v${SCRIPT_VERSION} ==="
        echo "Date      : $(date)"
        echo "File      : $(realpath "$FILENAME")"
        echo "Alias     : $ALIAS"
        echo "Algorithm : ${KEYALG}-${KEYSIZE}"
        echo "Validity  : ${VALIDITY} days"
        echo "DN        : CN=${CN}, OU=${OU}, O=${O}, L=${L}, ST=${ST}, C=${C}"
        echo "SHA-256   : ${sha256:-<unavailable>}"
        echo "SHA-1     : ${sha1:-<unavailable>}"
        echo ""
        echo "IMPORTANT: Keep your password in a password manager, NOT in this file."
    } > "$summary_file"

    log_success "Summary written to: $summary_file"
}

# ------------------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------------------
main() {
    log_setup
    print_banner

    log_info "genkey.sh v${SCRIPT_VERSION} started (PID $$)"

    check_dependencies
    step_filename
    check_write_permission
    step_alias
    step_password
    step_certificate
    step_advanced
    step_confirm
    generate_keystore
    post_verify

    # Move log to final location next to keystore (no longer temp)
    local final_log="${FILENAME%.p12}_genkey.log"
    cp "$LOG_FILE" "$final_log" 2>/dev/null || true
    log_info "Final log: $final_log"
}

main "$@"
