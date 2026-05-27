#!/bin/bash
set +e
LANG=C

HOSTNAME_FQDN="$(hostname -f 2>/dev/null || hostname 2>/dev/null)"
HOSTNAME_SHORT="$(hostname 2>/dev/null)"
IPV4_LIST="$(hostname -I 2>/dev/null | xargs)"
IPV6_LIST="$(ip -6 addr show scope global 2>/dev/null | awk '/inet6 /{print $2}' | paste -sd ', ' -)"
OS_NAME="$(awk -F= '/^PRETTY_NAME=/{gsub(/"/,"",$2);print $2}' /etc/os-release 2>/dev/null)"
OS_VERSION="$(uname -r 2>/dev/null)"
EXEC_USER="$(id -un 2>/dev/null)"
NOW_TS="$(date '+%Y%m%d%H%M%S')"
NOW_HUMAN="$(date '+%Y-%m-%d %H:%M:%S')"

OK_COUNT=0
WARN_COUNT=0
VULN_COUNT=0
RAW_DATA=""

add_count() {
  case "$1" in
    OK) OK_COUNT=$((OK_COUNT+1));;
    WARN) WARN_COUNT=$((WARN_COUNT+1));;
    VULN) VULN_COUNT=$((VULN_COUNT+1));;
  esac
}

append_raw() {
  local title="$1"; shift
  local value="$*"
  RAW_DATA="${RAW_DATA}### ${title}\n"
  if [ -z "$value" ]; then
    RAW_DATA="${RAW_DATA}(empty)\n\n"
  else
    RAW_DATA="${RAW_DATA}${value}\n\n"
  fi
}

write_item() {
  local code="$1" imp="$2" title="$3" result="$4" verdict="$5" target="$6" current="$7" basis="$8" action="$9"
  add_count "$result"
  {
    echo "------------------------------------------------------------"
    printf "ITEM CODE      : %s\n" "$code"
    printf "IMPORTANCE     : %s\n" "$imp"
    printf "CHECK ITEM     : %s\n" "$title"
    printf "TARGET         : %s\n" "$target"
    printf "RESULT CODE    : %s\n" "$result"
    printf "VERDICT        : %s\n" "$verdict"
    printf "CURRENT        : %s\n" "$current"
    printf "BASIS          : %s\n" "$basis"
    printf "ACTION         : %s\n" "$action"
    echo
  } >> "$OUTFILE"
}

print_profile_table() {
  {
    echo "============================================================"
    printf "%s\n" "$1"
    echo "============================================================"
    echo "[SERVER PROFILE]"
    echo "+----------------+------------------------------------------+"
    printf "| %-14s | %-40s |\n" "Hostname" "$HOSTNAME_SHORT"
    printf "| %-14s | %-40s |\n" "FQDN" "$HOSTNAME_FQDN"
    printf "| %-14s | %-40s |\n" "IPv4" "$IPV4_LIST"
    printf "| %-14s | %-40s |\n" "IPv6" "$IPV6_LIST"
    printf "| %-14s | %-40s |\n" "OS Name" "$OS_NAME"
    printf "| %-14s | %-40s |\n" "OS Version" "$OS_VERSION"
    printf "| %-14s | %-40s |\n" "Exec User" "$EXEC_USER"
    printf "| %-14s | %-40s |\n" "Time" "$NOW_HUMAN"
    echo "+----------------+------------------------------------------+"
    echo
  } > "$OUTFILE"
}

finish_report() {
  {
    echo "==================== SUMMARY ===================="
    printf "OK   : %s\n" "$OK_COUNT"
    printf "WARN : %s\n" "$WARN_COUNT"
    printf "VULN : %s\n" "$VULN_COUNT"
    echo "================================================="
    echo
    echo "==================== RAW DATA ===================="
    printf "%b" "$RAW_DATA"
  } >> "$OUTFILE"
  echo "$OUTFILE"
}

is_loose_perm() {
  local path="$1"
  [ -e "$path" ] || return 1
  local perm
  perm="$(stat -c '%a' "$path" 2>/dev/null)"
  [ -n "$perm" ] || return 1
  local other=${perm: -1}
  local group=${perm: -2:1}
  if [ "$other" -ge 4 ] || [ "$group" -ge 6 ]; then
    return 0
  fi
  return 1
}

OUTFILE="kisa_webtob_linux_audit_${HOSTNAME_SHORT}_${NOW_TS}.txt"
print_profile_table "KISA Linux WebtoB Audit"

# ------------------------------------------------------------
# WebtoB install path input / detection
# Priority:
#   1) First script argument
#   2) Interactive user input
#   3) WEBTOB_HOME environment variable
#   4) Common default paths
#
# Usage examples:
#   ./kisa_webtob_linux_audit_v2.sh
#   ./kisa_webtob_linux_audit_v2.sh /usr/local/webtob
#   WEBTOB_HOME=/usr/local/webtob ./kisa_webtob_linux_audit_v2.sh
# ------------------------------------------------------------
WEBTOB_HOME_INPUT="${1:-}"
WEBTOB_HOME_SOURCE=""

normalize_path() {
  local path="$1"
  path="$(printf '%s' "$path" | sed 's/[[:space:]]*$//' | sed 's/^[[:space:]]*//')"
  path="${path%/}"
  printf '%s' "$path"
}

if [ -n "$WEBTOB_HOME_INPUT" ]; then
  WEBTOB_HOME="$(normalize_path "$WEBTOB_HOME_INPUT")"
  WEBTOB_HOME_SOURCE="script argument"
elif [ -t 0 ]; then
  printf "Enter WebtoB install path. Press Enter to auto-detect"
  if [ -n "${WEBTOB_HOME:-}" ]; then
    printf " [current WEBTOB_HOME=%s]" "$WEBTOB_HOME"
  fi
  printf ": "
  read -r WEBTOB_HOME_INPUT
  WEBTOB_HOME_INPUT="$(normalize_path "$WEBTOB_HOME_INPUT")"
  if [ -n "$WEBTOB_HOME_INPUT" ]; then
    WEBTOB_HOME="$WEBTOB_HOME_INPUT"
    WEBTOB_HOME_SOURCE="interactive input"
  else
    WEBTOB_HOME="${WEBTOB_HOME:-}"
    [ -n "$WEBTOB_HOME" ] && WEBTOB_HOME_SOURCE="environment variable"
  fi
else
  WEBTOB_HOME="${WEBTOB_HOME:-}"
  [ -n "$WEBTOB_HOME" ] && WEBTOB_HOME_SOURCE="environment variable"
fi

WEBTOB_HOME="$(normalize_path "${WEBTOB_HOME:-}")"

if [ -z "$WEBTOB_HOME" ]; then
  for p in /usr/local/webtob* /opt/webtob* /usr/local/tmax/webtob* /opt/tmax/webtob*; do
    [ -d "$p" ] && WEBTOB_HOME="$(normalize_path "$p")" && WEBTOB_HOME_SOURCE="auto-detected default path" && break
  done
fi

WEBTOB_FOUND=0
WEBTOB_PATH_ERROR=""
if [ -n "$WEBTOB_HOME" ] && [ -d "$WEBTOB_HOME" ]; then
  WEBTOB_FOUND=1
else
  WEBTOB_PATH_ERROR="WebtoB install path not found or not a directory: ${WEBTOB_HOME:-N/A}"
fi

WEBTOB_USER="$(ps -eo user,cmd | awk '/[w]sboot|[w]ebtob|[h]ttpd\.webtob/{print $1; exit}')"
WEBTOB_VER="$(
  if [ -x "$WEBTOB_HOME/bin/wscfl" ]; then
    "$WEBTOB_HOME/bin/wscfl" -v 2>/dev/null | tr '\n' ' '
  elif [ -x "$WEBTOB_HOME/bin/wsboot" ]; then
    "$WEBTOB_HOME/bin/wsboot" -v 2>/dev/null | tr '\n' ' '
  fi
)"

CONFIG_FILES="$(
  find "$WEBTOB_HOME" -type f \( -iname '*.m' -o -iname '*.conf' -o -iname '*.cfg' -o -iname 'http.m' -o -iname 'wsconfig' \) 2>/dev/null | head -20
)"

CONFIG_RAW="$(
  for f in $CONFIG_FILES; do
    echo "# FILE: $f"
    sed -n '1,400p' "$f" 2>/dev/null
    echo
  done
)"

{
  echo "[SERVICE PROFILE]"
  echo "+----------------+------------------------------------------+"
  printf "| %-14s | %-40s |\n" "WebtoB Found" "$WEBTOB_FOUND"
  printf "| %-14s | %-40s |\n" "WebtoB Home" "$WEBTOB_HOME"
  printf "| %-14s | %-40s |\n" "WebtoB User" "$WEBTOB_USER"
  printf "| %-14s | %-40s |\n" "WebtoB Version" "$WEBTOB_VER"
  echo "+----------------+------------------------------------------+"
  echo
} >> "$OUTFILE"

if [ "$WEBTOB_FOUND" -ne 1 ]; then
  for i in $(seq -w 1 26); do
    write_item "WEB-$i" "N/A" "WebtoB not found" "WARN" "ManualCheck" "WebtoB" "Install path not found" "$WEBTOB_PATH_ERROR" "Enter correct WebtoB install path and rerun"
  done
  finish_report
  exit 0
fi

listings="$(printf "%s\n" "$CONFIG_RAW" | grep -niE 'directory-list|dirlist|autoindex|Indexing|Indexes' | head -20)"
cgi_exec="$(printf "%s\n" "$CONFIG_RAW" | grep -niE 'CGI|FastCGI|SCGI|PHP|Execute|ExecCGI' | head -20)"
auth_related="$(printf "%s\n" "$CONFIG_RAW" | grep -niE 'auth|access|deny|allow|acl|permission' | head -20)"
proxy="$(printf "%s\n" "$CONFIG_RAW" | grep -niE 'proxy|reverse-proxy|upstream|backend|balancer' | head -20)"
docroot="$(printf "%s\n" "$CONFIG_RAW" | grep -niE 'documentroot|docroot|home|serviceorder|uri' | head -20)"
symlink_cfg="$(printf "%s\n" "$CONFIG_RAW" | grep -niE 'symlink|followlink|alias|mapping' | head -20)"
scriptmap="$(printf "%s\n" "$CONFIG_RAW" | grep -niE 'mime|handler|php|jsp|cgi|fastcgi|servlet' | head -20)"
headerhide="$(printf "%s\n" "$CONFIG_RAW" | grep -niE 'server-header|x-powered-by|header|signature|version' | head -20)"
vdir="$(printf "%s\n" "$CONFIG_RAW" | grep -niE 'alias|mapping|vhost|virtualhost|uri' | head -20)"
webdav="$(printf "%s\n" "$CONFIG_RAW" | grep -niE 'webdav|dav|put|delete|propfind|mkcol' | head -20)"
ssi="$(printf "%s\n" "$CONFIG_RAW" | grep -niE 'ssi|shtml|server.side.include' | head -20)"
ssl="$(printf "%s\n" "$CONFIG_RAW" | grep -niE 'ssl|https|certificate|keyfile|secureport|sslflag' | head -20)"
redirect_https="$(printf "%s\n" "$CONFIG_RAW" | grep -niE 'redirect.*https|301.*https|302.*https|rewrite.*https' | head -20)"
errpage="$(printf "%s\n" "$CONFIG_RAW" | grep -niE 'errorpage|error-page|errordocument' | head -20)"
ldap="$(printf "%s\n" "$CONFIG_RAW" | grep -niE 'ldap|sha-256|sha256|ssha|digest|ldaps' | head -20)"
uploads="$(find "$WEBTOB_HOME" /data /home -maxdepth 5 -type d \( -iname upload -o -iname uploads -o -iname attach -o -iname temp \) 2>/dev/null | head -20)"
default_files="$(find "$WEBTOB_HOME" -maxdepth 4 -type f \( -iname 'index.html' -o -iname 'sample*' -o -iname 'examples*' -o -iname 'manual*' \) 2>/dev/null | head -20)"

write_item "WEB-01" "High" "Default admin account rename" "WARN" "ManualCheck" "WebtoB" "Admin account review required" "$WEBTOB_HOME" "Review WebtoB/Tmax admin IDs"
write_item "WEB-02" "High" "Weak password restriction" "WARN" "ManualCheck" "WebtoB" "Password policy review required" "$WEBTOB_HOME" "Review admin/account password policy"
write_item "WEB-03" "High" "Password file permission" "WARN" "ManualCheck" "WebtoB" "Credential/config file review required" "$CONFIG_FILES" "Check password-bearing file permissions"

[ -n "$listings" ] &&   write_item "WEB-04" "High" "Directory listing disabled" "VULN" "Vulnerable" "WebtoB" "Directory listing-like config found" "$listings" "Disable directory listing" ||   write_item "WEB-04" "High" "Directory listing disabled" "WARN" "ManualCheck" "WebtoB" "Listing config not auto-identified" "$CONFIG_FILES" "Verify WebtoB listing settings"

[ -n "$cgi_exec" ] &&   write_item "WEB-05" "High" "Restrict CGI/ISAPI" "WARN" "ManualCheck" "WebtoB" "CGI/FastCGI-like config found" "$cgi_exec" "Keep only required executable mappings" ||   write_item "WEB-05" "High" "Restrict CGI/ISAPI" "OK" "Good" "WebtoB" "No CGI/FastCGI-like config found" "$CONFIG_FILES" "Keep current state"

write_item "WEB-06" "High" "Restrict parent directory access" "WARN" "ManualCheck" "WebtoB" "Need path/auth review" "$auth_related" "Verify sensitive path controls"

[ -n "$default_files" ] &&   write_item "WEB-07" "Medium" "Remove unnecessary files" "VULN" "Vulnerable" "WebtoB" "Sample/default files found" "$default_files" "Remove unnecessary sample/manual files" ||   write_item "WEB-07" "Medium" "Remove unnecessary files" "OK" "Good" "WebtoB" "Typical sample files not found" "$WEBTOB_HOME" "Keep current state"

printf "%s\n" "$CONFIG_RAW" | grep -qiE 'maxpost|maxupload|maxbody|limitrequestbody|uploadlimit' &&   write_item "WEB-08" "Low" "Upload/download size limit" "OK" "Good" "WebtoB" "Upload/download limit-like config found" "$CONFIG_FILES" "Keep minimum necessary limit" ||   write_item "WEB-08" "Low" "Upload/download size limit" "WARN" "ManualCheck" "WebtoB" "Upload/download limit not auto-identified" "$CONFIG_FILES" "Verify upload/download size limits"

case "$WEBTOB_USER" in
  root|"") write_item "WEB-09" "High" "Least privilege process" "VULN" "Vulnerable" "WebtoB" "WebtoB user is root or unknown" "$WEBTOB_USER" "Use dedicated low-privilege user" ;;
  *) write_item "WEB-09" "High" "Least privilege process" "OK" "Good" "WebtoB" "WebtoB runtime user found" "$WEBTOB_USER" "Keep least privilege" ;;
esac

[ -n "$proxy" ] &&   write_item "WEB-10" "High" "Restrict proxy settings" "WARN" "ManualCheck" "WebtoB" "Proxy-like config found" "$proxy" "Keep only required proxy settings" ||   write_item "WEB-10" "High" "Restrict proxy settings" "WARN" "ManualCheck" "WebtoB" "Proxy config not auto-identified" "$CONFIG_FILES" "Verify proxy config"

write_item "WEB-11" "Medium" "Proper web root path" "WARN" "ManualCheck" "WebtoB" "Need document root review" "$docroot" "Verify dedicated deployment paths"
write_item "WEB-12" "Medium" "Avoid symbolic links" "WARN" "ManualCheck" "WebtoB" "Need symlink/alias mapping review" "$symlink_cfg" "Verify link-like mapping"
write_item "WEB-13" "High" "Prevent config file exposure" "WARN" "ManualCheck" "WebtoB" "Need deployed file review" "$WEBTOB_HOME" "Check config/backup files under service roots"

perm_vuln=""
for p in $CONFIG_FILES "$WEBTOB_HOME" "$WEBTOB_HOME/config" "$WEBTOB_HOME/conf"; do
  [ -e "$p" ] && is_loose_perm "$p" && perm_vuln="${perm_vuln} $p"
done
[ -n "$perm_vuln" ] &&   write_item "WEB-14" "High" "Access control for files" "VULN" "Vulnerable" "WebtoB" "Loose permissions found" "$perm_vuln" "Tighten permissions" ||   write_item "WEB-14" "High" "Access control for files" "OK" "Good" "WebtoB" "No obvious loose permission found" "$WEBTOB_HOME" "Keep current state"

write_item "WEB-15" "High" "Remove unnecessary script mapping" "WARN" "ManualCheck" "WebtoB" "Application/script mapping review required" "$scriptmap" "Review unnecessary handlers and mappings"

[ -n "$headerhide" ] &&   write_item "WEB-16" "Medium" "Limit header disclosure" "WARN" "ManualCheck" "WebtoB" "Header/version config found" "$headerhide" "Verify actual response header disclosure" ||   write_item "WEB-16" "Medium" "Limit header disclosure" "WARN" "ManualCheck" "WebtoB" "Need live header verification" "$CONFIG_FILES" "Check actual response headers"

write_item "WEB-17" "Medium" "Remove unnecessary virtual dirs" "WARN" "ManualCheck" "WebtoB" "Virtual path review required" "$vdir" "Remove unnecessary virtual paths"

[ -n "$webdav" ] &&   write_item "WEB-18" "High" "Disable WebDAV" "VULN" "Vulnerable" "WebtoB" "WebDAV-like config found" "$webdav" "Disable WebDAV/authoring methods" ||   write_item "WEB-18" "High" "Disable WebDAV" "WARN" "ManualCheck" "WebtoB" "WebDAV config not auto-identified" "$CONFIG_FILES" "Verify WebDAV disabled"

[ -n "$ssi" ] &&   write_item "WEB-19" "Medium" "Restrict SSI" "VULN" "Vulnerable" "WebtoB" "SSI text found" "$ssi" "Disable SSI" ||   write_item "WEB-19" "Medium" "Restrict SSI" "WARN" "ManualCheck" "WebtoB" "SSI config not auto-identified" "$CONFIG_FILES" "Verify SSI disabled"

[ -n "$ssl" ] &&   write_item "WEB-20" "High" "Enable SSL/TLS" "OK" "Good" "WebtoB" "HTTPS/SSL config found" "$ssl" "Keep modern TLS settings" ||   write_item "WEB-20" "High" "Enable SSL/TLS" "VULN" "Vulnerable" "WebtoB" "HTTPS/SSL config not found" "$CONFIG_FILES" "Enable HTTPS"

[ -n "$redirect_https" ] &&   write_item "WEB-21" "Medium" "HTTP redirect to HTTPS" "OK" "Good" "WebtoB" "HTTPS redirect found" "$redirect_https" "Keep current state" ||   write_item "WEB-21" "Medium" "HTTP redirect to HTTPS" "WARN" "ManualCheck" "WebtoB" "HTTPS redirect not auto-confirmed" "$CONFIG_FILES" "Verify redirect"

[ -n "$errpage" ] &&   write_item "WEB-22" "Low" "Error page management" "OK" "Good" "WebtoB" "Error page config found" "$errpage" "Keep current state" ||   write_item "WEB-22" "Low" "Error page management" "WARN" "ManualCheck" "WebtoB" "Error page config not auto-identified" "$CONFIG_FILES" "Verify custom error pages"

[ -n "$ldap" ] &&   write_item "WEB-23" "Medium" "LDAP algorithm configuration" "WARN" "ManualCheck" "WebtoB" "LDAP/digest config found" "$ldap" "Verify SHA-256+ and TLS" ||   write_item "WEB-23" "Medium" "LDAP algorithm configuration" "WARN" "ManualCheck" "WebtoB" "LDAP use not confirmed" "$CONFIG_FILES" "Verify only if LDAP is used"

[ -n "$uploads" ] &&   write_item "WEB-24" "Medium" "Separate upload path and ACL" "WARN" "ManualCheck" "WebtoB" "Upload-like directories found" "$uploads" "Verify non-webroot placement and ACL" ||   write_item "WEB-24" "Medium" "Separate upload path and ACL" "WARN" "ManualCheck" "WebtoB" "Upload path not auto-identified" "App-specific" "Verify upload segregation manually"

write_item "WEB-25" "High" "Apply security patches" "WARN" "ManualCheck" "WebtoB" "Installed version identified" "$WEBTOB_VER" "Compare with vendor advisories"

logdir="$(find "$WEBTOB_HOME" -maxdepth 3 -type d \( -iname logs -o -iname log \) 2>/dev/null | head -1)"
[ -n "$logdir" ] && is_loose_perm "$logdir" &&   write_item "WEB-26" "Medium" "Log directory/file permission" "VULN" "Vulnerable" "WebtoB" "Loose log directory permission" "$logdir" "Tighten log permissions" ||   write_item "WEB-26" "Medium" "Log directory/file permission" "WARN" "ManualCheck" "WebtoB" "Need WebtoB log dir review" "$logdir" "Verify actual log path and ACL"

append_raw "webtob home input source" "$WEBTOB_HOME_SOURCE"
append_raw "webtob path error" "$WEBTOB_PATH_ERROR"
append_raw "webtob version" "$WEBTOB_VER"
append_raw "candidate config file list" "$CONFIG_FILES"
append_raw "candidate config content" "$CONFIG_RAW"
append_raw "ssl matches" "$ssl"
append_raw "proxy matches" "$proxy"
append_raw "ldap matches" "$ldap"
finish_report
