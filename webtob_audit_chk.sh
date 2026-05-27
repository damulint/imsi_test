cp -p webtob_audit_chk.sh webtob_audit_chk.sh.bak 2>/dev/nullcp -p webtob_audit_chk.sh webtob_audit_chk.sh.b" "$IPV6_LIST"
    printf "OS Name    : %s\n" "$OS_NAME"
    printf "OS Version : %s\n" "$OS_VERSION"
    printf "Exec User  : %s\n" "$EXEC_USER"
    printf "Time       : %s\n" "$NOW_HUMAN"
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

is_loose_file_perm() {
  local path="$1"
  [ -f "$path" ] || return 1

  local perm
  local other
  local group

  perm="$(stat -c '%a' "$path" 2>/dev/null)"
  [ -n "$perm" ] || return 1

  other=${perm: -1}
  group=${perm: -2:1}

  if [ "$other" -gt 0 ] || [ "$group" -ge 6 ]; then
    return 0
  fi

  return 1
}

is_loose_dir_perm() {
  local path="$1"
  [ -d "$path" ] || return 1

  local perm
  local other
  local group

  perm="$(stat -c '%a' "$path" 2>/dev/null)"
  [ -n "$perm" ] || return 1

  other=${perm: -1}
  group=${perm: -2:1}

  if [ "$other" -ge 2 ] || [ "$group" -ge 6 ]; then
    return 0
  fi

  return 1
}

detect_webtob_home() {
  if [ -n "$WEBTOB_HOME" ] && [ -d "$WEBTOB_HOME" ]; then
    return 0
  fi

  local candidates

  candidates="$(
    find /usr/local /opt /app /data -maxdepth 4 -type d \
      \( -iname 'webtob' -o -iname 'webtob[0-9]*' \) \
      2>/dev/null | sort
  )"

  while IFS= read -r d; do
    [ -n "$d" ] || continue

    if [ -x "$d/bin/wsboot" ] || [ -x "$d/bin/wscfl" ]; then
      WEBTOB_HOME="$d"
      return 0
    fi
  done <<EOI
$candidates
EOI

  return 1
}

collect_config_files() {
  local home="$1"

  [ -n "$home" ] && [ -d "$home" ] || return 1

  find "$home" -maxdepth 6 -type f \
    \( \
      -iname 'http.m' \
      -o -iname '*.m' \
      -o -iname 'wsconfig' \
      -o -iname '*.conf' \
      -o -iname '*.cfg' \
    \) \
    ! -path '*/sample/*' \
    ! -path '*/samples/*' \
    ! -path '*/example/*' \
    ! -path '*/examples/*' \
    ! -path '*/backup/*' \
    ! -path '*/bak/*' \
    ! -iname '*.bak' \
    ! -iname '*.old' \
    ! -iname '*.org' \
    ! -iname '*.orig' \
    ! -iname '*.save' \
    2>/dev/null | sort | head -50
}

collect_config_raw() {
  local files="$1"

  while IFS= read -r f; do
    [ -n "$f" ] || continue
    [ -f "$f" ] || continue

    echo "# FILE: $f"
    sed -n '1,400p' "$f" 2>/dev/null
    echo
  done <<EOI
$files
EOI
}

OUTFILE="kisa_webtob_linux_audit_${HOSTNAME_SHORT}_${NOW_TS}.txt"
print_profile_table "KISA Linux WebtoB Audit"

WEBTOB_HOME="${WEBTOB_HOME:-}"
detect_webtob_home

WEBTOB_FOUND=0
[ -n "$WEBTOB_HOME" ] && [ -d "$WEBTOB_HOME" ] && WEBTOB_FOUND=1

if [ "$WEBTOB_FOUND" -ne 1 ]; then
  WEBTOB_USER=""
  WEBTOB_VER=""
  CONFIG_FILES=""
  CONFIG_RAW=""

  {
    echo "[SERVICE PROFILE]"
    printf "WebtoB Found   : %s\n" "$WEBTOB_FOUND"
    printf "WebtoB Home    : %s\n" "$WEBTOB_HOME"
    printf "WebtoB User    : %s\n" "$WEBTOB_USER"
    printf "WebtoB Version : %s\n" "$WEBTOB_VER"
    echo
  } >> "$OUTFILE"

  for i in $(seq -w 1 26); do
    write_item "WEB-$i" "N/A" "WebtoB not found" "WARN" "ManualCheck" "WebtoB" \
      "Install path not found" \
      "WEBTOB_HOME not identified" \
      "Verify installation and rerun"
  done

  append_raw "webtob detection" "WEBTOB_HOME=$WEBTOB_HOME"
  finish_report
  exit 0
fi

WEBTOB_USERS="$(
  ps -eo user=,comm=,args= 2>/dev/null |
  awk '
    /wsboot|wsm|htl|htmls|webtob|httpd.webtob/ {
      print $1
    }
  ' | sort -u | paste -sd ',' -
)"

WEBTOB_USER="$WEBTOB_USERS"

WEBTOB_VER="$(
  if [ -x "$WEBTOB_HOME/bin/wscfl" ]; then
    "$WEBTOB_HOME/bin/wscfl" -v 2>/dev/null | tr '\n' ' '
  elif [ -x "$WEBTOB_HOME/bin/wsboot" ]; then
    "$WEBTOB_HOME/bin/wsboot" -v 2>/dev/null | tr '\n' ' '
  fi
)"

CONFIG_FILES="$(collect_config_files "$WEBTOB_HOME")"
CONFIG_RAW="$(collect_config_raw "$CONFIG_FILES")"

{
  echo "[SERVICE PROFILE]"
  printf "WebtoB Found   : %s\n" "$WEBTOB_FOUND"
  printf "WebtoB Home    : %s\n" "$WEBTOB_HOME"
  printf "WebtoB User    : %s\n" "$WEBTOB_USER"
  printf "WebtoB Version : %s\n" "$WEBTOB_VER"
  printf "Config Count   : %s\n" "$(printf "%s\n" "$CONFIG_FILES" | awk 'NF{c++} END{print c+0}')"
  echo
} >> "$OUTFILE"

listings="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE '(^|[[:space:]])(directory-list|directorylisting|dirlist|autoindex|indexes)([[:space:]]*[:=][[:space:]]*|[[:space:]]+)(on|yes|true|enable|enabled|1)|Options[[:space:]].*Indexes' |
  head -20
)"

listing_related="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE 'directory-list|directorylisting|dirlist|autoindex|indexing|indexes|Options' |
  head -20
)"

cgi_exec="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE '\b(CGI|FastCGI|SCGI|PHP|ExecCGI)\b|Execute' |
  head -20
)"

auth_related="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE 'auth|access|deny|allow|acl|permission' |
  head -20
)"

proxy="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE 'proxy|reverse-proxy|upstream|backend|balancer' |
  head -20
)"

docroot="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE 'documentroot|docroot|serverroot|home|serviceorder|uri' |
  head -20
)"

symlink_cfg="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE 'symlink|followlink|alias|mapping' |
  head -20
)"

scriptmap="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE 'mime|handler|php|jsp|cgi|fastcgi|servlet' |
  head -20
)"

headerhide="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE 'server-header|x-powered-by|header|signature|version' |
  head -20
)"

vdir="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE 'alias|mapping|vhost|virtualhost|uri' |
  head -20
)"

webdav="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE '\b(webdav|dav|propfind|proppatch|mkcol|copy|move|lock|unlock)\b|(^|[[:space:],;])PUT([[:space:],;]|$)|(^|[[:space:],;])DELETE([[:space:],;]|$)' |
  head -20
)"

ssi="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE '\bSSI\b|shtml|server[.]side[.]include|server-side-include' |
  head -20
)"

ssl="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE '\bssl\b|https|certificate|certfile|keyfile|secureport|sslflag|tls' |
  head -20
)"

weak_tls="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE 'SSLv2|SSLv3|TLSv1([^.]|$)|TLSv1\.0|TLSv1\.1|RC4|3DES|DES|MD5|NULL|EXPORT|anon|aNULL|eNULL' |
  head -20
)"

ssl_disabled="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE 'sslflag[[:space:]]*[:=]?[[:space:]]*(n|no|false|off|0)|ssl[[:space:]]*[:=][[:space:]]*(n|no|false|off|0)' |
  head -20
)"

redirect_https="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE 'redirect.*https|301.*https|302.*https|rewrite.*https' |
  head -20
)"

errpage="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE 'errorpage|error-page|errordocument' |
  head -20
)"

ldap="$(
  printf "%s\n" "$CONFIG_RAW" |
  grep -niE 'ldap|sha-256|sha256|ssha|digest|ldaps' |
  head -20
)"

uploads="$(
  find "$WEBTOB_HOME" /data /home -maxdepth 5 -type d \
    \( -iname upload -o -iname uploads -o -iname attach -o -iname temp \) \
    2>/dev/null | sort | head -20
)"

default_files="$(
  find "$WEBTOB_HOME" -maxdepth 4 -type f \
    \( -iname 'sample*' -o -iname 'examples*' -o -iname 'manual*' \) \
    2>/dev/null | sort | head -20
)"

write_item "WEB-01" "High" "Default admin account rename" "WARN" "ManualCheck" "WebtoB" \
  "Admin account review required" "$WEBTOB_HOME" "Review WebtoB/Tmax admin IDs"

write_item "WEB-02" "High" "Weak password restriction" "WARN" "ManualCheck" "WebtoB" \
  "Password policy review required" "$WEBTOB_HOME" "Review admin/account password policy"

write_item "WEB-03" "High" "Password file permission" "WARN" "ManualCheck" "WebtoB" \
  "Credential/config file review required" "$CONFIG_FILES" "Check password-bearing file permissions"

if [ -n "$listings" ]; then
  write_item "WEB-04" "High" "Directory listing disabled" "VULN" "Vulnerable" "WebtoB" \
    "Directory listing enabled-like config found" "$listings" "Disable directory listing"
elif [ -n "$listing_related" ]; then
  write_item "WEB-04" "High" "Directory listing disabled" "WARN" "ManualCheck" "WebtoB" \
    "Directory listing-related config found but enabled state is unclear" "$listing_related" "Verify directory listing setting manually"
else
  write_item "WEB-04" "High" "Directory listing disabled" "OK" "Good" "WebtoB" \
    "Directory listing enabled-like config not found" "$CONFIG_FILES" "Keep current state"
fi

if [ -n "$cgi_exec" ]; then
  write_item "WEB-05" "High" "Restrict CGI/ISAPI" "WARN" "ManualCheck" "WebtoB" \
    "CGI/FastCGI-like config found" "$cgi_exec" "Keep only required executable mappings"
else
  write_item "WEB-05" "High" "Restrict CGI/ISAPI" "OK" "Good" "WebtoB" \
    "No CGI/FastCGI-like config found" "$CONFIG_FILES" "Keep current state"
fi

write_item "WEB-06" "High" "Restrict parent directory access" "WARN" "ManualCheck" "WebtoB" \
  "Need path/auth review" "$auth_related" "Verify sensitive path controls"

if [ -n "$default_files" ]; then
  write_item "WEB-07" "Medium" "Remove unnecessary files" "VULN" "Vulnerable" "WebtoB" \
    "Sample/default files found" "$default_files" "Remove unnecessary sample/manual files"
else
  write_item "WEB-07" "Medium" "Remove unnecessary files" "OK" "Good" "WebtoB" \
    "Typical sample/manual files not found" "$WEBTOB_HOME" "Keep current state"
fi

if printf "%s\n" "$CONFIG_RAW" | grep -qiE 'maxpost|maxupload|maxbody|limitrequestbody|uploadlimit'; then
  write_item "WEB-08" "Low" "Upload/download size limit" "OK" "Good" "WebtoB" \
    "Upload/download limit-like config found" "$CONFIG_FILES" "Keep minimum necessary limit"
else
  write_item "WEB-08" "Low" "Upload/download size limit" "WARN" "ManualCheck" "WebtoB" \
    "Upload/download limit not auto-identified" "$CONFIG_FILES" "Verify upload/download size limits"
fi

case ",$WEBTOB_USER," in
  *",root,"*|",,")
    write_item "WEB-09" "High" "Least privilege process" "VULN" "Vulnerable" "WebtoB" \
      "WebtoB user includes root or is unknown" "$WEBTOB_USER" "Use dedicated low-privilege user"
    ;;
  *)
    write_item "WEB-09" "High" "Least privilege process" "OK" "Good" "WebtoB" \
      "WebtoB runtime user found" "$WEBTOB_USER" "Keep least privilege"
    ;;
esac

if [ -n "$proxy" ]; then
  write_item "WEB-10" "High" "Restrict proxy settings" "WARN" "ManualCheck" "WebtoB" \
    "Proxy-like config found" "$proxy" "Keep only required proxy settings"
else
  write_item "WEB-10" "High" "Restrict proxy settings" "WARN" "ManualCheck" "WebtoB" \
    "Proxy config not auto-identified" "$CONFIG_FILES" "Verify proxy config"
fi

write_item "WEB-11" "Medium" "Proper web root path" "WARN" "ManualCheck" "WebtoB" \
  "Need document root review" "$docroot" "Verify dedicated deployment paths"

write_item "WEB-12" "Medium" "Avoid symbolic links" "WARN" "ManualCheck" "WebtoB" \
  "Need symlink/alias mapping review" "$symlink_cfg" "Verify link-like mapping"

write_item "WEB-13" "High" "Prevent config file exposure" "WARN" "ManualCheck" "WebtoB" \
  "Need deployed file review" "$WEBTOB_HOME" "Check config/backup files under service roots"

perm_vuln=""

while IFS= read -r p; do
  [ -n "$p" ] || continue
  [ -e "$p" ] || continue

  if [ -f "$p" ]; then
    if is_loose_file_perm "$p"; then
      perm_vuln="${perm_vuln}${p} $(stat -c '%U:%G %a' "$p" 2>/dev/null)\n"
    fi
  elif [ -d "$p" ]; then
    if is_loose_dir_perm "$p"; then
      perm_vuln="${perm_vuln}${p} $(stat -c '%U:%G %a' "$p" 2>/dev/null)\n"
    fi
  fi
done <<EOI
$CONFIG_FILES
$WEBTOB_HOME
$WEBTOB_HOME/config
$WEBTOB_HOME/conf
EOI

if [ -n "$perm_vuln" ]; then
  write_item "WEB-14" "High" "Access control for files" "VULN" "Vulnerable" "WebtoB" \
    "Loose permissions found" "$(printf "%b" "$perm_vuln")" "Tighten permissions"
else
  write_item "WEB-14" "High" "Access control for files" "OK" "Good" "WebtoB" \
    "No obvious loose permission found by separated file/dir criteria" "$WEBTOB_HOME" "Keep current state"
fi

write_item "WEB-15" "High" "Remove unnecessary script mapping" "WARN" "ManualCheck" "WebtoB" \
  "Application/script mapping review required" "$scriptmap" "Review unnecessary handlers and mappings"

if [ -n "$headerhide" ]; then
  write_item "WEB-16" "Medium" "Limit header disclosure" "WARN" "ManualCheck" "WebtoB" \
    "Header/version config found" "$headerhide" "Verify actual response header disclosure"
else
  write_item "WEB-16" "Medium" "Limit header disclosure" "WARN" "ManualCheck" "WebtoB" \
    "Need live header verification" "$CONFIG_FILES" "Check actual response headers"
fi

write_item "WEB-17" "Medium" "Remove unnecessary virtual dirs" "WARN" "ManualCheck" "WebtoB" \
  "Virtual path review required" "$vdir" "Remove unnecessary virtual paths"

if [ -n "$webdav" ]; then
  write_item "WEB-18" "High" "Disable WebDAV" "VULN" "Vulnerable" "WebtoB" \
    "WebDAV-like config found" "$webdav" "Disable WebDAV/authoring methods"
else
  write_item "WEB-18" "High" "Disable WebDAV" "OK" "Good" "WebtoB" \
    "WebDAV enabled-like config not found" "$CONFIG_FILES" "Keep current state or verify if application uses authoring methods"
fi

if [ -n "$ssi" ]; then
  write_item "WEB-19" "Medium" "Restrict SSI" "VULN" "Vulnerable" "WebtoB" \
    "SSI text found" "$ssi" "Disable SSI"
else
  write_item "WEB-19" "Medium" "Restrict SSI" "OK" "Good" "WebtoB" \
    "SSI config not found" "$CONFIG_FILES" "Keep current state"
fi

if [ -n "$ssl_disabled" ]; then
  write_item "WEB-20" "High" "Enable SSL/TLS" "VULN" "Vulnerable" "WebtoB" \
    "SSL/TLS appears disabled" "$ssl_disabled" "Enable HTTPS and use modern TLS settings"
elif [ -n "$weak_tls" ]; then
  write_item "WEB-20" "High" "Enable SSL/TLS" "VULN" "Vulnerable" "WebtoB" \
    "Weak SSL/TLS setting found" "$weak_tls" "Disable SSLv2/SSLv3/TLS1.0/TLS1.1 and weak ciphers"
elif [ -n "$ssl" ]; then
  write_item "WEB-20" "High" "Enable SSL/TLS" "WARN" "ManualCheck" "WebtoB" \
    "SSL/TLS config found but strength is not fully verified by static check" "$ssl" "Verify TLS protocol and cipher suites with live scan or vendor config review"
else
  write_item "WEB-20" "High" "Enable SSL/TLS" "VULN" "Vulnerable" "WebtoB" \
    "HTTPS/SSL config not found" "$CONFIG_FILES" "Enable HTTPS"
fi

if [ -n "$redirect_https" ]; then
  write_item "WEB-21" "Medium" "HTTP redirect to HTTPS" "OK" "Good" "WebtoB" \
    "HTTPS redirect found" "$redirect_https" "Keep current state"
else
  write_item "WEB-21" "Medium" "HTTP redirect to HTTPS" "WARN" "ManualCheck" "WebtoB" \
    "HTTPS redirect not auto-confirmed" "$CONFIG_FILES" "Verify redirect"
fi

if [ -n "$errpage" ]; then
  write_item "WEB-22" "Low" "Error page management" "OK" "Good" "WebtoB" \
    "Error page config found" "$errpage" "Keep current state"
else
  write_item "WEB-22" "Low" "Error page management" "WARN" "ManualCheck" "WebtoB" \
    "Error page config not auto-identified" "$CONFIG_FILES" "Verify custom error pages"
fi

if [ -n "$ldap" ]; then
  write_item "WEB-23" "Medium" "LDAP algorithm configuration" "WARN" "ManualCheck" "WebtoB" \
    "LDAP/digest config found" "$ldap" "Verify SHA-256+ and TLS"
else
  write_item "WEB-23" "Medium" "LDAP algorithm configuration" "WARN" "ManualCheck" "WebtoB" \
    "LDAP use not confirmed" "$CONFIG_FILES" "Verify only if LDAP is used"
fi

if [ -n "$uploads" ]; then
  write_item "WEB-24" "Medium" "Separate upload path and ACL" "WARN" "ManualCheck" "WebtoB" \
    "Upload-like directories found" "$uploads" "Verify non-webroot placement and ACL"
else
  write_item "WEB-24" "Medium" "Separate upload path and ACL" "WARN" "ManualCheck" "WebtoB" \
    "Upload path not auto-identified" "App-specific" "Verify upload segregation manually"
fi

write_item "WEB-25" "High" "Apply security patches" "WARN" "ManualCheck" "WebtoB" \
  "Installed version identified" "$WEBTOB_VER" "Compare with vendor advisories"

logdir="$(
  find "$WEBTOB_HOME" -maxdepth 3 -type d \
    \( -iname logs -o -iname log \) \
    2>/dev/null | sort | head -1
)"

if [ -n "$logdir" ] && is_loose_dir_perm "$logdir"; then
  write_item "WEB-26" "Medium" "Log directory/file permission" "VULN" "Vulnerable" "WebtoB" \
    "Loose log directory permission" "$logdir $(stat -c '%U:%G %a' "$logdir" 2>/dev/null)" "Tighten log permissions"
else
  write_item "WEB-26" "Medium" "Log directory/file permission" "WARN" "ManualCheck" "WebtoB" \
    "Need WebtoB log dir review" "$logdir" "Verify actual log path and ACL"
fi

append_raw "webtob home" "$WEBTOB_HOME"
append_raw "webtob user" "$WEBTOB_USER"
append_raw "webtob version" "$WEBTOB_VER"
append_raw "candidate config file list" "$CONFIG_FILES"
append_raw "candidate config content" "$CONFIG_RAW"
append_raw "directory listing enabled-like matches" "$listings"
append_raw "directory listing related matches" "$listing_related"
append_raw "ssl matches" "$ssl"
append_raw "weak tls matches" "$weak_tls"
append_raw "ssl disabled matches" "$ssl_disabled"
append_raw "webdav matches" "$webdav"
append_raw "proxy matches" "$proxy"
append_raw "ldap matches" "$ldap"
append_raw "permission vulnerable list" "$(printf "%b" "$perm_vuln")"

finish_report
EOF

chmod +x webtob_audit_chk.sh

cat > webtob_audit_chk.sh <<'EOF'
#!/bin/bash
set +e
set -o pipefail 2>/dev/null || true
export LANG=C
export LC_ALL=C

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
  local title="$1"
  shift
  local value="$*"

  RAW_DATA="${RAW_DATA}### ${title}\n"
  if [ -z "$value" ]; then
    RAW_DATA="${RAW_DATA}(empty)\n\n"
  else
    RAW_DATA="${RAW_DATA}${value}\n\n"
  fi
}

write_item() {
  local code="$1"
  local imp="$2"
  local title="$3"
  local result="$4"
  local verdict="$5"
  local target="$6"
  local current="$7"
  local basis="$8"
  local action="$9"

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
    printf "Hostname   : %s\n" "$HOSTNAME_SHORT"
    printf "FQDN       : %s\n" "$HOSTNAME_FQDN"
    printf "IPv4       : %s\n" "$IPV4_LIST"
