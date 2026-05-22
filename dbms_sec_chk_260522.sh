#!/bin/bash
set +e
LANG=C

DBMS="${1:-}"

if [ -z "$DBMS" ]; then
  echo "Usage: $0 {oracle|mysql|postgresql|altibase|tibero|cubrid}"
  exit 1
fi

case "$DBMS" in
  oracle|mysql|postgresql|altibase|tibero|cubrid) ;;
  *)
    echo "Unsupported DBMS: $DBMS"
    echo "Usage: $0 {oracle|mysql|postgresql|altibase|tibero|cubrid}"
    exit 1
    ;;
esac

prompt_default() {
  local label="$1"
  local default="$2"
  local value=""
  read -r -p "$label [$default]: " value
  if [ -z "$value" ]; then
    printf "%s" "$default"
  else
    printf "%s" "$value"
  fi
}

prompt_hidden() {
  local label="$1"
  local value=""
  read -r -s -p "$label: " value
  echo
  printf "%s" "$value"
}

find_client() {
  case "$DBMS" in
    oracle) command -v sqlplus 2>/dev/null ;;
    mysql) command -v mariadb 2>/dev/null || command -v mysql 2>/dev/null ;;
    postgresql) command -v psql 2>/dev/null ;;
    altibase) command -v is 2>/dev/null ;;
    tibero) command -v tbsql 2>/dev/null ;;
    cubrid) command -v csql 2>/dev/null ;;
  esac
}

mask_sensitive_text() {
  sed -E \
    -e 's/([Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd][[:space:]]*=[[:space:]]*)[^[:space:]]+/\1********/g' \
    -e 's/(-p)[^[:space:]]+/\1********/g' \
    -e 's/(password[[:space:]]*:[[:space:]]*)[^[:space:]]+/\1********/Ig'
}

DB_HOST="$(prompt_default 'DBHOST' 'localhost')"

case "$DBMS" in
  oracle) DB_PORT="$(prompt_default 'DBPORT' '1521')" ;;
  mysql) DB_PORT="$(prompt_default 'DBPORT' '3306')" ;;
  postgresql) DB_PORT="$(prompt_default 'DBPORT' '5432')" ;;
  altibase) DB_PORT="$(prompt_default 'DBPORT' '20300')" ;;
  tibero) DB_PORT="$(prompt_default 'DBPORT' '8629')" ;;
  cubrid) DB_PORT="$(prompt_default 'DBPORT' '33000')" ;;
esac

DB_USER="$(prompt_default 'DBUSER' '')"
DB_PASS="$(prompt_hidden 'DBPASS')"
DB_NAME="$(prompt_default 'DBNAME' '')"
DB_SERVICE="$(prompt_default 'DBSERVICE/SID(if needed)' '')"

DB_SOCKET=""
if [ "$DBMS" = "mysql" ]; then
  DB_SOCKET="$(prompt_default 'DBSOCKET(optional, blank=auto)' '')"
fi

CLIENT_BIN="$(find_client)"
HOST_SHORT="$(hostname -s 2>/dev/null || hostname 2>/dev/null || echo unknown)"
OUTFILE="kisa_${DBMS}_unix_${HOST_SHORT}_$(date '+%Y%m%d%H%M%S').txt"
SQL_ERR_FILE="/tmp/kisa_${DBMS}_sqlerr_$$.log"
: > "$SQL_ERR_FILE"

OK_COUNT=0
WARN_COUNT=0
VULN_COUNT=0
NA_COUNT=0
ERROR_COUNT=0
RAW_DATA=""

add_count() {
  case "$1" in
    OK) OK_COUNT=$((OK_COUNT + 1)) ;;
    WARN) WARN_COUNT=$((WARN_COUNT + 1)) ;;
    VULN) VULN_COUNT=$((VULN_COUNT + 1)) ;;
    N/A) NA_COUNT=$((NA_COUNT + 1)) ;;
    ERROR) ERROR_COUNT=$((ERROR_COUNT + 1)) ;;
  esac
}

append_raw() {
  local title="$1"
  shift
  local value="$*"

  if [ -z "$value" ]; then
    value="(empty)"
  fi

  RAW_DATA="${RAW_DATA}### ${title}"$'\n'"${value}"$'\n\n'
}

write_item() {
  local code="$1"
  local imp="$2"
  local title="$3"
  local result="$4"
  local verdict="$5"
  local current="$6"
  local basis="$7"
  local action="$8"

  add_count "$result"

  {
    echo "------------------------------------------------------------"
    printf "ITEM CODE      : %s\n" "$code"
    printf "IMPORTANCE     : %s\n" "$imp"
    printf "CHECK ITEM     : %s\n" "$title"
    printf "RESULT CODE    : %s\n" "$result"
    printf "VERDICT        : %s\n" "$verdict"
    printf "CURRENT        : %s\n" "$current"
    printf "BASIS          : %s\n" "$basis"
    printf "ACTION         : %s\n" "$action"
    echo
  } >> "$OUTFILE"
}

mysql_run_once() {
  local q="$1"
  shift
  local label="$1"
  shift

  local err=""
  local tmpout=""
  local rc=0

  err="$(mktemp /tmp/kisa_mysql_err.XXXXXX 2>/dev/null || echo /tmp/kisa_mysql_err.$$)"
  tmpout="$(mktemp /tmp/kisa_mysql_out.XXXXXX 2>/dev/null || echo /tmp/kisa_mysql_out.$$)"

  "$CLIENT_BIN" --batch --raw --skip-column-names --connect-timeout=5 --show-warnings "$@" -e "$q" > "$tmpout" 2> "$err"
  rc=$?

  if [ -s "$err" ]; then
    {
      echo "----- ${label} rc=${rc} -----"
      echo "QUERY: $(printf "%s" "$q" | tr '\n' ' ' | cut -c1-300)"
      sed -n '1,30p' "$err" | mask_sensitive_text
      echo
    } >> "$SQL_ERR_FILE"
  fi

  cat "$tmpout"
  rm -f "$err" "$tmpout"
  return $rc
}

exec_sql() {
  local q="$1"

  case "$DBMS" in
    oracle)
      [ -n "$CLIENT_BIN" ] || return 1
      [ -n "$DB_USER" ] || return 1
      [ -n "$DB_PASS" ] || return 1

      {
        echo "set pagesize 50000"
        echo "set linesize 32767"
        echo "set trimspool on"
        echo "set feedback off"
        echo "set verify off"
        echo "set heading off"
        echo "$q"
        echo "exit"
      } | "$CLIENT_BIN" -s "${DB_USER}/${DB_PASS}${DB_SERVICE:+@${DB_SERVICE}}" 2>>"$SQL_ERR_FILE"
      ;;

    mysql)
      [ -n "$CLIENT_BIN" ] || return 1

      local common_args=()

      if [ -n "$DB_USER" ]; then
        common_args+=("-u" "$DB_USER")
      fi

      if [ -n "$DB_PASS" ]; then
        common_args+=("-p${DB_PASS}")
      fi

      if [ -n "$DB_NAME" ]; then
        common_args+=("$DB_NAME")
      fi

      local out=""
      local rc=0

      if [ "$DB_HOST" = "localhost" ] || [ "$DB_HOST" = "127.0.0.1" ]; then
        out="$(mysql_run_once "$q" "mysql tcp 127.0.0.1:${DB_PORT}" --protocol=TCP -h 127.0.0.1 -P "$DB_PORT" "${common_args[@]}")"
        rc=$?

        if [ $rc -ne 0 ] && [ -z "$out" ]; then
          if [ -n "$DB_SOCKET" ]; then
            out="$(mysql_run_once "$q" "mysql socket ${DB_SOCKET}" --socket "$DB_SOCKET" "${common_args[@]}")"
          else
            out="$(mysql_run_once "$q" "mysql local socket fallback" "${common_args[@]}")"
          fi
        fi

        printf "%s" "$out"
      else
        mysql_run_once "$q" "mysql tcp ${DB_HOST}:${DB_PORT}" --protocol=TCP -h "$DB_HOST" -P "$DB_PORT" "${common_args[@]}"
      fi
      ;;

    postgresql)
      [ -n "$CLIENT_BIN" ] || return 1
      [ -n "$DB_USER" ] || return 1

      local pg_args=("-h" "$DB_HOST" "-p" "$DB_PORT" "-U" "$DB_USER" "-At" "-c" "$q")

      if [ -n "$DB_NAME" ]; then
        pg_args=("-h" "$DB_HOST" "-p" "$DB_PORT" "-U" "$DB_USER" "-d" "$DB_NAME" "-At" "-c" "$q")
      fi

      PGPASSWORD="$DB_PASS" "$CLIENT_BIN" "${pg_args[@]}" 2>>"$SQL_ERR_FILE"
      ;;

    altibase)
      [ -n "$CLIENT_BIN" ] || return 1
      [ -n "$DB_USER" ] || return 1

      {
        echo "$q"
        echo "quit;"
      } | "$CLIENT_BIN" -s "$DB_HOST" -port "$DB_PORT" -u "$DB_USER" -p "$DB_PASS" 2>>"$SQL_ERR_FILE"
      ;;

    tibero)
      [ -n "$CLIENT_BIN" ] || return 1
      [ -n "$DB_USER" ] || return 1

      {
        echo "$q"
        echo "exit"
      } | "$CLIENT_BIN" -s "${DB_USER}/${DB_PASS}${DB_SERVICE:+@${DB_SERVICE}}" 2>>"$SQL_ERR_FILE"
      ;;

    cubrid)
      [ -n "$CLIENT_BIN" ] || return 1
      [ -n "$DB_NAME" ] || return 1

      {
        echo "$q"
        echo ";exit"
      } | "$CLIENT_BIN" -u "$DB_USER" -p "$DB_PASS" "$DB_NAME" 2>>"$SQL_ERR_FILE"
      ;;
  esac
}

exec_sql_label() {
  local label="$1"
  local q="$2"
  local out=""
  local rc=0

  out="$(exec_sql "$q")"
  rc=$?

  if [ $rc -ne 0 ]; then
    {
      echo "----- ${label} rc=${rc} -----"
      echo "QUERY: $(printf "%s" "$q" | tr '\n' ' ' | cut -c1-300)"
      echo
    } >> "$SQL_ERR_FILE"
  fi

  printf "%s" "$out"
  return $rc
}

check_connection() {
  case "$DBMS" in
    oracle|tibero|altibase)
      exec_sql "select 1 from dual;" | grep -q "1"
      ;;
    mysql|postgresql|cubrid)
      exec_sql "select 1;" | grep -q "1"
      ;;
  esac
}

collect_root_db_process() {
  ps -eo pid=,user=,comm=,args= 2>/dev/null | while read -r pid user comm args; do
    [ "$user" = "root" ] || continue

    case "$DBMS" in
      oracle)
        case "$comm" in
          oracle|ora_*|tnslsnr)
            printf "%-8s %-8s %-20s %s\n" "$user" "$pid" "$comm" "$args"
            ;;
        esac
        ;;

      mysql)
        case "$comm" in
          mysqld|mariadbd)
            printf "%-8s %-8s %-20s %s\n" "$user" "$pid" "$comm" "$args"
            ;;
        esac
        ;;

      postgresql)
        case "$comm" in
          postgres|postmaster)
            printf "%-8s %-8s %-20s %s\n" "$user" "$pid" "$comm" "$args"
            ;;
        esac
        ;;

      altibase)
        case "$comm" in
          altibase|altibaseboot|altimon)
            printf "%-8s %-8s %-20s %s\n" "$user" "$pid" "$comm" "$args"
            ;;
        esac
        ;;

      tibero)
        case "$comm" in
          tbsvr|tblistener)
            printf "%-8s %-8s %-20s %s\n" "$user" "$pid" "$comm" "$args"
            ;;
        esac
        ;;

      cubrid)
        case "$comm" in
          cub_master|cub_broker|cub_server)
            printf "%-8s %-8s %-20s %s\n" "$user" "$pid" "$comm" "$args"
            ;;
        esac
        ;;
    esac
  done
}

collect_db_process() {
  ps -eo user=,pid=,comm=,args= 2>/dev/null | while read -r user pid comm args; do
    case "$comm" in
      oracle|ora_*|tnslsnr|mysqld|mariadbd|postgres|postmaster|altibase|altibaseboot|altimon|tbsvr|tblistener|cub_master|cub_broker|cub_server)
        printf "%-10s %-8s %-20s %s\n" "$user" "$pid" "$comm" "$args"
        ;;
    esac
  done | head -80
}

collect_file_perm() {
  local f=""
  for f in "$@"; do
    if [ -e "$f" ]; then
      ls -ld "$f" 2>/dev/null
    fi
  done
}

{
  echo "============================================================"
  echo "KISA DBMS UNIX Audit Framework v5.1"
  echo "============================================================"
  echo "[SERVER PROFILE]"
  printf "Hostname : %s\n" "$(hostname -f 2>/dev/null || hostname 2>/dev/null)"
  printf "IPv4     : %s\n" "$(hostname -I 2>/dev/null | xargs)"
  printf "OS       : %s\n" "$(awk -F= '/^PRETTY_NAME=/{gsub(/"/,"",$2);print $2}' /etc/os-release 2>/dev/null)"
  printf "Kernel   : %s\n" "$(uname -r 2>/dev/null)"
  printf "ExecUser : %s\n" "$(id -un 2>/dev/null)"
  printf "DBMS     : %s\n" "$DBMS"
  printf "DBHOST   : %s\n" "$DB_HOST"
  printf "DBPORT   : %s\n" "$DB_PORT"
  printf "DBUSER   : %s\n" "$DB_USER"
  printf "DBNAME   : %s\n" "$DB_NAME"
  printf "CLIENT   : %s\n" "$CLIENT_BIN"
  printf "Time     : %s\n" "$(date '+%Y-%m-%d %H:%M:%S')"
  echo
} > "$OUTFILE"

append_raw "client" "$CLIENT_BIN"
append_raw "execution note" "v5.1 syntax-safe release. D-07 uses command name matching to avoid awk/grep self-detection. MySQL blank DBUSER is allowed. CUBRID password is masked."
append_raw "processes" "$(collect_db_process)"

if [ -z "$CLIENT_BIN" ]; then
  write_item "CONN" "상" "DB Client 확인" "ERROR" "ClientNotFound" "DB client binary not found" "DBMS=$DBMS" "DB client 설치 또는 PATH 확인"
else
  if check_connection; then
    write_item "CONN" "상" "DB 접속 확인" "OK" "Connected" "DB 접속 성공" "client=$CLIENT_BIN host=$DB_HOST port=$DB_PORT user=$DB_USER" "현재 접속 정보 유지"
  else
    write_item "CONN" "상" "DB 접속 확인" "ERROR" "ConnectionFailed" "DB 접속 실패 또는 권한 부족" "client=$CLIENT_BIN host=$DB_HOST port=$DB_PORT user=$DB_USER" "접속 정보, 계정 권한, 방화벽, listener/socket 상태 확인"
  fi
fi

VERSION_INFO=""
RAW00=""
RAW01=""
RAW02=""
RAW03=""
RAW04=""
RAW05=""
RAW06=""
RAW08=""
RAW09=""
RAW10=""
RAW11=""
RAW12=""
RAW14=""
RAW15=""
RAW17=""
RAW18=""
RAW19=""
RAW20=""
RAW21=""
RAW22=""
RAW25=""
RAW26=""

case "$DBMS" in
  oracle)
    VERSION_INFO="$(exec_sql_label "oracle version" "select banner from v\$version;" | head -30)"
    RAW01="$(exec_sql_label "D-01 oracle users" "select username||','||account_status||','||lock_date||','||expiry_date||','||profile from dba_users order by username;" | head -300)"
    RAW02="$(exec_sql_label "D-02 oracle sample users" "select username||','||account_status from dba_users where username in ('SCOTT','HR','OE','SH','PM','IX','BI','ANONYMOUS') order by username;" | head -100)"
    RAW03="$(exec_sql_label "D-03 oracle profiles" "select profile||','||resource_name||','||limit from dba_profiles where resource_name in ('PASSWORD_LIFE_TIME','FAILED_LOGIN_ATTEMPTS','PASSWORD_REUSE_TIME','PASSWORD_REUSE_MAX','PASSWORD_VERIFY_FUNCTION','PASSWORD_LOCK_TIME','PASSWORD_GRACE_TIME') order by profile, resource_name;" | head -300)"
    RAW04="$(exec_sql_label "D-04 oracle high privileges" "select grantee||','||granted_role from dba_role_privs where granted_role in ('DBA','SELECT_CATALOG_ROLE','EXECUTE_CATALOG_ROLE') union all select grantee||','||privilege from dba_sys_privs where privilege in ('CREATE USER','ALTER USER','DROP USER','GRANT ANY ROLE','GRANT ANY PRIVILEGE','CREATE ANY PROCEDURE','EXECUTE ANY PROCEDURE','SELECT ANY DICTIONARY','ALTER SYSTEM') order by 1;" | head -300)"
    RAW05="$(exec_sql_label "D-05 oracle password reuse" "select profile||','||resource_name||','||limit from dba_profiles where resource_name in ('PASSWORD_REUSE_TIME','PASSWORD_REUSE_MAX') order by profile, resource_name;" | head -200)"
    RAW08="$(exec_sql_label "D-08 oracle password versions" "select username||','||password_versions from dba_users order by username;" | head -300)"
    RAW09="$(exec_sql_label "D-09 oracle failed login" "select profile||','||resource_name||','||limit from dba_profiles where resource_name in ('FAILED_LOGIN_ATTEMPTS','PASSWORD_LOCK_TIME') order by profile, resource_name;" | head -200)"
    RAW10="$(
      {
        exec_sql_label "D-10 oracle listener parameters" "select name||','||value from v\$parameter where name in ('local_listener','remote_listener');"
        if [ -n "${ORACLE_HOME:-}" ]; then
          grep -RiE 'TCP.VALIDNODE_CHECKING|TCP.INVITED_NODES|TCP.EXCLUDED_NODES|VALID_NODE_CHECKING_REGISTRATION|ADMIN_RESTRICTIONS|PASSWORDS_' "$ORACLE_HOME/network/admin" 2>/dev/null
        fi
      } | head -200
    )"
    RAW11="$(exec_sql_label "D-11 oracle system grants" "select grantee||','||privilege||','||owner||','||table_name from dba_tab_privs where (owner='SYS' or table_name like 'DBA_%') and grantee not in ('SYS','SYSTEM','DBA','PUBLIC') order by grantee, owner, table_name, privilege;" | head -300)"
    RAW12="$(
      if [ -n "${ORACLE_HOME:-}" ]; then
        grep -RiE 'ADMIN_RESTRICTIONS|VALID_NODE_CHECKING_REGISTRATION|PASSWORDS_|TCP.INVITED_NODES|TCP.EXCLUDED_NODES' "$ORACLE_HOME/network/admin" 2>/dev/null | head -100
      fi
    )"
    RAW14="$(
      if [ -n "${ORACLE_HOME:-}" ]; then
        collect_file_perm "$ORACLE_HOME/network/admin/listener.ora" "$ORACLE_HOME/network/admin/tnsnames.ora" "$ORACLE_HOME/network/admin/sqlnet.ora"
      fi
    )"
    RAW18="$(exec_sql_label "D-18 oracle public grants" "select grantee||','||owner||','||table_name||','||privilege from dba_tab_privs where grantee='PUBLIC' union all select grantee||',SYS_PRIV,'||privilege||',-' from dba_sys_privs where grantee='PUBLIC' order by 1;" | head -300)"
    RAW19="$(exec_sql_label "D-19 oracle parameters" "select name||','||value from v\$parameter where name in ('os_roles','remote_os_authent','remote_os_roles','resource_limit');")"
    RAW20="$(exec_sql_label "D-20 oracle object owners" "select owner||','||object_type||','||count(*) from dba_objects where owner not in ('SYS','SYSTEM','OUTLN','DBSNMP','SYSMAN','WMSYS','XDB','ORDSYS','MDSYS','CTXSYS') group by owner, object_type order by owner, object_type;" | head -300)"
    RAW21="$(exec_sql_label "D-21 oracle grant option" "select grantee||','||owner||','||table_name||','||privilege||','||grantable from dba_tab_privs where grantable='YES' order by grantee, owner, table_name, privilege;" | head -300)"
    RAW25="$(
      {
        echo "[v\$version]"
        printf "%s\n" "$VERSION_INFO"
        echo "[dba_registry_sqlpatch]"
        exec_sql_label "D-25 oracle sqlpatch" "select patch_id||','||action||','||status||','||description from dba_registry_sqlpatch order by action_time;"
      } | head -300
    )"
    RAW26="$(
      {
        exec_sql_label "D-26 oracle audit parameter" "select name||','||value from v\$parameter where name like 'audit%';"
        exec_sql_label "D-26 oracle unified audit" "select policy_name||','||enabled_option||','||entity_name from audit_unified_enabled_policies;"
      } | head -300
    )"
    ;;

  mysql)
    RAW00="$(exec_sql_label "mysql version" "select @@version, @@version_comment, current_user(), user(), @@hostname, @@port, @@socket;")"
    VERSION_INFO="${RAW00:-$(exec_sql_label "mysql version fallback" "select version();")}"

    MYSQL_FLAVOR="mysql"
    if printf "%s" "$VERSION_INFO" | grep -qi "mariadb"; then
      MYSQL_FLAVOR="mariadb"
    fi
    append_raw "mysql flavor" "$MYSQL_FLAVOR"

    if [ "$MYSQL_FLAVOR" = "mariadb" ]; then
      RAW01="$(exec_sql_label "D-01 mariadb users" "SELECT User,Host,COALESCE(JSON_UNQUOTE(JSON_EXTRACT(Priv,'$.plugin')),''),COALESCE(JSON_UNQUOTE(JSON_EXTRACT(Priv,'$.account_locked')),''),COALESCE(JSON_UNQUOTE(JSON_EXTRACT(Priv,'$.password_last_changed')),'') FROM mysql.global_priv WHERE User in ('root','mysql','mariadb.sys','mysql.sys','mysql.session') OR User='' ORDER BY User,Host;")"
      if [ -z "$RAW01" ]; then
        RAW01="$(exec_sql_label "D-01 mariadb mysql.user fallback" "select user,host,plugin from mysql.user where user in ('root','mysql','mariadb.sys','mysql.sys','mysql.session') or user='' order by user,host;")"
      fi
      RAW03="$(exec_sql_label "D-03 mariadb password policy" "show variables like 'strict_password_validation'; show variables like 'simple_password_check%'; show variables like 'cracklib_password_check%'; show variables like 'password_reuse_check%'; show plugins;")"
      RAW05="$(exec_sql_label "D-05 mariadb password reuse" "show variables like 'password_reuse_check%'; SELECT User,Host,COALESCE(JSON_UNQUOTE(JSON_EXTRACT(Priv,'$.password_last_changed')),''),COALESCE(JSON_UNQUOTE(JSON_EXTRACT(Priv,'$.password_lifetime')),'') FROM mysql.global_priv ORDER BY User,Host;")"
      RAW09="$(exec_sql_label "D-09 mariadb lock policy" "SELECT User,Host,COALESCE(JSON_UNQUOTE(JSON_EXTRACT(Priv,'$.account_locked')),''),COALESCE(JSON_UNQUOTE(JSON_EXTRACT(Priv,'$.password_lifetime')),'') FROM mysql.global_priv ORDER BY User,Host;")"
      RAW26="$(exec_sql_label "D-26 mariadb audit" "show variables like 'server_audit%'; show variables like 'audit%'; show variables like 'general_log'; show variables like 'log_error'; show variables like 'log_output'; show variables like 'slow_query_log'; show variables like 'log_bin'; show plugins;")"
    else
      RAW01="$(exec_sql_label "D-01 mysql users" "select user,host,plugin,account_locked,password_last_changed from mysql.user where user in ('root','mysql.sys','mysql.session') or user='' order by user,host;")"
      RAW03="$(exec_sql_label "D-03 mysql password policy" "show variables like 'validate_password%'; show variables like 'default_password_lifetime';")"
      RAW05="$(exec_sql_label "D-05 mysql password reuse" "show variables like 'password_history'; show variables like 'password_reuse_interval';")"
      RAW09="$(exec_sql_label "D-09 mysql lock policy" "show variables like 'failed_login_attempts'; show variables like 'password_lock_time';")"
      RAW26="$(exec_sql_label "D-26 mysql audit" "show variables like 'audit%'; show variables like 'general_log'; show variables like 'log_error'; show variables like 'log_output'; show variables like 'slow_query_log'; show variables like 'log_bin';")"
    fi

    RAW02="$(exec_sql_label "D-02 mysql anonymous users" "select user,host from mysql.user where user='' order by host;")"
    RAW04="$(exec_sql_label "D-04 mysql high privileges" "SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE in ('SUPER','SYSTEM_USER','SYSTEM_VARIABLES_ADMIN','SESSION_VARIABLES_ADMIN','CREATE USER','FILE','PROCESS','SHUTDOWN','RELOAD','REPLICATION SLAVE ADMIN','REPLICATION_APPLIER','BINLOG_ADMIN','BACKUP_ADMIN') ORDER BY GRANTEE, PRIVILEGE_TYPE;")"
    RAW08="$(exec_sql_label "D-08 mysql auth plugin" "select user,host,plugin from mysql.user order by user,host;")"
    RAW10="$(exec_sql_label "D-10 mysql network" "show variables like 'bind_address'; show variables like 'skip_networking'; show variables like 'port'; show variables like 'socket'; show variables like 'local_infile'; show variables like 'secure_file_priv'; show variables like 'require_secure_transport'; show variables like 'ssl_ca'; show variables like 'ssl_cert'; select user,host from mysql.user where host='%' or host like '0.0.0.0' or host like '::%' or (user='root' and host not in ('localhost','127.0.0.1','::1')) order by user,host;")"
    RAW11="$(exec_sql_label "D-11 mysql system schema privileges" "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE TABLE_SCHEMA in ('mysql','information_schema','performance_schema','sys') ORDER BY GRANTEE,TABLE_SCHEMA,TABLE_NAME,PRIVILEGE_TYPE;" | head -300)"
    RAW14="$(
      for f in /etc/my.cnf /etc/mysql/my.cnf /etc/mysql/mariadb.conf.d/*.cnf /etc/my.cnf.d/*.cnf "$HOME/.my.cnf"; do
        if [ -e "$f" ]; then
          ls -l "$f"
          grep -HnEi '^[[:space:]]*(bind-address|skip-networking|socket|port|plugin-load|server_audit|general_log|log_error|datadir|local_infile|secure_file_priv|ssl|require_secure_transport)' "$f" 2>/dev/null
        fi
      done
      collect_file_perm /var/lib/mysql /var/log/mysql /var/log/mariadb
    )"
    RAW20_SCHEMA="$(exec_sql_label "D-20 mysql schema summary" "SELECT table_schema, COUNT(*) AS table_count FROM information_schema.tables WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys') GROUP BY table_schema ORDER BY table_schema;")"
    RAW20_VIEWS="$(exec_sql_label "D-20 mysql views" "SELECT TABLE_SCHEMA, TABLE_NAME, DEFINER, SECURITY_TYPE FROM INFORMATION_SCHEMA.VIEWS WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys') ORDER BY TABLE_SCHEMA,TABLE_NAME;" | head -300)"
    RAW20_TRIGGERS="$(exec_sql_label "D-20 mysql triggers" "SELECT TRIGGER_SCHEMA, TRIGGER_NAME, DEFINER FROM INFORMATION_SCHEMA.TRIGGERS WHERE TRIGGER_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys') ORDER BY TRIGGER_SCHEMA,TRIGGER_NAME;" | head -300)"
    RAW20_ROUTINES="$(exec_sql_label "D-20 mysql routines" "SELECT ROUTINE_SCHEMA, ROUTINE_NAME, ROUTINE_TYPE, DEFINER, SECURITY_TYPE FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys') ORDER BY ROUTINE_SCHEMA,ROUTINE_NAME;" | head -300)"
    RAW20_EVENTS="$(exec_sql_label "D-20 mysql events" "SELECT EVENT_SCHEMA, EVENT_NAME, DEFINER FROM INFORMATION_SCHEMA.EVENTS WHERE EVENT_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys') ORDER BY EVENT_SCHEMA,EVENT_NAME;" | head -300)"
    RAW20_PRIVS="$(exec_sql_label "D-20 mysql privileges" "SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys') ORDER BY GRANTEE,TABLE_SCHEMA,PRIVILEGE_TYPE;" | head -300)"
    RAW20="[Schema Summary]
${RAW20_SCHEMA}

[Views Definer]
${RAW20_VIEWS}

[Triggers Definer]
${RAW20_TRIGGERS}

[Routines Definer]
${RAW20_ROUTINES}

[Events Definer]
${RAW20_EVENTS}

[Schema Privileges]
${RAW20_PRIVS}"
    RAW21="$(
      {
        echo "[Global grant option]"
        exec_sql_label "D-21 mysql global grant option" "SELECT GRANTEE, PRIVILEGE_TYPE, IS_GRANTABLE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE IS_GRANTABLE='YES' ORDER BY GRANTEE, PRIVILEGE_TYPE;"
        echo "[Schema grant option]"
        exec_sql_label "D-21 mysql schema grant option" "SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE, IS_GRANTABLE FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES WHERE IS_GRANTABLE='YES' ORDER BY GRANTEE,TABLE_SCHEMA,PRIVILEGE_TYPE;"
        echo "[Table grant option]"
        exec_sql_label "D-21 mysql table grant option" "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE, IS_GRANTABLE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE IS_GRANTABLE='YES' ORDER BY GRANTEE,TABLE_SCHEMA,TABLE_NAME,PRIVILEGE_TYPE;"
      } | head -500
    )"
    ;;

  postgresql)
    VERSION_INFO="$(exec_sql_label "postgresql version" "select version();")"
    RAW01="$(exec_sql_label "D-01 postgresql roles" "select rolname,rolsuper,rolcanlogin,rolvaliduntil from pg_roles order by rolname;")"
    RAW02="$(exec_sql_label "D-02 postgresql login roles" "select rolname,rolcanlogin,rolvaliduntil from pg_roles where rolcanlogin=true order by rolname;")"
    RAW03="$(exec_sql_label "D-03 postgresql password encryption" "show password_encryption;")"
    RAW04="$(exec_sql_label "D-04 postgresql high roles" "select rolname,rolsuper,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,rolcanlogin,rolconnlimit,rolvaliduntil from pg_roles where rolsuper=true or rolcreaterole=true or rolcreatedb=true or rolreplication=true or rolbypassrls=true order by rolname;")"
    RAW08="$RAW03"
    RAW09="$(exec_sql_label "D-09 postgresql role limits" "select rolname,rolconnlimit,rolvaliduntil from pg_roles order by rolname;")"
    RAW10="$(exec_sql_label "D-10 postgresql listen" "show listen_addresses; show port;")"
    RAW11="$(exec_sql_label "D-11 postgresql catalog grants" "select grantee,table_schema,table_name,privilege_type from information_schema.role_table_grants where table_schema in ('pg_catalog','information_schema') order by grantee,table_schema,table_name,privilege_type;" | head -300)"
    PG_HBA_FILE="$(exec_sql_label "postgresql hba_file" "show hba_file;" | head -1)"
    PG_CONFIG_FILE="$(exec_sql_label "postgresql config_file" "show config_file;" | head -1)"
    PG_IDENT_FILE="$(exec_sql_label "postgresql ident_file" "show ident_file;" | head -1)"
    RAW14="$(
      collect_file_perm "$PG_HBA_FILE" "$PG_CONFIG_FILE" "$PG_IDENT_FILE"
      if [ -f "$PG_HBA_FILE" ]; then
        echo "[pg_hba.conf active lines]"
        grep -E '^[[:space:]]*(host|local)' "$PG_HBA_FILE" 2>/dev/null | head -200
        echo "[pg_hba.conf risky lines]"
        grep -E '^[[:space:]]*(host|local).*([[:space:]]trust([[:space:]]|$)|0\.0\.0\.0/0|::/0)' "$PG_HBA_FILE" 2>/dev/null | head -100
      fi
    )"
    RAW21="$(exec_sql_label "D-21 postgresql grant option" "select grantee,table_schema,table_name,privilege_type,is_grantable from information_schema.role_table_grants where is_grantable='YES' order by grantee,table_schema,table_name,privilege_type;" | head -300)"
    RAW26="$(exec_sql_label "D-26 postgresql logging" "show log_destination; show logging_collector; show log_directory; show log_filename; show log_line_prefix; show log_statement; show log_connections; show log_disconnections; show log_min_duration_statement; show log_lock_waits; show log_checkpoints; select name, setting from pg_settings where name like 'pgaudit%';" | head -300)"
    ;;

  altibase)
    VERSION_INFO="$(exec_sql_label "altibase version" "select * from v\$version;" | head -30)"
    RAW01="$(exec_sql_label "D-01 altibase users" "SELECT USER_NAME, ACCOUNT_LOCK_DATE FROM SYSTEM_.SYS_USERS_;")"
    RAW02="$RAW01"
    RAW03="$(exec_sql_label "D-03 altibase password policy" "SELECT USER_NAME, FAILED_LOGIN_ATTEMPTS, PASSWORD_LOCK_TIME, PASSWORD_LIFE_TIME, PASSWORD_REUSE_TIME, PASSWORD_REUSE_MAX, PASSWORD_VERIFY_FUNCTION FROM SYSTEM_.SYS_USERS_;")"
    RAW04="$(exec_sql_label "D-04 altibase admin users" "SELECT USER_NAME, IS_ADMIN FROM SYSTEM_.SYS_USERS_;")"
    RAW05="$(exec_sql_label "D-05 altibase password reuse" "SELECT USER_NAME, PASSWORD_REUSE_TIME, PASSWORD_REUSE_MAX FROM SYSTEM_.SYS_USERS_;")"
    RAW09="$(exec_sql_label "D-09 altibase failed login" "SELECT USER_NAME, FAILED_LOGIN_ATTEMPTS, PASSWORD_LOCK_TIME FROM SYSTEM_.SYS_USERS_;")"
    RAW10="$(exec_sql_label "D-10 altibase network" "select name,value1 from v\$property where name like '%LISTEN%' or name like '%TCP%' or name like '%ACCESS%' or name like '%REMOTE%';" | head -100)"
    RAW26="$(exec_sql_label "D-26 altibase audit" "select name,value1 from v\$property where name like '%AUDIT%' or name like '%LOG%';" | head -100)"
    ;;

  tibero)
    VERSION_INFO="$(exec_sql_label "tibero version" "select * from v\$version;" | head -30)"
    RAW01="$(exec_sql_label "D-01 tibero users" "select username,account_status,lock_date,expiry_date,profile from dba_users order by username;" | head -300)"
    RAW02="$(exec_sql_label "D-02 tibero sample users" "select username,account_status from dba_users where username in ('SCOTT','HR','OE','SH','PM','IX','BI','ANONYMOUS') order by username;" | head -100)"
    RAW03="$(exec_sql_label "D-03 tibero profiles" "select profile,resource_name,limit from dba_profiles where resource_name in ('FAILED_LOGIN_ATTEMPTS','PASSWORD_LIFE_TIME','PASSWORD_REUSE_TIME','PASSWORD_REUSE_MAX','PASSWORD_VERIFY_FUNCTION','PASSWORD_LOCK_TIME') order by profile,resource_name;" | head -300)"
    RAW04="$(exec_sql_label "D-04 tibero high privileges" "select grantee,granted_role from dba_role_privs where granted_role in ('DBA','SELECT_CATALOG_ROLE','EXECUTE_CATALOG_ROLE') union all select grantee,privilege from dba_sys_privs where privilege in ('CREATE USER','ALTER USER','DROP USER','CREATE ANY PROCEDURE','EXECUTE ANY PROCEDURE','ALTER SYSTEM','SELECT ANY DICTIONARY') order by 1;" | head -300)"
    RAW05="$(exec_sql_label "D-05 tibero password reuse" "select profile,resource_name,limit from dba_profiles where resource_name in ('PASSWORD_REUSE_TIME','PASSWORD_REUSE_MAX') order by profile,resource_name;" | head -200)"
    RAW08="$(exec_sql_label "D-08 tibero encrypted tablespaces" "SELECT \"TS#\", \"ENCRYPTIONALG\", \"ENCRYPTEDTS\" FROM V\$ENCRYPTED_TABLESPACES;" | head -200)"
    RAW09="$(exec_sql_label "D-09 tibero failed login" "select profile,resource_name,limit from dba_profiles where resource_name in ('FAILED_LOGIN_ATTEMPTS','PASSWORD_LOCK_TIME') order by profile,resource_name;" | head -200)"
    RAW10="$(echo "$DB_SERVICE" | sed 's/^/SERVICE_HINT=/')"
    RAW11="$(exec_sql_label "D-11 tibero system grants" "select grantee,owner,table_name,privilege from dba_tab_privs where owner='SYS' order by grantee,owner,table_name,privilege;" | head -300)"
    RAW18="$(exec_sql_label "D-18 tibero public grants" "select grantee,owner,table_name,privilege from dba_tab_privs where grantee='PUBLIC' order by owner,table_name,privilege;" | head -300)"
    RAW20="$(exec_sql_label "D-20 tibero object owners" "select owner,object_type,count(*) from dba_objects where owner not in ('SYS','SYSTEM') group by owner,object_type order by owner,object_type;" | head -300)"
    RAW21="$(exec_sql_label "D-21 tibero grant option" "select grantee,owner,table_name,privilege,grantable from dba_tab_privs where grantable='YES' order by grantee,owner,table_name,privilege;" | head -300)"
    RAW26="$(exec_sql_label "D-26 tibero audit" "show parameter audit;" | head -200)"
    ;;

  cubrid)
    VERSION_INFO="$(csql --version 2>/dev/null || cubrid_rel 2>/dev/null)"
    RAW01="$(exec_sql_label "D-01 cubrid users masked" "SELECT name, CASE WHEN password IS NULL OR password = '' THEN 'EMPTY_OR_NULL' ELSE 'SET' END AS password_status FROM db_user;")"
    RAW02="$RAW01"
    RAW04="$RAW01"
    RAW10="$(grep -RiE 'access_ip_control|access_control|cubrid_port_id|max_clients|server|broker|acl' "${CUBRID:-/usr/local/cubrid}/conf" 2>/dev/null | head -200)"
    RAW14="$(
      collect_file_perm "${CUBRID:-/usr/local/cubrid}/conf" "${CUBRID:-/usr/local/cubrid}/conf/"*.conf
      grep -RiE 'SERVICE|BROKER_PORT|ACCESS_MODE|MAX_NUM_APPL_SERVER|SQL_LOG|SLOW_LOG|ERROR_LOG|ACCESS_MODE' "${CUBRID:-/usr/local/cubrid}/conf" 2>/dev/null | head -200
    )"
    RAW26="$(grep -RiE 'audit|SQL_LOG|SLOW_LOG|ERROR_LOG|ACCESS_LOG' "${CUBRID:-/usr/local/cubrid}/conf" 2>/dev/null | head -200)"
    ;;
esac

append_raw "version" "$VERSION_INFO"

D01_RESULT="WARN"
D01_VERDICT="ManualCheck"
D01_CURRENT="기본 계정 상태 점검 필요"

if [ "$DBMS" = "mysql" ] && [ -n "$RAW02" ]; then
  D01_RESULT="VULN"
  D01_VERDICT="Vulnerable"
  D01_CURRENT="anonymous 계정 발견"
fi

write_item "D-01" "상" "기본 계정 비밀번호/정책 변경" "$D01_RESULT" "$D01_VERDICT" "$D01_CURRENT" "${RAW01:-No data}" "기본 계정 잠금, 비밀번호 변경, anonymous/sample 계정 제거"
write_item "D-02" "상" "불필요 계정 제거/잠금" "WARN" "ManualCheck" "사용자 목록 및 샘플 계정 점검 필요" "${RAW02:-${RAW01:-No data}}" "불필요/데모/퇴직/anonymous 계정 제거 또는 잠금"
write_item "D-03" "상" "비밀번호 기간 및 복잡도 설정" "WARN" "ManualCheck" "패스워드 정책 확인 필요" "${RAW03:-No data}" "기관 정책에 맞게 복잡도, 만료, 잠금 정책 설정"
write_item "D-04" "상" "DBA 권한 최소화" "WARN" "ManualCheck" "관리자/고위험 권한 계정 점검 필요" "${RAW04:-No data}" "불필요 DBA/SUPER/CREATEROLE/ALTER SYSTEM 등 고위험 권한 회수"

case "$DBMS" in
  oracle|mysql|tibero|altibase)
    write_item "D-05" "중" "비밀번호 재사용 제약" "WARN" "ManualCheck" "재사용 제약 파라미터 확인 필요" "${RAW05:-${RAW03:-No data}}" "PASSWORD_REUSE, password_history 또는 동등 기능 설정"
    ;;
  *)
    write_item "D-05" "중" "비밀번호 재사용 제약" "N/A" "NotApplicable" "자동판정 미지원 또는 DBMS 기본 기능 제한" "$DBMS" "수동 확인"
    ;;
esac

write_item "D-06" "중" "DB 사용자 계정 개별 부여" "WARN" "ManualCheck" "공용 계정 사용 여부 인터뷰 필요" "${RAW06:-No collected result}" "개인별/응용프로그램별 계정 분리 및 공유계정 사용 제한"

ROOT_DB_PROC="$(collect_root_db_process)"

if [ -n "$ROOT_DB_PROC" ]; then
  write_item "D-07" "중" "root 권한으로 서비스 구동 제한" "VULN" "Vulnerable" "root 권한 DBMS 엔진/리스너 프로세스 발견" "$ROOT_DB_PROC" "DBMS 전용 OS 계정으로 서비스 구동"
else
  write_item "D-07" "중" "root 권한으로 서비스 구동 제한" "OK" "Good" "root 권한 DBMS 엔진/리스너 프로세스 미발견" "process scan by command name" "전용 계정 구동 상태 유지"
fi

D08_RESULT="WARN"
D08_VERDICT="ManualCheck"
D08_CURRENT="암호화/인증 알고리즘 설정 점검 필요"

if [ "$DBMS" = "oracle" ] && printf "%s" "$RAW08" | grep -q "10G"; then
  D08_RESULT="VULN"
  D08_VERDICT="Vulnerable"
  D08_CURRENT="Oracle 10G password verifier 사용 흔적 발견"
elif [ "$DBMS" = "postgresql" ] && printf "%s" "$RAW08" | grep -qi "scram-sha-256"; then
  D08_RESULT="OK"
  D08_VERDICT="Good"
  D08_CURRENT="password_encryption=scram-sha-256"
elif [ "$DBMS" = "postgresql" ] && printf "%s" "$RAW08" | grep -qi "md5"; then
  D08_RESULT="VULN"
  D08_VERDICT="Vulnerable"
  D08_CURRENT="password_encryption=md5"
fi

write_item "D-08" "상" "안전한 암호화 알고리즘 사용" "$D08_RESULT" "$D08_VERDICT" "$D08_CURRENT" "${RAW08:-No data}" "SHA-256/SCRAM 등 안전한 인증/암호화 방식 사용"
write_item "D-09" "중" "로그인 실패 잠금 정책" "WARN" "ManualCheck" "로그인 실패 잠금 정책 확인 필요" "${RAW09:-No data}" "FAILED_LOGIN_ATTEMPTS, lock time 또는 동등 기능 설정"

D10_RESULT="WARN"
D10_VERDICT="ManualCheck"
D10_CURRENT="원격접속 제한 정책 확인 필요"

if [ "$DBMS" = "postgresql" ] && printf "%s" "$RAW14" | grep -Eq '^[[:space:]]*(host|local).*[[:space:]]trust([[:space:]]|$)|0\.0\.0\.0/0|::/0'; then
  D10_RESULT="VULN"
  D10_VERDICT="Vulnerable"
  D10_CURRENT="pg_hba.conf에 trust 또는 전체 대역 허용 의심 설정 발견"
elif [ "$DBMS" = "mysql" ] && printf "%s" "$RAW10" | grep -Eq '0\.0\.0\.0|%'; then
  D10_RESULT="WARN"
  D10_VERDICT="ManualCheck"
  D10_CURRENT="전체 바인딩 또는 wildcard host 계정 가능성 확인 필요"
fi

D10_BASIS="${RAW10:-No data}
${RAW14:-}"

write_item "D-10" "상" "원격 접속 제한" "$D10_RESULT" "$D10_VERDICT" "$D10_CURRENT" "$D10_BASIS" "허용 IP, listener binding, pg_hba.conf, 계정 host 제한 점검"
write_item "D-11" "상" "비인가 사용자 시스템 테이블 접근 제한" "WARN" "ManualCheck" "시스템 테이블/카탈로그 권한 점검 필요" "${RAW11:-No data}" "비인가 사용자 시스템 테이블 접근 권한 회수"

case "$DBMS" in
  oracle|tibero)
    write_item "D-12" "상" "안전한 리스너 비밀번호 설정 및 사용" "WARN" "ManualCheck" "리스너 보호 설정 확인 필요" "${RAW12:-${RAW10:-No data}}" "listener admin restriction, invited node, 접근제어 설정 검토"
    ;;
  *)
    write_item "D-12" "상" "안전한 리스너 비밀번호 설정 및 사용" "N/A" "NotApplicable" "가이드상 주 대상 아님" "$DBMS" "해당사항 없음"
    ;;
esac

write_item "D-13" "중" "불필요한 ODBC/OLE-DB 제거" "N/A" "NotApplicable" "UNIX 계열 자동점검 제외" "$DBMS" "Windows 계열에서 별도 점검"
write_item "D-14" "중" "주요 파일 접근권한 적절성" "WARN" "ManualCheck" "설정/로그/접근제어 파일 권한 후보 수집" "${RAW14:-No data}" "주요 설정파일 600/640 등 최소권한 검토"

if [ "$DBMS" = "oracle" ]; then
  write_item "D-15" "하" "오라클 리스너 로그/trace 변경 제한" "WARN" "ManualCheck" "리스너 로그/trace 권한 점검 필요" "${RAW15:-${RAW14:-No data}}" "listener log/trace 파일 권한 및 소유자 점검"
else
  write_item "D-15" "하" "오라클 리스너 로그/trace 변경 제한" "N/A" "NotApplicable" "Oracle 전용 항목" "$DBMS" "해당사항 없음"
fi

write_item "D-16" "하" "Windows 인증 모드 사용" "N/A" "NotApplicable" "Windows MSSQL 전용" "$DBMS" "해당사항 없음"

if [ "$DBMS" = "oracle" ]; then
  write_item "D-17" "하" "Audit Table 접근 제한" "WARN" "ManualCheck" "감사 테이블 접근권한 점검 필요" "${RAW17:-${RAW26:-No data}}" "AUD$, FGA_LOG$ 등 감사 테이블 접근권한 제한"
else
  write_item "D-17" "하" "Audit Table 접근 제한" "N/A" "NotApplicable" "Oracle 중심 항목" "$DBMS" "수동 확인"
fi

case "$DBMS" in
  oracle|tibero)
    write_item "D-18" "상" "응용프로그램 또는 DBA Role의 Public 설정 조정" "WARN" "ManualCheck" "PUBLIC role/permission 점검 필요" "${RAW18:-No data}" "PUBLIC 권한 최소화 및 불필요 권한 회수"
    ;;
  *)
    write_item "D-18" "상" "응용프로그램 또는 DBA Role의 Public 설정 조정" "N/A" "NotApplicable" "DBMS 구조 차이" "$DBMS" "수동 확인"
    ;;
esac

if [ "$DBMS" = "oracle" ]; then
  if printf "%s" "${RAW19:-}" | grep -qiE 'os_roles.*,TRUE|remote_os_authent.*,TRUE|remote_os_roles.*,TRUE'; then
    write_item "D-19" "상" "OS_ROLES/REMOTE_OS_* FALSE 설정" "VULN" "Vulnerable" "TRUE 설정 발견" "${RAW19}" "FALSE로 변경"
  else
    write_item "D-19" "상" "OS_ROLES/REMOTE_OS_* FALSE 설정" "OK" "Good" "TRUE 설정 미발견" "${RAW19:-No data}" "FALSE 상태 유지"
  fi
else
  write_item "D-19" "상" "OS_ROLES/REMOTE_OS_* FALSE 설정" "N/A" "NotApplicable" "Oracle 전용" "$DBMS" "해당사항 없음"
fi

write_item "D-20" "하" "인가되지 않은 Object owner 제한" "WARN" "ManualCheck" "Object owner/DEFINER/비시스템 스키마 객체 점검 필요" "${RAW20:-No data}" "비인가 owner/DEFINER 및 과도한 객체권한 정리"
write_item "D-21" "중" "인가되지 않은 GRANT OPTION 제한" "WARN" "ManualCheck" "GRANT OPTION 또는 IS_GRANTABLE 점검 필요" "${RAW21:-No data}" "불필요 GRANT OPTION 회수"

if [ "$DBMS" = "oracle" ]; then
  if printf "%s" "${RAW19:-}" | grep -qi 'resource_limit,TRUE'; then
    write_item "D-22" "하" "자원 제한 기능 TRUE 설정" "OK" "Good" "RESOURCE_LIMIT=TRUE" "${RAW19}" "TRUE 유지"
  else
    write_item "D-22" "하" "자원 제한 기능 TRUE 설정" "WARN" "ManualCheck" "RESOURCE_LIMIT 미확인 또는 비활성 가능성" "${RAW19:-No data}" "RESOURCE_LIMIT=TRUE 설정 검토"
  fi
else
  write_item "D-22" "하" "자원 제한 기능 TRUE 설정" "N/A" "NotApplicable" "Oracle 중심 항목" "$DBMS" "수동 확인"
fi

write_item "D-23" "상" "xp_cmdshell 사용 제한" "N/A" "NotApplicable" "MSSQL 전용" "$DBMS" "해당사항 없음"
write_item "D-24" "상" "Registry Procedure 권한 제한" "N/A" "NotApplicable" "MSSQL 전용" "$DBMS" "해당사항 없음"
write_item "D-25" "상" "보안 패치 및 벤더 권고 적용" "WARN" "ManualCheck" "버전 및 패치 정보 수집" "${RAW25:-${VERSION_INFO:-No data}}" "벤더 최신 패치, 보안권고, CVE 영향도 비교"
write_item "D-26" "상" "감사 기록 정책 적합성" "WARN" "ManualCheck" "감사/로그 설정 점검 필요" "${RAW26:-No data}" "기관 감사 정책에 맞게 로그인, 권한변경, DDL/DCL, 오류 로그 설정"

append_raw "D-01 queried result" "${RAW01:-No collected result}"
append_raw "D-02 queried result" "${RAW02:-No collected result}"
append_raw "D-03 queried result" "${RAW03:-No collected result}"
append_raw "D-04 queried result" "${RAW04:-No collected result}"
append_raw "D-05 queried result" "${RAW05:-No collected result}"
append_raw "D-06 queried result" "${RAW06:-No collected result}"
append_raw "D-07 queried result" "$(collect_db_process)"
append_raw "D-08 queried result" "${RAW08:-No collected result}"
append_raw "D-09 queried result" "${RAW09:-No collected result}"
append_raw "D-10 queried result" "${RAW10:-No collected result}"
append_raw "D-11 queried result" "${RAW11:-No collected result}"
append_raw "D-12 queried result" "${RAW12:-No collected result}"
append_raw "D-13 queried result" "UNIX 계열 자동점검 제외"
append_raw "D-14 queried result" "${RAW14:-No collected result}"
append_raw "D-15 queried result" "${RAW15:-No collected result}"
append_raw "D-16 queried result" "MSSQL Windows 전용"
append_raw "D-17 queried result" "${RAW17:-No collected result}"
append_raw "D-18 queried result" "${RAW18:-No collected result}"
append_raw "D-19 queried result" "${RAW19:-No collected result}"
append_raw "D-20 queried result" "${RAW20:-No collected result}"
append_raw "D-21 queried result" "${RAW21:-No collected result}"
append_raw "D-22 queried result" "${RAW22:-No collected result}"
append_raw "D-23 queried result" "MSSQL 전용"
append_raw "D-24 queried result" "MSSQL 전용"
append_raw "D-25 queried result" "${RAW25:-${VERSION_INFO:-No collected result}}"
append_raw "D-26 queried result" "${RAW26:-No collected result}"

if [ -s "$SQL_ERR_FILE" ]; then
  append_raw "sql errors" "$(cat "$SQL_ERR_FILE" | mask_sensitive_text)"
else
  append_raw "sql errors" "No SQL stderr captured"
fi

rm -f "$SQL_ERR_FILE"

{
  echo "==================== SUMMARY ===================="
  printf "OK    : %s\n" "$OK_COUNT"
  printf "WARN  : %s\n" "$WARN_COUNT"
  printf "VULN  : %s\n" "$VULN_COUNT"
  printf "N/A   : %s\n" "$NA_COUNT"
  printf "ERROR : %s\n" "$ERROR_COUNT"
  echo "================================================="
  echo
  echo "==================== RAW DATA ===================="
  printf "%s" "$RAW_DATA"
} >> "$OUTFILE"

echo "$OUTFILE"
