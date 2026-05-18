#!/bin/bash
set +e
LANG=C

DBMS="${1:-}"
if [ -z "$DBMS" ]; then
  echo "Usage: $0 {oracle|mysql|postgresql|altibase|tibero|cubrid}"
  exit 1
fi

prompt_default() {
  local label="$1"
  local default="$2"
  local value
  read -r -p "$label [$default]: " value
  if [ -z "$value" ]; then
    echo "$default"
  else
    echo "$value"
  fi
}

prompt_hidden() {
  local label="$1"
  local value
  read -r -s -p "$label: " value
  echo
  echo "$value"
}

find_client() {
  case "$DBMS" in
    oracle) command -v sqlplus 2>/dev/null ;;
    mysql) command -v mysql 2>/dev/null ;;
    postgresql) command -v psql 2>/dev/null ;;
    altibase) command -v is 2>/dev/null ;;
    tibero) command -v tbsql 2>/dev/null ;;
    cubrid) command -v csql 2>/dev/null ;;
    *) echo "" ;;
  esac
}

DB_HOST="$(prompt_default 'DBHOST' 'localhost')"
case "$DBMS" in
  oracle) DB_PORT="$(prompt_default 'DBPORT' '1521')" ;;
  mysql) DB_PORT="$(prompt_default 'DBPORT' '3306')" ;;
  postgresql) DB_PORT="$(prompt_default 'DBPORT' '5432')" ;;
  altibase) DB_PORT="$(prompt_default 'DBPORT' '20300')" ;;
  tibero) DB_PORT="$(prompt_default 'DBPORT' '8629')" ;;
  cubrid) DB_PORT="$(prompt_default 'DBPORT' '33000')" ;;
  *) DB_PORT="" ;;
esac
DB_USER="$(prompt_default 'DBUSER' '')"
DB_PASS="$(prompt_hidden 'DBPASS')"
DB_NAME="$(prompt_default 'DBNAME' '')"
DB_SERVICE="$(prompt_default 'DBSERVICE/SID(if needed)' '')"

CLIENT_BIN="$(find_client)"
OUTFILE="kisa_${DBMS}_unix_$(hostname -s 2>/dev/null)_$(date '+%Y%m%d%H%M%S').txt"
SQL_ERR_FILE="/tmp/kisa_${DBMS}_sqlerr_$$.log"
: > "$SQL_ERR_FILE"

OK_COUNT=0
WARN_COUNT=0
VULN_COUNT=0
NA_COUNT=0
RAW_DATA=""

add_count() {
  case "$1" in
    OK) OK_COUNT=$((OK_COUNT+1));;
    WARN) WARN_COUNT=$((WARN_COUNT+1));;
    VULN) VULN_COUNT=$((VULN_COUNT+1));;
    N/A) NA_COUNT=$((NA_COUNT+1));;
  esac
}

append_raw() {
  local title="$1"; shift
  local value="$*"
  RAW_DATA="${RAW_DATA}### ${title}\n${value:-"(empty)"}\n\n"
}

write_item() {
  local code="$1" imp="$2" title="$3" result="$4" verdict="$5" current="$6" basis="$7" action="$8"
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
  local q="$1"; shift
  local label="$1"; shift
  local err tmpout rc
  err="$(mktemp /tmp/kisa_mysql_err.XXXXXX 2>/dev/null || echo /tmp/kisa_mysql_err.$$)"
  tmpout="$(mktemp /tmp/kisa_mysql_out.XXXXXX 2>/dev/null || echo /tmp/kisa_mysql_out.$$)"

  "$CLIENT_BIN" --batch --raw --skip-column-names --connect-timeout=5 "$@" -e "$q" >"$tmpout" 2>"$err"
  rc=$?

  if [ -s "$err" ]; then
    {
      echo "----- ${label} rc=${rc} -----"
      echo "QUERY: $(printf "%s" "$q" | tr '
' ' ' | cut -c1-220)"
      sed -n '1,20p' "$err"
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
      [ -n "$CLIENT_BIN" ] && [ -n "$DB_USER" ] && [ -n "$DB_PASS" ] && echo "$q" | "$CLIENT_BIN" -s "${DB_USER}/${DB_PASS}${DB_SERVICE:+@${DB_SERVICE}}" 2>>"$SQL_ERR_FILE"
      ;;
    mysql)
      [ -n "$CLIENT_BIN" ] && [ -n "$DB_USER" ] || return 1

      # Build credential options safely. Do NOT pass -p when DB_PASS is empty.
      # Passing bare -p can make mysql prompt/hang or fail in root/unix_socket environments.
      local common_args=()
      common_args+=("-u" "$DB_USER")
      if [ -n "$DB_PASS" ]; then
        common_args+=("-p${DB_PASS}")
      fi
      if [ -n "$DB_NAME" ]; then
        common_args+=("$DB_NAME")
      fi

      local out rc
      if [ "$DB_HOST" = "localhost" ] || [ "$DB_HOST" = "127.0.0.1" ]; then
        # First try explicit TCP because a port was supplied. mysql -h localhost may ignore -P and use socket.
        out="$(mysql_run_once "$q" "mysql tcp 127.0.0.1:${DB_PORT}" --protocol=TCP -h 127.0.0.1 -P "$DB_PORT" "${common_args[@]}")"
        rc=$?
        if [ $rc -ne 0 ] && [ -z "$out" ]; then
          # Fallback for MariaDB/MySQL root accounts using unix_socket authentication.
          out="$(mysql_run_once "$q" "mysql local socket fallback" "${common_args[@]}")"
        fi
        printf "%s" "$out"
      else
        mysql_run_once "$q" "mysql tcp ${DB_HOST}:${DB_PORT}" --protocol=TCP -h "$DB_HOST" -P "$DB_PORT" "${common_args[@]}"
      fi
      ;;
    postgresql)
      [ -n "$CLIENT_BIN" ] && [ -n "$DB_USER" ] && PGPASSWORD="$DB_PASS" "$CLIENT_BIN" -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" ${DB_NAME:+-d "$DB_NAME"} -At -c "$q" 2>>"$SQL_ERR_FILE"
      ;;
    altibase)
      [ -n "$CLIENT_BIN" ] && [ -n "$DB_USER" ] && echo "$q" | "$CLIENT_BIN" -s "$DB_HOST" -port "$DB_PORT" -u "$DB_USER" -p "$DB_PASS" 2>>"$SQL_ERR_FILE"
      ;;
    tibero)
      [ -n "$CLIENT_BIN" ] && [ -n "$DB_USER" ] && echo "$q" | "$CLIENT_BIN" -s "${DB_USER}/${DB_PASS}${DB_SERVICE:+@${DB_SERVICE}}" 2>>"$SQL_ERR_FILE"
      ;;
    cubrid)
      [ -n "$CLIENT_BIN" ] && [ -n "$DB_NAME" ] && echo "$q" | "$CLIENT_BIN" -u "$DB_USER" -p "$DB_PASS" "$DB_NAME" 2>>"$SQL_ERR_FILE"
      ;;
  esac
}

{
  echo "============================================================"
  echo "KISA DBMS UNIX Audit Framework"
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
append_raw "mysql execution note" "v3: TCP first for localhost/127.0.0.1, socket fallback, no -p when password is empty, stderr preserved in sql errors"
append_raw "processes" "$(ps -ef | egrep -i 'oracle|tnslsnr|mysqld|mariadbd|mysql.server|postgres|altibase|tbsvr|tblistener|cub_master' | grep -v grep | head -50)"

# Collect version and a few DBMS-specific raw outputs
VERSION_INFO=""
case "$DBMS" in
  oracle)
    VERSION_INFO="$(exec_sql "set pages 0 feedback off verify off heading off; select banner from v\$version;" | head -20)"
    RAW01="$(exec_sql "set pages 0 feedback off verify off heading off; select username||','||account_status from dba_users;" | head -100)"
    RAW03="$(exec_sql "set pages 0 feedback off verify off heading off; select profile||','||resource_name||','||limit from dba_profiles where resource_name in ('PASSWORD_LIFE_TIME','FAILED_LOGIN_ATTEMPTS','PASSWORD_REUSE_TIME','PASSWORD_REUSE_MAX','PASSWORD_VERIFY_FUNCTION');" | head -100)"
    RAW04="$(exec_sql "set pages 0 feedback off verify off heading off; select grantee||','||granted_role from dba_role_privs where granted_role='DBA';" | head -100)"
    RAW10="$(grep -Ri "PASSWORDS_" "$ORACLE_HOME/network/admin" 2>/dev/null | head -20)"
    RAW11="$(exec_sql "set pages 0 feedback off verify off heading off; select grantee||','||privilege||','||owner||','||table_name from dba_tab_privs where (owner='SYS' or table_name like 'DBA_%') and grantee not in ('SYS','SYSTEM','DBA','PUBLIC');" | head -100)"
    RAW19="$(exec_sql "set pages 0 feedback off verify off heading off; select name||','||value from v\$parameter where name in ('os_roles','remote_os_authent','remote_os_roles','resource_limit');")"
    RAW21="$(exec_sql "set pages 0 feedback off verify off heading off; select grantee||','||owner||','||table_name||','||grantable from dba_tab_privs where grantable='YES';" | head -100)"
    RAW26="$(exec_sql "set pages 0 feedback off verify off heading off; show parameter audit;")"
    ;;
  mysql)
    RAW00="$(exec_sql "select @@version, @@version_comment, current_user(), user(), @@hostname, @@port;")"
    VERSION_INFO="${RAW00:-$(exec_sql "select version();")}"
    RAW01="$(exec_sql "select user,host,plugin from mysql.user where user in ('root','mysql.sys','mysql.session');")"
    RAW03="$(exec_sql "show variables like 'validate_password%'; show variables like 'default_password_lifetime';")"
    RAW04="$(exec_sql "SELECT GRANTEE, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.USER_PRIVILEGES WHERE PRIVILEGE_TYPE in ('SUPER','SYSTEM_USER','CREATE USER');")"
    RAW05="$(exec_sql "show variables like 'password_history'; show variables like 'password_reuse_interval';")"
    RAW09="$(exec_sql "show variables like 'failed_login_attempts'; show variables like 'password_lock_time';")"
    RAW10="$(exec_sql "show variables like 'bind_address'; show variables like 'skip_networking'; show variables like 'port'; select user,host from mysql.user where host='%' or host like '0.0.0.0';")"
    RAW11="$(exec_sql "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE TABLE_SCHEMA in ('mysql','information_schema','performance_schema','sys');" | head -100)"
    RAW20_SCHEMA="$(exec_sql "SELECT table_schema, COUNT(*) AS table_count FROM information_schema.tables WHERE table_schema NOT IN ('mysql','information_schema','performance_schema','sys') GROUP BY table_schema ORDER BY table_schema;")"
    RAW20_VIEWS="$(exec_sql "SELECT TABLE_SCHEMA, TABLE_NAME, DEFINER FROM INFORMATION_SCHEMA.VIEWS WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys');" | head -200)"
    RAW20_TRIGGERS="$(exec_sql "SELECT TRIGGER_SCHEMA, TRIGGER_NAME, DEFINER FROM INFORMATION_SCHEMA.TRIGGERS WHERE TRIGGER_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys');" | head -200)"
    RAW20_ROUTINES="$(exec_sql "SELECT ROUTINE_SCHEMA, ROUTINE_NAME, ROUTINE_TYPE, DEFINER FROM INFORMATION_SCHEMA.ROUTINES WHERE ROUTINE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys');" | head -200)"
    RAW20_EVENTS="$(exec_sql "SELECT EVENT_SCHEMA, EVENT_NAME, DEFINER FROM INFORMATION_SCHEMA.EVENTS WHERE EVENT_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys');" | head -200)"
    RAW20_SCH_PRIVS="$(exec_sql "SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.SCHEMA_PRIVILEGES WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys');" | head -200)"
    RAW20_TBL_PRIVS="$(exec_sql "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, PRIVILEGE_TYPE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys');" | head -200)"
    RAW21="$(exec_sql "SELECT GRANTEE, TABLE_SCHEMA, TABLE_NAME, IS_GRANTABLE FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES WHERE IS_GRANTABLE='YES';" | head -100)"
    RAW26="$(exec_sql "show variables like 'audit%'; show variables like 'general_log'; show variables like 'log_error'; show variables like 'log_output';")"
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
${RAW20_SCH_PRIVS}

[Table Privileges]
${RAW20_TBL_PRIVS}" 
    ;;
  postgresql)
    VERSION_INFO="$(exec_sql "select version();")"
    RAW01="$(exec_sql "select rolname,rolsuper,rolcanlogin from pg_roles where rolname='postgres';")"
    RAW03="$(exec_sql "show password_encryption;")"
    RAW04="$(exec_sql "select rolname from pg_roles where rolsuper=true;")"
    RAW09="$(exec_sql "select rolname,rolconnlimit from pg_roles;")"
    RAW10="$(exec_sql "show listen_addresses;")"
    RAW11="$(exec_sql "select grantee,table_schema,table_name,privilege_type from information_schema.role_table_grants where table_schema in ('pg_catalog','information_schema');" | head -100)"
    RAW14="$(if [ -n "$PGDATA" ]; then grep -E '^[[:space:]]*host' "$PGDATA/pg_hba.conf" 2>/dev/null | head -50; fi)"
    RAW21="$(exec_sql "select grantee,table_schema,table_name,is_grantable from information_schema.role_table_grants where is_grantable='YES';" | head -100)"
    RAW26="$(exec_sql "show logging_collector; show log_statement; show log_connections; show log_disconnections;")"
    ;;
  altibase)
    VERSION_INFO="$(exec_sql "select * from v\$version;" | head -20)"
    RAW01="$(exec_sql "SELECT USER_NAME, ACCOUNT_LOCK_DATE FROM SYSTEM_.SYS_USERS_;")"
    RAW03="$(exec_sql "SELECT USER_NAME, FAILED_LOGIN_ATTEMPTS, PASSWORD_LOCK_TIME, PASSWORD_LIFE_TIME, PASSWORD_REUSE_TIME, PASSWORD_REUSE_MAX, PASSWORD_VERIFY_FUNCTION FROM SYSTEM_.SYS_USERS_;")"
    RAW04="$(exec_sql "SELECT USER_NAME, IS_ADMIN FROM SYSTEM_.SYS_USERS_;")"
    RAW10="$(exec_sql "select name,value1 from v\$property where name like '%LISTEN%';" | head -50)"
    RAW26="$(exec_sql "select name,value1 from v\$property where name like '%AUDIT%';")"
    ;;
  tibero)
    VERSION_INFO="$(exec_sql "select * from v\$version;" | head -20)"
    RAW01="$(exec_sql "select username,account_status,profile from dba_users;")"
    RAW03="$(exec_sql "select profile,resource_name,limit from dba_profiles where resource_name in ('FAILED_LOGIN_ATTEMPTS','PASSWORD_LIFE_TIME','PASSWORD_REUSE_TIME','PASSWORD_REUSE_MAX','PASSWORD_VERIFY_FUNCTION');")"
    RAW04="$(exec_sql "select grantee,granted_role from dba_role_privs where granted_role='DBA';")"
    RAW08="$(exec_sql "SELECT \"TS#\", \"ENCRYPTIONALG\", \"ENCRYPTEDTS\" FROM V\$ENCRYPTED_TABLESPACES;")"
    RAW10="$(echo "$DB_SERVICE" | sed 's/^/SERVICE_HINT=/')"
    RAW11="$(exec_sql "select grantee,owner,table_name,privilege from dba_tab_privs where owner='SYS';" | head -100)"
    RAW26="$(exec_sql "show parameter audit;")"
    ;;
  cubrid)
    VERSION_INFO="$(csql --version 2>/dev/null || cubrid_rel 2>/dev/null)"
    RAW01="$(exec_sql "SELECT name, password FROM db_user;")"
    RAW02="$(exec_sql "SELECT name, password FROM db_user;")"
    RAW10="$(grep -RiE 'access_ip_control|access_control' "${CUBRID:-/usr/local/cubrid}/conf" 2>/dev/null | head -20)"
    RAW26="$(grep -Ri audit "${CUBRID:-/usr/local/cubrid}/conf" 2>/dev/null | head -20)"
    ;;
esac

append_raw "version" "$VERSION_INFO"

# Report conservatively for D-01 ~ D-26
write_item "D-01" "상" "기본 계정 비밀번호/정책 변경" "WARN" "ManualCheck" "기본 계정 상태 점검 필요" "${RAW01:-No data}" "기본 계정 잠금/패스워드 변경 확인"
write_item "D-02" "상" "불필요 계정 제거/잠금" "WARN" "ManualCheck" "사용자 목록 점검 필요" "${RAW02:-${RAW01:-No data}}" "불필요/데모/퇴직 계정 제거"
write_item "D-03" "상" "비밀번호 기간 및 복잡도 설정" "WARN" "ManualCheck" "패스워드 정책 확인" "${RAW03:-No data}" "기관 정책에 맞게 프로파일/정책 설정"
write_item "D-04" "상" "DBA 권한 최소화" "WARN" "ManualCheck" "관리자 권한 계정 점검 필요" "${RAW04:-No data}" "불필요 DBA/SUPER 권한 회수"

case "$DBMS" in
  oracle|mysql|tibero)
    write_item "D-05" "중" "비밀번호 재사용 제약" "WARN" "ManualCheck" "재사용 제약 파라미터 확인" "${RAW05:-${RAW03:-No data}}" "PASSWORD_REUSE 또는 password_history 설정"
    ;;
  *)
    write_item "D-05" "중" "비밀번호 재사용 제약" "N/A" "NotApplicable" "자동판정 미지원" "$DBMS" "수동 확인"
    ;;
esac

write_item "D-06" "중" "DB 사용자 계정 개별 부여" "WARN" "ManualCheck" "공용 계정 사용 여부 인터뷰 필요" "" "개인별/응용프로그램별 계정 분리"

if printf "%s\n" "$(ps -ef | egrep -i 'oracle|mysqld|mariadbd|mysql.server|postgres|altibase|tbsvr|cub_master' | grep -v grep)" | grep -q ' root '; then
  write_item "D-07" "중" "root 권한으로 서비스 구동 제한" "VULN" "Vulnerable" "DBMS 프로세스가 root로 구동" "process scan" "전용 계정으로 서비스 구동"
else
  write_item "D-07" "중" "root 권한으로 서비스 구동 제한" "OK" "Good" "root 구동 흔적 없음 또는 미확인" "process scan" "전용 계정 유지"
fi

case "$DBMS" in
  mysql|postgresql|tibero)
    write_item "D-08" "상" "안전한 암호화 알고리즘 사용" "WARN" "ManualCheck" "알고리즘 설정 점검" "${RAW08:-${RAW03:-No data}}" "SHA-256 이상 사용 확인"
    ;;
  oracle|altibase|cubrid)
    write_item "D-08" "상" "안전한 암호화 알고리즘 사용" "WARN" "ManualCheck" "자동판정 제한적" "${RAW08:-No data}" "패스워드/암호화 정책 수동 검증"
    ;;
esac

write_item "D-09" "중" "로그인 실패 잠금 정책" "WARN" "ManualCheck" "잠금 정책 확인" "${RAW09:-No data}" "FAILED_LOGIN_ATTEMPTS 또는 동등 기능 설정"
write_item "D-10" "상" "원격 접속 제한" "WARN" "ManualCheck" "원격접속 제한 정책 확인" "${RAW10:-No data}" "허용 IP/리스너 바인딩/pg_hba 등 점검"
write_item "D-11" "상" "비인가 사용자 시스템 테이블 접근 제한" "WARN" "ManualCheck" "시스템 테이블 권한 점검" "${RAW11:-No data}" "비인가 권한 회수"

case "$DBMS" in
  oracle|tibero)
    write_item "D-12" "상" "안전한 리스너 비밀번호 설정 및 사용" "WARN" "ManualCheck" "리스너 보호 설정 확인" "${RAW12:-${RAW10:-No data}}" "리스너 비밀번호/초대IP 설정 검토"
    ;;
  *)
    write_item "D-12" "상" "안전한 리스너 비밀번호 설정 및 사용" "N/A" "NotApplicable" "가이드상 주 대상 아님" "$DBMS" "해당사항 없음"
    ;;
esac

write_item "D-13" "중" "불필요한 ODBC/OLE-DB 제거" "N/A" "NotApplicable" "UNIX 계열 자동점검 제외" "$DBMS" "Windows 계열에서 별도 점검"

if [ -n "${RAW14:-}" ]; then
  append_raw "config/file candidates" "${RAW14}"
  write_item "D-14" "중" "주요 파일 접근권한 적절성" "WARN" "ManualCheck" "설정/로그 파일 후보 수집" "${RAW14}" "권한 600/640 등 최소권한 검토"
else
  write_item "D-14" "중" "주요 파일 접근권한 적절성" "WARN" "ManualCheck" "설정 파일 후보 미수집" "$DBMS" "주요 파일 수동 확인"
fi

if [ "$DBMS" = "oracle" ]; then
  write_item "D-15" "하" "오라클 리스너 로그/trace 변경 제한" "WARN" "ManualCheck" "리스너 로그 권한 점검 필요" "${RAW15:-No data}" "listener log/trace 파일 권한 점검"
else
  write_item "D-15" "하" "오라클 리스너 로그/trace 변경 제한" "N/A" "NotApplicable" "Oracle 전용 항목" "$DBMS" "해당사항 없음"
fi

write_item "D-16" "하" "Windows 인증 모드 사용" "N/A" "NotApplicable" "Windows MSSQL 전용" "$DBMS" "해당사항 없음"

if [ "$DBMS" = "oracle" ]; then
  write_item "D-17" "하" "Audit Table 접근 제한" "WARN" "ManualCheck" "감사 테이블 접근권한 점검 필요" "${RAW26:-No data}" "AUD$ 접근 권한 제한"
else
  write_item "D-17" "하" "Audit Table 접근 제한" "N/A" "NotApplicable" "Oracle 중심 항목" "$DBMS" "수동 확인"
fi

case "$DBMS" in
  oracle)
    write_item "D-18" "상" "응용프로그램 또는 DBA Role의 Public 설정 조정" "WARN" "ManualCheck" "PUBLIC role/permission 점검" "${RAW18:-No data}" "PUBLIC 권한 최소화"
    ;;
  *)
    write_item "D-18" "상" "응용프로그램 또는 DBA Role의 Public 설정 조정" "N/A" "NotApplicable" "DBMS 구조 차이" "$DBMS" "수동 확인"
    ;;
esac

if [ "$DBMS" = "oracle" ]; then
  if printf "%s" "${RAW19:-}" | grep -qiE 'os_roles.*,TRUE|remote_os_authent.*,TRUE|remote_os_roles.*,TRUE'; then
    write_item "D-19" "상" "OS_ROLES/REMOTE_OS_* FALSE 설정" "VULN" "Vulnerable" "TRUE 설정 발견" "${RAW19}" "FALSE로 변경"
  else
    write_item "D-19" "상" "OS_ROLES/REMOTE_OS_* FALSE 설정" "OK" "Good" "TRUE 설정 미발견" "${RAW19:-No data}" "FALSE 유지"
  fi
else
  write_item "D-19" "상" "OS_ROLES/REMOTE_OS_* FALSE 설정" "N/A" "NotApplicable" "Oracle 전용" "$DBMS" "해당사항 없음"
fi

write_item "D-20" "하" "인가되지 않은 Object owner 제한" "WARN" "ManualCheck" "Object owner/DEFINER/비시스템 스키마 객체 점검 필요" "${RAW20:-No data}" "비인가 owner/DEFINER 및 과도한 객체권한 정리"
write_item "D-21" "중" "인가되지 않은 GRANT OPTION 제한" "WARN" "ManualCheck" "GRANT OPTION 점검" "${RAW21:-No data}" "불필요 GRANT OPTION 회수"

if [ "$DBMS" = "oracle" ]; then
  if printf "%s" "${RAW19:-}" | grep -qi 'resource_limit,TRUE'; then
    write_item "D-22" "하" "자원 제한 기능 TRUE 설정" "OK" "Good" "RESOURCE_LIMIT=TRUE" "${RAW19}" "TRUE 유지"
  else
    write_item "D-22" "하" "자원 제한 기능 TRUE 설정" "WARN" "ManualCheck" "RESOURCE_LIMIT 미확인/비활성" "${RAW19:-No data}" "TRUE 설정 검토"
  fi
else
  write_item "D-22" "하" "자원 제한 기능 TRUE 설정" "N/A" "NotApplicable" "Oracle 중심 항목" "$DBMS" "수동 확인"
fi

write_item "D-23" "상" "xp_cmdshell 사용 제한" "N/A" "NotApplicable" "MSSQL 전용" "$DBMS" "해당사항 없음"
write_item "D-24" "상" "Registry Procedure 권한 제한" "N/A" "NotApplicable" "MSSQL 전용" "$DBMS" "해당사항 없음"
write_item "D-25" "상" "보안 패치 및 벤더 권고 적용" "WARN" "ManualCheck" "버전 정보 수집" "${VERSION_INFO:-No data}" "벤더 최신 패치/권고 비교"
write_item "D-26" "상" "감사 기록 정책 적합성" "WARN" "ManualCheck" "감사/로그 설정 점검" "${RAW26:-No data}" "기관 감사 정책에 맞게 설정"

# Per-item queried result raw-data
append_raw "D-01 queried result" "${RAW01:-No collected result}"
append_raw "D-02 queried result" "${RAW02:-No collected result}"
append_raw "D-03 queried result" "${RAW03:-No collected result}"
append_raw "D-04 queried result" "${RAW04:-No collected result}"
append_raw "D-05 queried result" "${RAW05:-No collected result}"
append_raw "D-06 queried result" "${RAW06:-No collected result}"
append_raw "D-07 queried result" "$(ps -ef | egrep -i 'oracle|mysqld|mariadbd|mysql.server|postgres|altibase|tbsvr|cub_master' | grep -v grep | head -50)"
append_raw "D-08 queried result" "${RAW08:-No collected result}"
append_raw "D-09 queried result" "${RAW09:-No collected result}"
append_raw "D-10 queried result" "${RAW10:-No collected result}"
append_raw "D-11 queried result" "${RAW11:-No collected result}"
append_raw "D-12 queried result" "${RAW12:-No collected result}"
append_raw "D-13 queried result" "${RAW13:-No collected result}"
append_raw "D-14 queried result" "${RAW14:-No collected result}"
append_raw "D-15 queried result" "${RAW15:-No collected result}"
append_raw "D-16 queried result" "${RAW16:-No collected result}"
append_raw "D-17 queried result" "${RAW17:-No collected result}"
append_raw "D-18 queried result" "${RAW18:-No collected result}"
append_raw "D-19 queried result" "${RAW19:-No collected result}"
append_raw "D-20 queried result" "${RAW20:-No collected result}"
append_raw "D-21 queried result" "${RAW21:-No collected result}"
append_raw "D-22 queried result" "${RAW22:-No collected result}"
append_raw "D-23 queried result" "${RAW23:-No collected result}"
append_raw "D-24 queried result" "${RAW24:-No collected result}"
append_raw "D-25 queried result" "${VERSION_INFO:-No collected result}"
append_raw "D-26 queried result" "${RAW26:-No collected result}"
if [ -s "$SQL_ERR_FILE" ]; then
  append_raw "sql errors" "$(cat "$SQL_ERR_FILE")"
else
  append_raw "sql errors" "No SQL stderr captured"
fi
rm -f "$SQL_ERR_FILE"

{
  echo "==================== SUMMARY ===================="
  printf "OK   : %s\n" "$OK_COUNT"
  printf "WARN : %s\n" "$WARN_COUNT"
  printf "VULN : %s\n" "$VULN_COUNT"
  printf "N/A  : %s\n" "$NA_COUNT"
  echo "================================================="
  echo
  echo "==================== RAW DATA ===================="
  printf "%b" "$RAW_DATA"
} >> "$OUTFILE"

echo "$OUTFILE"
