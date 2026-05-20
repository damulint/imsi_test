#!/bin/bash
# MariaDB/MySQL Linux Security Check Script
# - Linux LF line ending 기준
# - MySQL/MariaDB client 자동 탐색
# - 주요 문법 오류 수정
# - 결과 파일: <hostname>_mysql.txt

###############################################################################
# 전역변수 설정
###############################################################################

HOST="localhost"
PORT="3306"
DB_UID="root"
UPW=""
CLIENT="mysql"
DEBUGMODE=0

FILEHD="$(hostname -s)_mysql"
RESULT="${FILEHD}.txt"
RAWLOG="${FILEHD}_RAW.txt"

rm -f "$RESULT" "$RAWLOG"

###############################################################################
# 공통 함수
###############################################################################

log() {
    echo "$*" >> "$RESULT"
}

run_mysql() {
    "$CLIENT" -h "$HOST" -P "$PORT" -u "$DB_UID" -p"$UPW" "$@"
}

run_mysql_no_pw_echo() {
    "$CLIENT" -h "$HOST" -P "$PORT" -u "$DB_UID" -p"$UPW" --skip-column-names -B -e "$1"
}

section_header() {
    log "■ $1"
    log "■ 기준 : $2"
    log "■ 현황"
}

###############################################################################
# MySQL Client 자동 탐색
###############################################################################

FOUND_CLIENTS=$(find /usr /bin /sbin /usr/local /opt -type f -executable -iname mysql 2>/dev/null)

for C in $FOUND_CLIENTS; do
    if "$C" --help 2>/dev/null | grep -qi "mysql"; then
        CLIENT="$C"
        break
    fi
done

###############################################################################
# MySQL 연결 값 입력
###############################################################################

echo "#####################################################################################################################"
echo "# 진단 진행을 위한 Connection 정보를 입력받습니다."
echo "#####################################################################################################################"

if [ -x "$CLIENT" ] || command -v "$CLIENT" >/dev/null 2>&1; then
    client="$CLIENT"
else
    echo -n "MySQL Client Path (0/4 - default:mysql) : "
    read -r client
fi

echo -n "MySQL Host (1/4 - default:$HOST) : "
read -r host

echo -n "MySQL Port (2/4 - default:$PORT) : "
read -r port

echo -n "MySQL Admin ID (3/4 - default:$DB_UID) : "
read -r id

echo -n "MySQL Admin Password (4/4) : "
stty -echo
read -r pw
stty echo
echo ""

###############################################################################
# 입력값 검증
###############################################################################

if [ -n "$client" ]; then
    CLIENT="$client"
fi

if [ -n "$host" ]; then
    HOST="$host"
fi

if [ -n "$port" ]; then
    if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
        PORT="$port"
    else
        echo "Invalid port: $port"
        exit 1
    fi
fi

if [ -n "$id" ]; then
    DB_UID="$id"
fi

if [ -n "$pw" ]; then
    UPW="$pw"
else
    echo "Connection Fail_1: password is empty"
    exit 1
fi

###############################################################################
# Connection 체크
###############################################################################

DBVER=$(run_mysql --skip-column-names -B -e "SELECT SUBSTRING_INDEX(VERSION(), '-', 1);" 2>/dev/null)

if [ $? -ne 0 ] || [ -z "$DBVER" ]; then
    echo "Connection Fail_2"
    exit 1
fi

if ! echo "$DBVER" | grep -Eq '^[0-9]+\.[0-9]+(\.[0-9]+)?'; then
    echo "Connection Fail_3"
    exit 1
fi

IS55MORE=$(run_mysql_no_pw_echo "SELECT VERSION() >= '5.5.0';" 2>/dev/null)
IS57MORE=$(run_mysql_no_pw_echo "SELECT VERSION() >= '5.7.0';" 2>/dev/null)

IS55MORE=${IS55MORE:-0}
IS57MORE=${IS57MORE:-0}

###############################################################################
# 최신 버전 정보
# 필요 시 현행 정책에 맞게 갱신
###############################################################################

LAT_55="5.5.62"
LAT_56="5.6.51"
LAT_57="5.7.44"
LAT_80="8.0.36"

###############################################################################
# SQL_MODE 설정
# MySQL 8.0에서는 NO_AUTO_CREATE_USER가 제거되어 오류가 발생할 수 있으므로
# 실패해도 스크립트는 계속 진행
###############################################################################

run_mysql -B -e "SET SESSION sql_mode='STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';" >/dev/null 2>&1

###############################################################################
# D-01
###############################################################################

section_header "D-01. 기본 계정의 패스워드, 정책 등을 변경하여 사용" \
"기본 계정의 패스워드를 변경하여 사용하는 경우 양호"

if [ "$IS55MORE" -eq 1 ]; then
    if [ "$IS57MORE" -eq 1 ]; then
        run_mysql --skip-column-names -B -e "
SELECT CONCAT('D-01', ',', IF(COUNT(T.user) > 0, 'X', 'O'), ',,') AS ''
FROM (
    SELECT user, plugin, authentication_string
    FROM mysql.user
    WHERE user <> ''
    GROUP BY user, plugin, authentication_string
) T
WHERE plugin = 'mysql_native_password'
  AND (
      authentication_string = PASSWORD('')
      OR authentication_string = PASSWORD(T.user)
  );
" >> "$RESULT" 2>> "$RAWLOG"

        run_mysql --skip-column-names -B -e "
SELECT CASE
WHEN (
    SELECT COUNT(user)
    FROM (
        SELECT user, plugin, authentication_string
        FROM mysql.user
        WHERE user <> ''
        GROUP BY user, plugin, authentication_string
    ) T
    WHERE plugin = 'mysql_native_password'
      AND (
          authentication_string = PASSWORD('')
          OR authentication_string = PASSWORD(T.user)
      )
) > 0
THEN '패스워드가 취약한(미설정 또는 아이디와 동일) 계정이 존재함'
ELSE '패스워드가 취약한(미설정 또는 아이디와 동일) 계정이 발견되지 않음'
END AS '';
" >> "$RESULT" 2>> "$RAWLOG"

        run_mysql -B -e "
SELECT DISTINCT user, plugin, authentication_string,
       authentication_string = PASSWORD(user) AS passwordSameId
FROM mysql.user
WHERE user <> ''
GROUP BY user, plugin, authentication_string;
" >> "$RESULT" 2>> "$RAWLOG"

    else
        run_mysql --skip-column-names -B -e "
SELECT CONCAT('D-01', ',', IF(COUNT(T.user) > 0, 'X', 'O'), ',,') AS ''
FROM (
    SELECT user, password, plugin, authentication_string
    FROM mysql.user
    WHERE user <> ''
    GROUP BY user, password, plugin, authentication_string
) T
WHERE (plugin IS NULL AND password = PASSWORD(''))
   OR (
       plugin = 'mysql_native_password'
       AND (
           authentication_string = PASSWORD('')
           OR authentication_string = PASSWORD(T.user)
       )
   );
" >> "$RESULT" 2>> "$RAWLOG"

        run_mysql --skip-column-names -B -e "
SELECT CASE
WHEN (
    SELECT COUNT(user)
    FROM (
        SELECT user, password, plugin, authentication_string
        FROM mysql.user
        WHERE user <> ''
        GROUP BY user, password, plugin, authentication_string
    ) T
    WHERE (plugin IS NULL AND password = PASSWORD(''))
       OR (
           plugin = 'mysql_native_password'
           AND (
               authentication_string = PASSWORD('')
               OR authentication_string = PASSWORD(T.user)
           )
       )
) > 0
THEN '패스워드가 취약한(미설정 또는 아이디와 동일) 계정이 존재함'
ELSE '패스워드가 취약한(미설정 또는 아이디와 동일) 계정이 발견되지 않음'
END AS '';
" >> "$RESULT" 2>> "$RAWLOG"

        run_mysql -B -e "
SELECT DISTINCT user, password, plugin, authentication_string,
       authentication_string = PASSWORD(user) AS passwordSameId
FROM mysql.user
WHERE user <> ''
GROUP BY user, password, plugin, authentication_string;
" >> "$RESULT" 2>> "$RAWLOG"
    fi
else
    run_mysql --skip-column-names -B -e "
SELECT CONCAT('D-01', ',', IF(COUNT(T.user) > 0, 'X', 'O'), ',,') AS ''
FROM (
    SELECT user, password
    FROM mysql.user
    WHERE user <> ''
    GROUP BY user, password
) T
WHERE T.password = PASSWORD('')
   OR T.password = PASSWORD(user);
" >> "$RESULT" 2>> "$RAWLOG"

    run_mysql --skip-column-names -B -e "
SELECT CASE
WHEN (
    SELECT COUNT(T.user)
    FROM (
        SELECT user, password
        FROM mysql.user
        WHERE user <> ''
        GROUP BY user, password
    ) T
    WHERE T.password = PASSWORD('')
       OR T.password = PASSWORD(user)
) > 0
THEN '패스워드가 취약한(미설정 또는 아이디와 동일) 계정이 존재함'
ELSE '패스워드가 취약한(미설정 또는 아이디와 동일) 계정이 발견되지 않음'
END AS '';
" >> "$RESULT" 2>> "$RAWLOG"

    run_mysql -B -e "
SELECT DISTINCT user, password
FROM mysql.user
WHERE user <> ''
GROUP BY user, password;
" >> "$RESULT" 2>> "$RAWLOG"
fi

log ""

###############################################################################
# D-02
###############################################################################

section_header "D-02. scott 등 Demonstration 및 불필요 계정을 제거하거나 잠금 설정 후 사용" \
"계정 정보를 확인하여 불필요한 계정이 없는 경우 양호"

log "D-02,C,,"
log "[수동진단]사용하지 않는 계정에 대한 인터뷰 필요"
log ""
log "[설정]"

run_mysql -B -e "
SELECT u.user, d.db
FROM mysql.user u
LEFT JOIN mysql.db d ON u.user = d.user
WHERE u.user <> ''
GROUP BY u.user, d.db;
" >> "$RESULT" 2>> "$RAWLOG"

log ""

###############################################################################
# D-03
###############################################################################

section_header "D-03. 패스워드의 사용기간 및 복잡도 기관 정책에 맞도록 설정" \
"패스워드를 주기적으로 변경하고, 패스워드 정책이 적용되어 있는 경우 양호"

log "D-03,C,,"
log "[수동진단]인터뷰 필요"
log ""

###############################################################################
# D-04
###############################################################################

section_header "D-04. 데이터베이스 관리자 권한을 꼭 필요한 계정 및 그룹에 허용" \
"계정 별 관리자 권한이 차등 부여 되어 있는 경우 양호"

ADMIN_PRIV_COLS="Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Reload_priv, Shutdown_priv, Process_priv, File_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Show_db_priv, Super_priv, Create_tmp_table_priv, Lock_tables_priv, Execute_priv, Repl_slave_priv, Repl_client_priv, Create_view_priv, Show_view_priv, Create_routine_priv, Alter_routine_priv, Create_user_priv, Event_priv, Trigger_priv"

run_mysql --skip-column-names -B -e "
SELECT CONCAT('D-04', ',', IF(COUNT(T.user) > 0, 'X', 'O'), ',,') AS ''
FROM (
    SELECT User
    FROM mysql.user
    WHERE 'Y' IN ($ADMIN_PRIV_COLS)
    GROUP BY User
) T
WHERE T.User <> 'root';
" >> "$RESULT" 2>> "$RAWLOG"

run_mysql --skip-column-names -B -e "
SELECT CASE
WHEN (
    SELECT COUNT(*)
    FROM (
        SELECT User
        FROM mysql.user
        WHERE 'Y' IN ($ADMIN_PRIV_COLS)
          AND User <> 'root'
        GROUP BY User
    ) A
) > 0
THEN 'ROOT 외 관리권한이 부여된 계정이 존재해 취약함'
ELSE 'ROOT 외 관리권한이 부여된 계정이 발견되지 않아 양호함'
END AS '';
" >> "$RESULT" 2>> "$RAWLOG"

log ""
log "[설정]"

run_mysql -B -e "
SELECT User, $ADMIN_PRIV_COLS
FROM mysql.user
WHERE 'Y' IN ($ADMIN_PRIV_COLS)
GROUP BY User, $ADMIN_PRIV_COLS;
" >> "$RESULT" 2>> "$RAWLOG"

log ""

###############################################################################
# D-05
###############################################################################

section_header "D-05. 패스워드 재사용에 대한 제약" \
"PASSWORD_REUSE_TIME, PASSWORD_REUSE_MAX 파라미터 설정이 적용된 경우 양호"

log "D-05,N/A,,"
log "Oracle 환경에 대한 설정부분으로 해당사항 없음"
log ""

###############################################################################
# D-06
###############################################################################

section_header "D-06. DB 사용자 계정 개별적 부여" \
"사용자별 계정을 사용하고 있는 경우 양호"

DB_PRIV_COLS="Select_priv, Insert_priv, Update_priv, Delete_priv, Create_priv, Drop_priv, Grant_priv, References_priv, Index_priv, Alter_priv, Create_tmp_table_priv, Lock_tables_priv, Create_view_priv, Show_view_priv, Create_routine_priv, Alter_routine_priv, Execute_priv, Event_priv, Trigger_priv"

run_mysql --skip-column-names -B -e "
SELECT CONCAT('D-06', ',', IF(COUNT(T.db) > 0, 'X', 'O'), ',,') AS ''
FROM (
    SELECT db, COUNT(user) userCnt
    FROM mysql.db
    WHERE 'Y' IN ($DB_PRIV_COLS)
    GROUP BY db
) T
WHERE T.userCnt > 1;
" >> "$RESULT" 2>> "$RAWLOG"

run_mysql --skip-column-names -B -e "
SELECT CASE
WHEN (
    SELECT COUNT(T.db)
    FROM (
        SELECT db, COUNT(user) userCnt
        FROM mysql.db
        WHERE 'Y' IN ($DB_PRIV_COLS)
        GROUP BY db
    ) T
    WHERE T.userCnt > 1
) > 0
THEN '2명 이상의 접근 가능 사용자가 할당된 데이터베이스가 발견되어 취약함'
ELSE '2명 이상의 접근 가능 사용자가 할당된 데이터베이스가 발견되지 않아 양호함'
END AS '';
" >> "$RESULT" 2>> "$RAWLOG"

log ""
log "[설정]"

run_mysql -B -e "
SELECT db, user
FROM mysql.db
WHERE 'Y' IN ($DB_PRIV_COLS);
" >> "$RESULT" 2>> "$RAWLOG"

log ""

###############################################################################
# D-07
###############################################################################

section_header "D-07. 원격에서 DB 서버로의 접속 제한" \
"허용된 IP 및 포트에 대한 접근 통제가 되어 있는 경우 양호"

run_mysql --skip-column-names -B -e "
SELECT CONCAT('D-07', ',', IF(COUNT(host) > 0, 'X', 'O'), ',,') AS ''
FROM mysql.user
WHERE host = '%'
  AND user <> '';
" >> "$RESULT" 2>> "$RAWLOG"

run_mysql --skip-column-names -B -e "
SELECT CASE
WHEN (
    SELECT COUNT(DISTINCT user)
    FROM mysql.user
    WHERE host = '%'
      AND user <> ''
) > 0
THEN '외부 접근이 허용된 계정이 존재해 취약함'
ELSE '외부 접근이 허용된 계정이 발견되지 않아 양호함'
END AS '';
" >> "$RESULT" 2>> "$RAWLOG"

log ""
log "[설정]"

run_mysql -B -e "
SELECT DISTINCT host, user
FROM mysql.user
WHERE user <> '';
" >> "$RESULT" 2>> "$RAWLOG"

log ""

###############################################################################
# D-08
###############################################################################

section_header "D-08. DBA이외의 인가되지 않은 사용자 시스템 테이블 접근 제한 설정" \
"DBA만 접근 가능한 테이블에 일반 사용자 접근이 불가능 할 경우 양호"

run_mysql --skip-column-names -B -e "
SELECT CONCAT('D-08', ',', IF(COUNT(T.cnt) > 0, 'X', 'O'), ',,') AS ''
FROM (
    SELECT db, COUNT(*) cnt
    FROM mysql.db
    WHERE 'Y' IN ($DB_PRIV_COLS)
    GROUP BY db
) T
WHERE T.db = 'mysql';
" >> "$RESULT" 2>> "$RAWLOG"

run_mysql --skip-column-names -B -e "
SELECT CASE
WHEN (
    SELECT COUNT(user)
    FROM mysql.db
    WHERE 'Y' IN ($DB_PRIV_COLS)
      AND db = 'mysql'
) > 0
THEN 'mysql 데이터베이스의 접근 또는 관리권한이 부여된 계정이 존재해 취약함'
ELSE 'mysql 데이터베이스의 접근 또는 관리권한이 부여된 계정이 발견되지 않아 양호함'
END AS '';
" >> "$RESULT" 2>> "$RAWLOG"

log ""
log "[설정]"

run_mysql -B -e "
SELECT *
FROM mysql.db
WHERE 'Y' IN ($DB_PRIV_COLS)
  AND db = 'mysql';
" >> "$RESULT" 2>> "$RAWLOG"

log ""

###############################################################################
# D-09 ~ D-11
###############################################################################

section_header "D-09. 오라클 데이터베이스의 경우 리스너 패스워드 설정" \
"Listener의 패스워드가 설정되어 있는 경우 양호"
log "D-09,N/A,,"
log "Oracle 환경에 대한 설정부분으로 해당사항 없음"
log ""

section_header "D-10. 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거" \
"불필요한 ODBC/OLE-DB가 설치되지 않은 경우 양호"
log "D-10,N/A,,"
log "Windows 에서 ODBC/OLE-DB 확인부분으로 해당사항 없음"
log ""

section_header "D-11. 일정 횟수의 로그인 실패 시 잠금 정책 설정" \
"로그인 시도 횟수를 제한하는 값을 설정한 경우 양호"
log "D-11,N/A,,"
log "MySQL 에서 기능을 제공하지 않고 있으며, Oracle 환경에 해당하므로 해당사항 없음"
log ""

###############################################################################
# D-12
###############################################################################

section_header "D-12. 데이터베이스의 주요 파일 보호 등을 위해 DB 계정의 umask를 022 이상으로 설정" \
"계정의 umask가 022 이상으로 설정되어 있는 경우 양호"

CURRENT_UMASK=$(umask)

# 일반적으로 022, 027, 077 등은 양호로 판단
case "$CURRENT_UMASK" in
    022|027|077|0022|0027|0077)
        log "D-12,O,,"
        log "UMASK 가 022 이상으로 설정이 되어 있어 양호함"
        ;;
    *)
        log "D-12,X,,"
        log "UMASK 가 설정이 되어 있지 않거나 022 보다 낮은 권한으로 설정되어 있어 취약함"
        ;;
esac

log ""
log "[설정]"
log "UMASK : $CURRENT_UMASK"
log ""

###############################################################################
# D-13
###############################################################################

section_header "D-13. 데이터베이스의 주요 설정파일, 패스워드 파일 등 주요 파일들의 접근 권한 설정" \
"주요 설정 파일 및 디렉터리의 퍼미션 설정이 되어있는 경우 양호"

TMP_CNF_LIST=$(mktemp)
find / -type f -name "my*.cnf" -exec ls -l {} \; 2>/dev/null > "$TMP_CNF_LIST"

WEAK_CNF_COUNT=0

while read -r line; do
    perm=$(echo "$line" | awk '{print $1}')
    file=$(echo "$line" | awk '{print $NF}')

    # 권한 숫자 확인
    if [ -n "$file" ] && [ -e "$file" ]; then
        mode=$(stat -c "%a" "$file" 2>/dev/null)
        if [ -n "$mode" ]; then
            # 640 이하만 양호로 판단, 그보다 넓으면 취약
            if [ "$mode" -gt 640 ]; then
                WEAK_CNF_COUNT=$((WEAK_CNF_COUNT + 1))
            fi
        fi
    fi
done < "$TMP_CNF_LIST"

if [ "$WEAK_CNF_COUNT" -eq 0 ]; then
    log "D-13,O,,"
    log "설정 파일(my*.cnf)의 권한이 640 이하로 설정되어 있어 양호함"
else
    log "D-13,X,,"
    log "설정 파일(my*.cnf)의 권한이 640 보다 넓게 설정된 파일이 존재하여 취약함"
fi

log ""
log "[설정]"
cat "$TMP_CNF_LIST" >> "$RESULT"
rm -f "$TMP_CNF_LIST"
log ""

###############################################################################
# D-14 ~ D-20
###############################################################################

section_header "D-14. 관리자 이외의 사용자가 오라클 리스너의 접속을 통해 리스너 로그 및 trace 파일에 대한 변경 권한 제한" \
"주요 설정 파일 및 로그 파일에 대한 퍼미션을 관리자로 설정한 경우 양호"
log "D-14,N/A,,"
log "Oracle 환경에 대한 설정부분으로 해당사항 없음"
log ""

section_header "D-15. 응용프로그램 또는 DBA 계정의 Role이 Public으로 설정되지 않도록 조정" \
"DBA 계정의 Role이 Public으로 설정되어 있지 않은 경우 양호"
log "D-15,N/A,,"
log "Oracle 및 MSSQL 환경에 대한 설정부분으로 해당사항 없음"
log ""

section_header "D-16. OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES를 FALSE로 설정" \
"OS_ROLES, REMOTE_OS_AUTHENTICATION, REMOTE_OS_ROLES설정이 FALSE로 되어있는 경우 양호"
log "D-16,N/A,,"
log "Oracle 환경에 대한 설정부분으로 해당사항 없음"
log ""

section_header "D-17. 패스워드 확인함수가 설정되어 적용되는가?" \
"패스워드 검증 함수로 검증이 진행되는 경우 양호"
log "D-17,N/A,,"
log "Oracle 환경에 대한 설정부분으로 해당사항 없음"
log ""

section_header "D-18. 인가되지 않은 Object Owner가 존재하지 않는가?" \
"Object Owner 의 권한이 SYS, SYSTEM, 관리자 계정 등으로 제한된 경우 양호"
log "D-18,N/A,,"
log "Oracle 환경에 대한 설정부분으로 해당사항 없음"
log ""

section_header "D-19. grant option이 role에 의해 부여되도록 설정" \
"WITH_GRANT_OPTION이 ROLE에 의하여 설정되어있는 경우 양호"
log "D-19,N/A,,"
log "Oracle 환경에 대한 설정부분으로 해당사항 없음"
log ""

section_header "D-20. 데이터베이스의 자원 제한 기능을 TRUE로 설정" \
"RESOURCE_LIMIT 설정이 TRUE로 되어있는 경우 양호"
log "D-20,N/A,,"
log "Oracle 환경에 대한 설정부분으로 해당사항 없음"
log ""

###############################################################################
# D-21
###############################################################################

section_header "D-21. 데이터베이스에 대해 최신 보안 패치와 밴더 권고사항을 모두 적용" \
"버전 별 최신 패치를 적용한 경우 양호"

DOT1VERSION=$(run_mysql_no_pw_echo "SELECT SUBSTRING_INDEX(VERSION(), '.', 2);" 2>/dev/null)
DB23_EXPIRE=0
LATESTVER=""

case "$DOT1VERSION" in
    "5.5")
        LATESTVER="$LAT_55"
        ;;
    "5.6")
        LATESTVER="$LAT_56"
        ;;
    "5.7")
        LATESTVER="$LAT_57"
        ;;
    "8.0")
        LATESTVER="$LAT_80"
        ;;
    *)
        DB23_EXPIRE=1
        ;;
esac

if [ "$DB23_EXPIRE" -eq 0 ]; then
    ISLATEST=$(run_mysql_no_pw_echo "SELECT SUBSTRING_INDEX(VERSION(), '-', 1) >= '$LATESTVER';" 2>/dev/null)
    ISLATEST=${ISLATEST:-0}

    if [ "$ISLATEST" -eq 1 ]; then
        log "D-21,O,,"
        log "데이터베이스가 '$LATESTVER'과 같거나 높아 양호함"
    else
        log "D-21,X,,"
        log "데이터베이스가 '$LATESTVER'보다 낮아 취약함"
    fi
else
    log "D-21,C,,"
    log "현재 버전($DOT1VERSION)에 대한 최신 버전 기준이 스크립트에 정의되어 있지 않아 수동 확인 필요"
fi

log ""

###############################################################################
# D-22
###############################################################################

section_header "D-22. 데이터베이스의 접근, 변경, 삭제 등의 감사기록이 기관의 감사기록 정책에 적합하도록 설정" \
"DBMS의 감사 로그 저장 정책이 수립되어 있으며, 정책이 적용되어 있는 경우 양호"

log "D-22,N/A,,"
log "Oracle 및 MSSQL 환경에 대한 설정부분으로 해당사항 없음"
log ""

###############################################################################
# D-23
###############################################################################

section_header "D-23. 보안에 취약하지 않은 버전의 데이터베이스를 사용하고 있는가?" \
"Oracle 보안 패치가 지원되는 버전을 사용하는 경우 양호"

if [ "$DB23_EXPIRE" -eq 0 ]; then
    log "D-23,O,,"
    log "현재 사용하고 있는 데이터베이스는 스크립트 기준상 업데이트 지원 대상 버전으로 확인됨"
else
    log "D-23,X,,"
    log "현재 사용하고 있는 데이터베이스는 스크립트 기준상 업데이트 지원 대상 버전으로 확인되지 않음"
fi

log ""
log "[설정]"
log "데이터베이스 버전 : $DOT1VERSION"
log "상세 버전 : $DBVER"
log ""

###############################################################################
# D-24
###############################################################################

section_header "D-24. Audit Table은 데이터베이스 관리자 계정에 속해 있도록 설정" \
"Audit Table 접근 권한이 관리자 계정으로 설정한 경우 양호"

log "D-24,N/A,,"
log "Oracle 환경에 대한 설정부분으로 해당사항 없음"
log ""

###############################################################################
# MariaDB/MySQL Process Check
###############################################################################

log ""
log "------------------------MariaDB/MySQL Process Check---------------------------"
log "[명령어] ps -ef | egrep '[m]ariadb|[m]ariadbd|[m]ysqld'"

echo ""
echo "------------------------MariaDB/MySQL Process Check---------------------------"
echo "[명령어] ps -ef | egrep '[m]ariadb|[m]ariadbd|[m]ysqld'"

if ps -ef | egrep '[m]ariadb|[m]ariadbd|[m]ysqld' | tee -a "$RESULT"; then
    :
else
    echo "MariaDB/MySQL 프로세스가 확인되지 않음" | tee -a "$RESULT"
fi

log ""

###############################################################################
# Basic RAW
###############################################################################

log "------------------------Basic RAW---------------------------"
log "기본 정보"
log "MySQL Current Version : $DBVER"
log "Host : $HOST"
log "Port : $PORT"
log "Client : $CLIENT"

echo ""
echo ""
echo "Please Return your $RESULT"
