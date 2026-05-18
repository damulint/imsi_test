#!/bin/bash
DIR="$(cd "$(dirname "$0")" && pwd)"
bash "$DIR/dbms_linux_chk.sh" mysql
