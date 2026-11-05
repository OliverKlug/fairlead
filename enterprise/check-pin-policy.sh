#!/bin/sh
# SPDX-FileCopyrightText: Copyright (c) 2026 Oliver Klug
# SPDX-License-Identifier: Apache-2.0
# Falsifier for fleet-pin-policy.sql. sqlite3 stands in for osquery's `processes` and `hash`
# tables, so this proves the predicate, not osquery. check-install.sh runs it on real osquery.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
q=$(grep -v '^--' "$here/fleet-pin-policy.sql" |
  sed -e 's|@HOOKS_PATH@|/m/hooks.json|' -e 's|@HOOKS_SHA256@|aa|' \
      -e 's|@BIN_PATH@|/m/fairlead|' -e 's|@BIN_SHA256@|bb|' \
      -e 's|@WRAP_PATH@|/m/fairlead-hook|' -e 's|@WRAP_SHA256@|cc|' \
      -e 's|@CEDAR_PATH@|/m/baseline.cedar|' -e 's|@CEDAR_SHA256@|dd|' \
      -e 's|@SCHEMA_PATH@|/m/coding-agent.cedarschema|' -e 's|@SCHEMA_SHA256@|ee|')

# $1 = label, $2 = expected row count, $3 = process inserts, $4 = hash inserts
case_() {
  got=$(sqlite3 :memory: "create table processes(name text, path text); create table hash(path text, sha256 text); $3 $4 $q" | wc -l | tr -d ' ')
  [ "$got" = "$2" ] || { echo "FAIL $1: want $2 row(s), got $got" >&2; exit 1; }
  echo "ok   $1"
}
ide="insert into processes values('Cursor','/Applications/Cursor.app/Contents/MacOS/Cursor');"
h="('/m/hooks.json','aa')"; b="('/m/fairlead','bb')"; w="('/m/fairlead-hook','cc')"
c="('/m/baseline.cedar','dd')"; s="('/m/coding-agent.cedarschema','ee')"
all="insert into hash values$h,$b,$w,$c,$s;"

case_ "IDE closed overnight, no files at all: pass"   1 ""  ""
case_ "IDE open, all five hashes match: pass"         1 "$ide" "$all"
case_ "IDE open and idle is the same input: pass"     1 "$ide" "$all"
case_ "cursor-agent CLI, hashes match: pass"          1 "insert into processes values('cursor-agent','/usr/local/bin/cursor-agent');" "$all"
case_ "unrelated process only, no files: pass"        1 "insert into processes values('Safari','/Applications/Safari.app/Contents/MacOS/Safari');" ""
hp="insert into processes values('Cursor Helper','/Applications/Cursor.app/Contents/Frameworks/Cursor Helper.app/Contents/MacOS/Cursor Helper');"
case_ "only a lingering Cursor Helper, hooks.json deleted: pass" 1 "$hp" "insert into hash values$b,$w,$c,$s;"
case_ "Windows Cursor.exe, hooks.json deleted: FAIL"  0 "insert into processes values('Cursor.exe','C:\\Users\\u\\AppData\\Local\\Programs\\cursor\\Cursor.exe');" "insert into hash values$b,$w,$c,$s;"
case_ "native claude (name is the version), pin bad: FAIL" 0 "insert into processes values('2.1.300','/home/u/.local/share/claude/versions/2.1.300');" "insert into hash values$b,$w,$c,$s;"
case_ "KNOWN GAP: npm-fallback claude runs as node, not matched: pass"      1 "insert into processes values('node','/usr/bin/node');" "insert into hash values$b,$w,$c,$s;"
case_ "IDE open, hooks.json deleted: FAIL"            0 "$ide" "insert into hash values$b,$w,$c,$s;"
case_ "IDE open, hooks.json edited: FAIL"             0 "$ide" "insert into hash values('/m/hooks.json','zz'),$b,$w,$c,$s;"
case_ "claude open, binary swapped: FAIL"             0 "insert into processes values('claude','/opt/homebrew/Caskroom/claude-code/2.1.22/claude');" "insert into hash values$h,('/m/fairlead','zz'),$w,$c,$s;"
case_ "IDE open, binary deleted: FAIL"                0 "$ide" "insert into hash values$h,$w,$c,$s;"
case_ "IDE open, wrapper edited: FAIL"                0 "$ide" "insert into hash values$h,$b,('/m/fairlead-hook','zz'),$c,$s;"
case_ "IDE open, wrapper deleted: FAIL"               0 "$ide" "insert into hash values$h,$b,$c,$s;"
case_ "IDE open, baseline.cedar edited: FAIL"          0 "$ide" "insert into hash values$h,$b,$w,('/m/baseline.cedar','zz'),$s;"
case_ "IDE open, schema deleted: FAIL"                0 "$ide" "insert into hash values$h,$b,$w,$c;"
echo "pin policy: all cases pass"
