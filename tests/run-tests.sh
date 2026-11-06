#!/usr/bin/env bash
# Run the hx command line tests.
#
# Each tests/NAME.t directory holds a TESTRECIPE (in the format of
# https://github.com/np/cmdcheck) with the command arguments and expected
# exit code, plus the expected stdin, stdout, stderr and product files.
#
# Usage: tests/run-tests.sh [-v] [TEST.t...]
#   HX=/path/to/hx overrides the binary (default: `stack exec which hx`).

set -u

verbose=0
if [ "${1:-}" = "-v" ]; then verbose=1; shift; fi

here="$(cd "$(dirname "$0")" && pwd)"
if [ -z "${HX:-}" ]; then
  HX="$(cd "$here/.." && stack exec -- which hx)" || { echo "cannot find hx; build it or set HX" >&2; exit 2; }
fi

if [ $# -eq 0 ]; then
  set -- "$here"/*.t
fi

pass=0
fail=0
failed=()

for t in "$@"; do
  t="$(cd "$t" && pwd)"
  name="$(basename "$t")"
  work="$(mktemp -d)"
  result="$(
    # Load the recipe in a subshell: it only defines variables and functions.
    stdin_file=/dev/null stdout_file=/dev/null stderr_file=/dev/null
    exit_code=0 products=() args=()
    # shellcheck disable=SC1091
    . "$t/TESTRECIPE"
    resolve() { case "$1" in /*) echo "$1" ;; *) echo "$t/$1" ;; esac; }
    in_f="$(resolve "$stdin_file")"
    # /dev/stdin means "inherit"; it may not exist when we have no stdin.
    [ -r "$in_f" ] || in_f=/dev/null
    out_f="$(resolve "$stdout_file")"
    err_f="$(resolve "$stderr_file")"
    [ -e "$out_f" ] || out_f=/dev/null
    [ -e "$err_f" ] || err_f=/dev/null
    cd "$work" || exit 1
    "$HX" "${args[@]}" < "$in_f" > "$work/stdout" 2> "$work/stderr"
    code=$?
    # Recipes may post-process the outputs (in place) before the comparison.
    if ! command -v sponge > /dev/null; then
      sponge() { local tmp; tmp="$(mktemp)"; cat > "$tmp"; mv "$tmp" "$1"; }
    fi
    if declare -F munge > /dev/null; then munge; fi
    ok=1
    msgs=""
    if [ "$code" != "$exit_code" ]; then ok=0; msgs+="  exit code: expected $exit_code, got $code"$'\n'; fi
    if ! cmp -s "$out_f" "$work/stdout"; then
      ok=0; msgs+="  stdout differs:"$'\n'"$(diff -u --label expected --label actual "$out_f" "$work/stdout" | sed 's/^/    /')"$'\n'
    fi
    if ! cmp -s "$err_f" "$work/stderr"; then
      ok=0; msgs+="  stderr differs:"$'\n'"$(diff -u --label expected --label actual "$err_f" "$work/stderr" | sed 's/^/    /')"$'\n'
    fi
    for p in "${products[@]}"; do
      if ! cmp -s "$t/$p" "$work/$p"; then ok=0; msgs+="  product $p differs or is missing"$'\n'; fi
    done
    if [ $ok = 1 ]; then echo PASS; else echo FAIL; printf '%s' "$msgs"; fi
  )"
  rm -rf "$work"
  if [ "${result%%$'\n'*}" = PASS ]; then
    pass=$((pass + 1))
    [ $verbose = 1 ] && echo "PASS $name"
  else
    fail=$((fail + 1))
    failed+=("$name")
    echo "FAIL $name"
    printf '%s\n' "${result#FAIL}" | sed '/^$/d'
  fi
done

echo
echo "$pass passed, $fail failed"
[ $fail = 0 ]
