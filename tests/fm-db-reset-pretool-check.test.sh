#!/usr/bin/env bash
# shellcheck disable=SC1091,SC2016
# Behavior tests for the db-reset PreToolUse seatbelt (docs/db-reset-guard.md).
#
# bin/fm-db-reset-command-policy.mjs is the single owner of the block/allow
# decision; it reuses the shell tokenizer, command-position analysis, and
# nested-execution-payload extraction owned by bin/fm-arm-command-policy.mjs.
# This suite drives the stable shell transport through all five harness entry
# forms and asserts the classifier decision matrix, the deliberate lack of
# primary-checkout scoping (unlike the cd-guard), the fail-open transport
# behavior, the prefilter fast path, and the per-harness wiring. No harness is
# spawned.
set -u

# shellcheck source=tests/lib.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

fm_git_identity fmtest fmtest@example.invalid
TMP_ROOT=$(fm_test_tmproot fm-db-reset-pretool-check)

CHECK="$ROOT/bin/fm-db-reset-pretool-check.sh"
POLICY="$ROOT/bin/fm-db-reset-command-policy.mjs"

# --- full cross-harness acceptance matrix ----------------------------------

MATRIX_IDS=()
MATRIX_EXPECTED=()
MATRIX_COMMANDS=()

matrix_case() {
  MATRIX_IDS+=("$1")
  MATRIX_EXPECTED+=("$2")
  MATRIX_COMMANDS+=("$3")
}

# DENY: a direct raw supabase invocation of a guarded subcommand.
matrix_case D01 deny 'supabase db reset --local'
matrix_case D02 deny 'supabase db reset'
matrix_case D03 deny 'supabase db push'
matrix_case D04 deny 'supabase db push --linked'
matrix_case D05 deny 'supabase migration up'
matrix_case D06 deny 'supabase migration up --linked'
matrix_case D07 deny './node_modules/.bin/supabase db reset --local'
matrix_case D08 deny '/usr/local/bin/supabase db reset --local'
matrix_case D09 deny 'sudo supabase db reset --local'
matrix_case D10 deny 'env FOO=bar supabase db reset --local'
matrix_case D11 deny 'timeout 5 supabase migration up'
matrix_case D12 deny 'exec supabase db reset --local'
matrix_case D13 deny 'command supabase db reset --local'
matrix_case D14 deny 'supabase --experimental db reset --local'
matrix_case D15 deny 'supabase --debug db push'
matrix_case D16 deny 'echo before; supabase db reset --local'
matrix_case D17 deny 'true && supabase db reset --local'
matrix_case D18 deny 'supabase db reset --local; echo after'
# DENY: pipeline/substitution bypass attempts - the exact class of obfuscation
# a naive string-contains check would miss but command-position analysis
# still resolves.
matrix_case D19 deny 'true | supabase db reset --local'
matrix_case D20 deny 'supabase db reset --local | cat'
matrix_case D21 deny 'echo "$(supabase db reset --local)"'
matrix_case D22 deny '$(supabase migration up)'
matrix_case D23 deny 'cat <(supabase db push)'
matrix_case D24 deny '(supabase db reset --local)'
matrix_case D25 deny 'bash -c "supabase db reset --local"'
matrix_case D26 deny "sh -c 'supabase db push'"
matrix_case D27 deny "eval 'supabase migration up'"
matrix_case D28 deny $'bash <<\'EOF\'\nsupabase db reset --local\nEOF'
matrix_case D29 deny "bash <<< 'supabase db reset --local'"
matrix_case D30 deny "su'pa'base db reset --local"
matrix_case D31 deny 'supabase "db" reset --local'
# DENY: a dynamic word occupying either half of an otherwise-literal guarded
# pair - its runtime value could still complete `db reset`/`db push`/
# `migration up`, so this fails closed rather than silently allowing.
matrix_case D32 deny 'supabase db "$X"'
matrix_case D33 deny 'supabase migration "$X"'
matrix_case D34 deny 'supabase "$GROUP" reset'
matrix_case D35 deny 'supabase "$GROUP" up'

# ALLOW: the guarded wrapper, unrelated supabase subcommands, and data mentions.
matrix_case A01 allow 'pnpm db:reset'
matrix_case A02 allow 'node scripts/db/safe-reset-local.mjs'
matrix_case A03 allow 'npm run db:reset'
matrix_case A04 allow 'supabase status'
matrix_case A05 allow 'supabase db diff'
matrix_case A06 allow 'supabase db dump'
matrix_case A07 allow 'supabase migration list'
matrix_case A08 allow 'supabase link'
matrix_case A09 allow "echo 'supabase db reset --local'"
matrix_case A10 allow 'echo supabase db reset is dangerous, run the guarded wrapper instead'
matrix_case A11 allow 'grep -r "supabase db reset" docs'
matrix_case A12 allow 'ls -la'
matrix_case A13 allow 'git status'
matrix_case A14 allow "printf '%s\\n' 'supabase db reset --local'"
# ALLOW: unrelated, real supabase subcommands with a dynamic flag value or
# positional argument nowhere near either half of a guarded pair.
matrix_case A15 allow 'supabase gen types --project-id "$PROJECT_ID"'
matrix_case A16 allow 'supabase functions deploy "$FUNC_NAME"'
matrix_case A17 allow 'supabase link --project-ref "$REF"'
matrix_case A18 allow 'supabase db dump --output "$OUT_FILE"'

MATRIX_TMP=$(mktemp -d "${TMPDIR:-/tmp}/fm-db-reset-policy-matrix.XXXXXX")
FM_TEST_CLEANUP_DIRS+=("$MATRIX_TMP")
trap fm_test_cleanup EXIT

run_matrix_entry() {
  local id=$1 expected=$2 entry=$3 cmd=$4 payload out_file err_file rc
  out_file="$MATRIX_TMP/$id-$entry.out"
  err_file="$MATRIX_TMP/$id-$entry.err"

  case "$entry" in
    codex)
      payload=$(jq -cn --arg command "$cmd" '{tool_name:"Bash",tool_input:{command:$command}}')
      printf '%s' "$payload" | "$CHECK" >"$out_file" 2>"$err_file"
      rc=$?
      ;;
    claude)
      payload=$(jq -cn --arg command "$cmd" '{tool_name:"Bash",tool_input:{command:$command}}')
      printf '%s' "$payload" | "$CHECK" --claude >"$out_file" 2>"$err_file"
      rc=$?
      ;;
    grok)
      payload=$(jq -cn --arg command "$cmd" '{toolName:"run_terminal_command",toolInput:{command:$command}}')
      printf '%s' "$payload" | "$CHECK" >"$out_file" 2>"$err_file"
      rc=$?
      ;;
    opencode|pi)
      "$CHECK" --command "$cmd" >"$out_file" 2>"$err_file"
      rc=$?
      ;;
    *)
      fail "unknown matrix entry form: $entry"
      ;;
  esac

  if [ "$expected" = allow ]; then
    [ "$rc" -eq 0 ] || fail "$id via $entry must allow, got exit $rc: $(cat "$err_file")"
    [ ! -s "$out_file" ] || fail "$id via $entry allow must leave stdout empty: $(cat "$out_file")"
    [ ! -s "$err_file" ] || fail "$id via $entry allow must leave stderr empty: $(cat "$err_file")"
    return
  fi

  [ "$rc" -eq 2 ] || fail "$id via $entry must deny, got exit $rc"
  jq -e '.hookSpecificOutput.permissionDecision == "deny" and (.systemMessage | test("\\[(db-reset-direct|db-push-direct|migration-up-direct|unclassifiable-db-command)\\]"))' "$err_file" >/dev/null 2>&1 \
    || fail "$id via $entry deny must carry a stable reason code on stderr: $(cat "$err_file")"
  if [ "$entry" = claude ]; then
    [ ! -s "$out_file" ] || fail "$id via claude deny must leave stdout empty: $(cat "$out_file")"
  elif [ "$entry" = grok ]; then
    jq -e '.decision == "deny"' "$out_file" >/dev/null 2>&1 \
      || fail "$id via grok deny must carry decision=deny on stdout: $(cat "$out_file")"
  fi
}

test_full_acceptance_matrix() {
  local i entry
  for ((i = 0; i < ${#MATRIX_IDS[@]}; i++)); do
    for entry in codex claude grok opencode pi; do
      run_matrix_entry "${MATRIX_IDS[$i]}" "${MATRIX_EXPECTED[$i]}" "$entry" "${MATRIX_COMMANDS[$i]}"
    done
    pass "matrix ${MATRIX_IDS[$i]}: ${MATRIX_EXPECTED[$i]} through all five entry forms"
  done
}

# --- unsupported compound grammar: fail-closed backstop ---------------------

test_unsupported_grammar_fails_closed() {
  local out rc
  out=$("$CHECK" --command 'for x in 1; do supabase db reset --local; done' 2>&1); rc=$?
  expect_code 2 "$rc" "a loop wrapping a guarded command must fail closed"
  assert_contains "$out" '[unclassifiable-db-command]' "loop backstop must carry the unclassifiable reason code"
  out=$("$CHECK" --command "supabase db reset --local 'unterminated" 2>&1); rc=$?
  expect_code 2 "$rc" "unterminated quoting containing a guarded command must fail closed"
  assert_contains "$out" '[unclassifiable-db-command]' "malformed-syntax backstop must carry the unclassifiable reason code"
  out=$("$CHECK" --command 'for f in 1; do echo supabase; done' 2>&1); rc=$?
  expect_code 0 "$rc" "a loop that only mentions supabase as data, with no guarded subcommand pair, must stay allowed"
  pass "db-reset-guard: unsupported compound grammar fails closed only when a guarded command is actually implicated"
}

# --- deliberate lack of primary-checkout scoping ----------------------------

test_fires_in_child_worktree() {
  local base dir out rc
  base="$TMP_ROOT/wt-base"
  dir="$TMP_ROOT/wt-child"
  fm_git_worktree "$base" "$dir" fm/db-reset-guard-test-branch
  mkdir -p "$dir/bin"
  cp "$ROOT/bin/fm-db-reset-pretool-check.sh" "$dir/bin/fm-db-reset-pretool-check.sh"
  cp "$ROOT/bin/fm-db-reset-command-policy.mjs" "$dir/bin/fm-db-reset-command-policy.mjs"
  cp "$ROOT/bin/fm-arm-command-policy.mjs" "$dir/bin/fm-arm-command-policy.mjs"
  chmod +x "$dir/bin/fm-db-reset-pretool-check.sh" "$dir/bin/fm-db-reset-command-policy.mjs"
  out=$("$dir/bin/fm-db-reset-pretool-check.sh" --claude --command 'supabase db reset --local' 2>&1); rc=$?
  expect_code 2 "$rc" "db-reset-guard must fire in a linked crewmate/scout task worktree too, unlike the cd-guard"
  assert_contains "$out" '[db-reset-direct]' "child-worktree block must carry the reason code"
  pass "db-reset-guard: fires in a linked task worktree (danger is not location-dependent, so no primary-checkout scoping)"
}

# --- direct policy CLI contract ---------------------------------------------

assert_policy() {
  local id=$1 expected=$2 command=$3 output
  output=$(node "$POLICY" --command "$command") \
    || fail "$id direct policy invocation failed"
  case "$output" in
    "$expected"|"$expected"$'\t'*) : ;;
    *) fail "$id direct policy expected $expected, got: $output" ;;
  esac
  pass "direct policy $id: $expected"
}

test_direct_policy_contract() {
  assert_policy direct-reset $'deny\tdb-reset-direct' 'supabase db reset --local'
  assert_policy direct-push $'deny\tdb-push-direct' 'supabase db push'
  assert_policy direct-migration $'deny\tmigration-up-direct' 'supabase migration up'
  assert_policy direct-wrapper allow 'pnpm db:reset'
  assert_policy direct-status allow 'supabase status'
  assert_policy direct-no-command allow ''
}

# --- CLI parsing -------------------------------------------------------------

test_command_equals_form() {
  "$CHECK" --command='supabase db reset --local' >/dev/null 2>&1
  [ "$?" -eq 2 ] || fail "--command=<val> form must parse the same as --command <val>"
  pass "--command=<val> equals-form parses correctly"
}

test_unknown_flag_errors() {
  "$CHECK" --bogus-flag >/dev/null 2>&1
  [ "$?" -eq 2 ] || fail "an unrecognized flag must exit non-zero, not silently allow"
  pass "unknown CLI flag is rejected"
}

# --- --cursor output shaping -------------------------------------------------

test_cursor_mode_deny_shape() {
  local out rc
  out=$("$CHECK" --cursor --command 'supabase db reset --local' 2>&1); rc=$?
  expect_code 0 "$rc" "--cursor deny must exit 0 (Cursor reads the returned object, not the exit status)"
  printf '%s' "$out" | jq -e '.permission == "deny"' >/dev/null 2>&1 \
    || fail "--cursor deny must carry Cursor's own {\"permission\":\"deny\",...} shape: $out"
  pass "--cursor: deny renders Cursor's own decision object with exit 0"
}

# --- prefilter fast path ----------------------------------------------------

test_prefilter_skips_node_without_supabase_substring() {
  local fakebin marker tool tool_path out rc
  fakebin=$(fm_fakebin "$TMP_ROOT/prefilter-fake")
  marker="$TMP_ROOT/prefilter-node-called"
  for tool in bash sh git dirname cat printf sed tr jq; do
    tool_path=$(command -v "$tool") || continue
    ln -s "$tool_path" "$fakebin/$tool"
  done
  cat > "$fakebin/node" <<EOF
#!/usr/bin/env bash
: > "$marker"
exit 0
EOF
  chmod +x "$fakebin/node"
  out=$(PATH="$fakebin" "$CHECK" --command 'git status && echo done' 2>&1); rc=$?
  expect_code 0 "$rc" "prefilter must fast-allow a command with no supabase substring"
  [ -z "$out" ] || fail "prefilter fast-allow produced output: $out"
  [ ! -e "$marker" ] || fail "prefilter fast-allow still invoked the node policy owner"
  pass "db-reset-guard: prefilter fast-allows (skips node) when no supabase substring is present"
}

test_prefilter_is_strict_superset() {
  local rc
  "$CHECK" --command 'supabase db reset --local' >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 2 ] || fail "prefilter must delegate a deniable supabase command, not fast-allow it, got exit $rc"
  "$CHECK" --command "$(printf 'supaba\\\nse db reset --local')" >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 2 ] || fail "prefilter must delegate a line-continuation-split supabase command, got exit $rc"
  "$CHECK" --command 'echo "supabase db reset --local"' >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || fail "a benign supabase-substring command must be classified and allowed, got exit $rc"
  pass "db-reset-guard: transport prefilter is a strict superset"
}

# --- fail-open transport behavior ------------------------------------------

test_fail_open_empty_stdin() {
  local out rc
  out=$("$CHECK" < /dev/null 2>&1); rc=$?
  expect_code 0 "$rc" "transport must exit 0 on empty stdin"
  [ -z "$out" ] || fail "transport produced output on empty stdin: $out"
  pass "db-reset-guard: fails open on empty stdin"
}

test_fail_open_unparseable_json() {
  local out rc
  out=$(printf 'not json at all' | "$CHECK" 2>&1); rc=$?
  expect_code 0 "$rc" "transport must exit 0 on unparseable stdin JSON"
  [ -z "$out" ] || fail "transport produced output on unparseable JSON: $out"
  pass "db-reset-guard: fails open on unparseable stdin JSON"
}

test_fail_open_missing_node() {
  local fakebin tool tool_path out rc
  fakebin=$(fm_fakebin "$TMP_ROOT/nonode")
  for tool in bash sh git dirname cat printf sed tr jq; do
    tool_path=$(command -v "$tool") || continue
    ln -s "$tool_path" "$fakebin/$tool"
  done
  out=$(PATH="$fakebin" "$CHECK" --command 'supabase db reset --local' 2>&1); rc=$?
  expect_code 0 "$rc" "transport must fail open when node is unavailable"
  [ -z "$out" ] || fail "transport produced output without node: $out"
  pass "db-reset-guard: fails open (never blocks) when node is missing"
}

test_fail_open_missing_jq_on_stdin() {
  local fakebin tool tool_path out rc
  fakebin=$(fm_fakebin "$TMP_ROOT/nojq")
  for tool in bash sh git dirname cat printf sed tr node; do
    tool_path=$(command -v "$tool") || continue
    ln -s "$tool_path" "$fakebin/$tool"
  done
  out=$(printf '{"tool_input":{"command":"supabase db reset --local"}}' | PATH="$fakebin" "$CHECK" 2>&1); rc=$?
  expect_code 0 "$rc" "stdin transport must fail open when jq is unavailable"
  [ -z "$out" ] || fail "transport produced output without jq on the stdin path: $out"
  pass "db-reset-guard: fails open on the stdin path when jq is missing"
}

# --- allow is silent ---------------------------------------------------------

test_allow_is_silent_both_modes() {
  local out1 out2
  out1=$("$CHECK" --command 'supabase status' 2>&1)
  out2=$("$CHECK" --claude --command 'supabase status' 2>&1)
  [ -z "$out1" ] || fail "default allow must be silent, got: $out1"
  [ -z "$out2" ] || fail "--claude allow must be silent, got: $out2"
  pass "allow is silent on both stdout and stderr in default and --claude mode"
}

# --- per-harness wiring: the registered hook entry fires end-to-end ---------

wired_hook_command() {
  jq -r '.hooks.PreToolUse[]?.hooks[]? | select(.command? and (.command | contains("fm-db-reset-pretool-check.sh"))) | .command' "$1" | head -n1
}

test_claude_settings_wired() {
  local hook_command payload out rc
  hook_command=$(wired_hook_command "$ROOT/.claude/settings.json")
  [ -n "$hook_command" ] || fail ".claude/settings.json must register fm-db-reset-pretool-check.sh on a Bash PreToolUse hook"

  payload=$(jq -cn --arg command 'supabase db reset --local' '{tool_name:"Bash",tool_input:{command:$command}}')
  out=$(printf '%s' "$payload" | CLAUDE_PROJECT_DIR="$ROOT" bash -c "$hook_command" 2>&1); rc=$?
  expect_code 2 "$rc" "the wired .claude/settings.json hook entry must deny a raw supabase db reset"
  assert_contains "$out" '[db-reset-direct]' "the wired Claude hook deny must carry the reason code"

  payload=$(jq -cn --arg command 'supabase status' '{tool_name:"Bash",tool_input:{command:$command}}')
  out=$(printf '%s' "$payload" | CLAUDE_PROJECT_DIR="$ROOT" bash -c "$hook_command" 2>&1); rc=$?
  expect_code 0 "$rc" "the wired .claude/settings.json hook entry must allow an unrelated supabase command"
  [ -z "$out" ] || fail "the wired Claude hook allow must be silent: $out"
  pass ".claude/settings.json wires fm-db-reset-pretool-check.sh and it fires end-to-end"
}

test_codex_hooks_wired() {
  local hook_command payload out rc
  hook_command=$(wired_hook_command "$ROOT/.codex/hooks.json")
  [ -n "$hook_command" ] || fail ".codex/hooks.json must register fm-db-reset-pretool-check.sh on a Bash PreToolUse hook"

  payload=$(jq -cn --arg command 'supabase db reset --local' '{tool_name:"Bash",tool_input:{command:$command}}')
  out=$(cd "$ROOT" && printf '%s' "$payload" | bash -c "$hook_command" 2>&1); rc=$?
  expect_code 2 "$rc" "the wired .codex/hooks.json hook entry must deny a raw supabase db reset"
  assert_contains "$out" '[db-reset-direct]' "the wired Codex hook deny must carry the reason code"

  payload=$(jq -cn --arg command 'supabase status' '{tool_name:"Bash",tool_input:{command:$command}}')
  out=$(cd "$ROOT" && printf '%s' "$payload" | bash -c "$hook_command" 2>&1); rc=$?
  expect_code 0 "$rc" "the wired .codex/hooks.json hook entry must allow an unrelated supabase command"
  [ -z "$out" ] || fail "the wired Codex hook allow must be silent: $out"
  pass ".codex/hooks.json wires fm-db-reset-pretool-check.sh and it fires end-to-end"
}

# --- shellcheck (belt-and-suspenders; CI/CONTRIBUTING.md also runs this) -----

test_scripts_are_shellcheck_clean() {
  local out
  command -v shellcheck >/dev/null 2>&1 || { pass "shellcheck not installed, skipping"; return; }
  out=$("$ROOT/bin/fm-lint.sh" "$CHECK" 2>&1) \
    || fail "bin/fm-db-reset-pretool-check.sh is not lint-clean under the pinned definition: $out"
  pass "bin/fm-db-reset-pretool-check.sh is clean under bin/fm-lint.sh"
}

test_full_acceptance_matrix
test_unsupported_grammar_fails_closed
test_fires_in_child_worktree
test_direct_policy_contract
test_command_equals_form
test_unknown_flag_errors
test_cursor_mode_deny_shape
test_prefilter_skips_node_without_supabase_substring
test_prefilter_is_strict_superset
test_fail_open_empty_stdin
test_fail_open_unparseable_json
test_fail_open_missing_node
test_fail_open_missing_jq_on_stdin
test_allow_is_silent_both_modes
test_claude_settings_wired
test_codex_hooks_wired
test_scripts_are_shellcheck_clean
