# db-reset-guard PreToolUse seatbelt

This document is the authoritative human-readable contract for the db-reset PreToolUse seatbelt.
`bin/fm-db-reset-command-policy.mjs` is the single decision owner.
`bin/fm-db-reset-pretool-check.sh` is the stable harness transport and output renderer.
The tracked harness adapters forward command text without classifying it.

It is a sibling of the watcher-arm PreToolUse seatbelt (`bin/fm-arm-pretool-check.sh`, `docs/arm-pretool-check.md`) and the cd-guard (`bin/fm-cd-pretool-check.sh`, `docs/cd-guard.md`), reusing the same cross-harness hook machinery and the same shell classifier.

## Why this exists

A project's own guarded database-reset wrapper (for example `scripts/db/safe-reset-local.mjs`, run through `pnpm db:reset` or `node` directly) refuses to reset, push to, or migrate a database stack it cannot verify is safe - a primary or corpus-holding stack needs an explicit human override before that wrapper will touch it.
That guard is opt-in code the wrapper itself enforces: nothing stopped an agent from shelling out to the raw `supabase` CLI directly and bypassing it entirely.
That is the exact shape of a real incident: a primary corpus database was wiped by a raw `supabase db reset --local` (or equivalent raw command) that never went through the guarded wrapper.
This seatbelt closes that gap at the tool-call layer, the same way the watcher-arm and cd seatbelts close their respective gaps: the guarded wrapper becomes the only path an agent can take without an explicit human approval, because the raw CLI invocation is denied before it runs.

The underlying wrapper contract (`ALLOW_PRIMARY_DB_WIPE=1` / `ALLOW_CORPUS_WIPE=1`, stack-identity detection) is owned by the project that ships it, not by this guard.
This guard only closes the bypass path; it does not re-implement or duplicate the wrapper's own safety logic.

## Purpose and boundary

The guard denies a Bash command whose real command-position invocation is `supabase db reset`, `supabase db push`, or `supabase migration up`, run directly rather than through a project's guarded wrapper.

This guard is not a general sandbox.
It classifies shell command positions only; it never evaluates, expands, sources, or runs any byte of the submitted command.
Unlike the cd-guard's agent-mistake threat model, this guard's threat model explicitly includes a deliberate bypass attempt via pipeline or substitution, so it fails closed on unsupported or malformed grammar that implicates a guarded command, matching the watcher-arm seatbelt's `broad-watcher-kill` backstop rather than the cd-guard's fail-open default.

### Out of scope by design

- **Raw `docker exec ... psql` writes.** The motivating incident could also be reproduced through a raw `psql` write against the container directly. Classifying an arbitrary SQL statement as a "write" versus a "read" from static shell analysis alone is not reliably possible, and a wrong classification in either direction is worse than no classification: a false allow defeats the guard silently, and a false deny blocks routine read-only debugging. This guard therefore does not attempt it. Closing this gap needs a different mechanism (for example a project-side wrapper around its own `psql` access), not a PreToolUse command-shape classifier.
- **Indirection through the package-manager `dlx` runners** (`npx supabase ...`, `pnpm dlx supabase ...`, `bunx supabase ...`). The guard recognizes `supabase` only in direct command position (including through `sudo`/`env`/`timeout`/`exec`/`command` wrappers and literal nested `sh -c`/`eval`/heredoc/here-string payloads, which `commandPosition` and the shared nested-payload extraction already resolve for free); it does not special-case a package runner's first positional argument as an alternate command identity. This mirrors the existing classifiers, none of which model package-runner indirection either.
- **Opaque dynamic dataflow.** A variable built from parts and later fed to `eval` or `bash -c "$VAR"` cannot be proven statically and remains out of scope, exactly as `bin/fm-arm-command-policy.mjs` documents for the same class of construct. The same boundary applies to a command-position word itself reconstructed from concatenated parts (for example `BIN="$A$B"; $BIN db reset` where neither `$A` nor `$B` contains the literal substring `supabase`): the fail-closed backstop for a dynamic command word depends on the literal substring `supabase` appearing somewhere in the raw command text, so a name built entirely from non-matching fragments defeats it the same way opaque `eval`/`bash -c` dataflow does. It also applies to a fully dynamic adjacent argument pair with no literal `db`/`migration` anchor establishing the position as a plausible subcommand slot (for example `A=db; B=reset; supabase "$A" "$B"`): at this classifier's information level, such a pair is indistinguishable from two unrelated dynamic flag values that happen to sit next to each other, and a heuristic broad enough to catch the former would also deny ordinary supabase invocations with two dynamic flag values in sequence - a false-positive cost worse than the gap.

None of these is silently assumed to be covered; each is a deliberate, documented boundary.

## Block vs allow

The guard **blocks** a command whose real, statically-provable execution position resolves to the `supabase` CLI with an adjacent guarded subcommand pair (`db reset`, `db push`, or `migration up`) anywhere among its non-flag arguments - regardless of flags, wrapper commands (`sudo`, `env`, `timeout`, `gtimeout`, `exec`, `command`), pipeline position, backgrounding, or redirection, because the dangerous action is the execution itself, not any particular shell shape around it.
This includes the same command reached through a subshell group, a command or process substitution, or a literal (non-dynamic) `sh -c`/`bash -c`/`zsh -c` payload, `eval` payload, heredoc body, or here-string - the exact bypass shapes a naive string-contains check would miss.

The guard **allows** everything else, including:

- The project's own guarded wrapper (`pnpm db:reset`, `node scripts/db/safe-reset-local.mjs`, or any command that never resolves to the literal `supabase` binary in command position).
- Any other `supabase` subcommand (`supabase status`, `supabase db diff`, `supabase db dump`, `supabase migration list`, `supabase link`, and so on).
- The guarded subcommand words appearing as data: quoted text (`echo 'supabase db reset --local'`), a comment, a `printf` payload, or a later argument word.

## Stable reason codes

Every deny carries one stable code in square brackets before its prose reason.

| Code | Meaning |
| --- | --- |
| `db-reset-direct` | A direct `supabase db reset` bypasses the guarded wrapper. |
| `db-push-direct` | A direct `supabase db push` bypasses the guarded wrapper. |
| `migration-up-direct` | A direct `supabase migration up` bypasses the guarded wrapper. |
| `unclassifiable-db-command` | Malformed or unsupported syntax implicates a guarded command and cannot be safely classified. |

Reason codes are the stable contract for tests and adapters.
Prose may improve without changing adapter behavior.

## Scope: unscoped, unlike the cd-guard

This seatbelt is **not** scoped to the primary checkout.
A direct `supabase db reset` is equally dangerous from the firstmate primary, a secondmate, or a crewmate dispatched on a firstmate-repo task, so it fires everywhere the hook is wired - matching `bin/fm-arm-pretool-check.sh`'s scope rather than `bin/fm-cd-pretool-check.sh`'s primary-checkout-only scope.
The cd-guard's narrower scope exists because a `cd` inside a crewmate's own task worktree is ordinary, legitimate usage; there is no equivalent legitimate-usage carve-out for a raw database reset, so no scoping is applied.

## Transport and fail-open behavior

`bin/fm-db-reset-pretool-check.sh` supports the same harness-engine entry shapes as the sibling guards:

- Claude and Codex send stdin JSON at `.tool_input.command` (Claude adds `--claude`).
- Grok sends stdin JSON at `.toolInput.command`.
- OpenCode and Pi send the exact command string through `--command <exact string>`.
- Cursor sends stdin JSON at `.tool_input.command` and adds `--cursor`, which renders the deny as Cursor's own returned decision object.

Processing order is cheapest-first: a strict-superset prefilter, then the Node policy owner.
The prefilter removes ordinary single quotes, double quotes, backslashes, carriage returns, and newlines before fast-allowing any command that carries no `supabase` substring and no quoting-decoder marker (`$'` ANSI-C or `$"` locale), so quoted or escaped command-word fragments still delegate to the policy while most commands never pay for the Node process.
The quoting-decoder marker set is coupled to the classifier's decoder set in `bin/fm-arm-command-policy.mjs`: adding any new quote or expansion form the classifier decodes requires extending the prefilter marker set in the same change, or it stops being a strict superset.

Empty stdin, unparseable JSON, missing `jq` on the stdin path, missing Node, a missing policy owner, or an invalid policy response all fail open with exit 0 and no output.
A broken hook must never deny every shell tool call.

## Output contract

Identical in shape to `docs/arm-pretool-check.md` and `docs/cd-guard.md`:

- Allow returns exit 0 with both streams empty.
- Deny returns exit 2 and writes `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny"},"systemMessage":"[code] reason"}` to stderr.
- Default deny mode also writes `{"decision":"deny","reason":"[code] reason"}` to stdout for Grok.
- `--claude` suppresses stdout completely because Claude ignores a PreToolUse deny when stdout is nonempty.
- `--cursor` renders `{"permission":"deny","user_message":"[code] reason"}` on stdout and exits 0, because Cursor reads the returned object rather than the exit status.
- Codex blocks on exit 2 and displays stderr.
- OpenCode throws only when the checker exits 2.
- Pi and pi-signed return `{block: true}` only when the checker exits 2.

## Shared classifier ownership

`bin/fm-db-reset-command-policy.mjs` imports the shell tokenizer, command-position analysis, and nested-execution-payload extraction (`Lexer`, `splitProgram`, `commandPosition`, `shellInvocation`, `evalPayload`, `shellHeredocPayloads`, `shellHereStringPayloads`) from `bin/fm-arm-command-policy.mjs`, the sole owner of firstmate's shell classification.
This guard is the first sibling policy to reuse the nested-payload extraction in addition to the tokenizer and command-position analysis that `bin/fm-cd-command-policy.mjs` already reused; `bin/fm-arm-command-policy.mjs`'s header comment and export list are the single place that contract is stated.
The db-reset guard never duplicates shell lexing or nested-payload extraction; it adds only its own recursive "does a guarded command execute anywhere in this program" walk and its own `supabase`-subcommand matcher on top of that shared classifier.
`bin/fm-arm-command-policy.mjs` runs its own CLI entry point only when invoked directly, never on import, so the sibling policies stay independent CLIs over one parser.

## Harness/backend coverage review

Every supported primary harness and runtime backend was reviewed, per the `firstmate-coding-guidelines` skill's harness-dependent-checks section.
Applicability turns on one question: can this harness's session shell out to the raw `supabase` CLI, and does it expose a PreToolUse-equivalent mechanism this guard can hook?

| Harness | Delegation surface | Status |
| --- | --- | --- |
| Claude | Runs arbitrary Bash | **Wired and live-validated** below via `.claude/settings.json`. |
| Codex | Runs arbitrary shell commands | **Wired** via `.codex/hooks.json`, following the identical existing template `fm-arm-pretool-check.sh` and `fm-cd-pretool-check.sh` already use (payload-forward, hook-file self-verification, same output contract). Live validation was attempted (see below) but blocked by an account usage-limit error unrelated to this change; the wiring is mechanically identical to the already-validated arm/cd entries and the classifier itself is covered by the portable automated suite, but the harness-level exit-2 behavior for this specific hook has not yet been confirmed against a live Codex process. |
| Grok | Runs arbitrary shell commands; already has `.grok/hooks/fm-primary-pretool-check.json` and `.grok/hooks/fm-primary-cd-check.json` wired for the sibling guards | **Not wired.** Grok is not installed on the host where this change was made, so a new `.grok/hooks/` entry could not be live-verified before trusting it. The bounded follow-up is identical to the one `docs/subagent-guard.md` already records for Grok: add a `.grok/hooks/fm-primary-db-reset-check.json` entry anchored on `${GROK_WORKSPACE_ROOT:-}` forwarding stdin to `bin/fm-db-reset-pretool-check.sh`, then re-run the live matrix on a host with Grok installed. |
| OpenCode | Runs arbitrary shell commands; already has `.opencode/plugins/fm-primary-pretool-check.js` wired for the sibling guards | **Not wired.** OpenCode is installed on this host, but adding and live-validating a new plugin entry (or extending the existing one to also call `fm-db-reset-pretool-check.sh`) was judged out of scope for this change given the task's explicit minimum bar (Claude/Codex); the existing plugin's `tool.execute.before` throw-on-exit-2 mechanism is structurally identical to the arm/cd wiring and the checker already accepts the `--command` CLI form OpenCode uses. |
| Pi / pi-signed | Runs arbitrary shell commands; already has `.pi/extensions/fm-primary-turnend-guard.ts` wired for the sibling guards | **Not wired**, for the same reason as OpenCode. Pi is not installed on this host either, so live verification is unavailable regardless. The checker already accepts the `--command` CLI form Pi uses. |
| Cursor | Runs arbitrary shell commands; already has `.cursor/hooks.json` wired for the sibling guards | **Not wired.** `cursor-agent` is installed on this host, but the same minimum-bar scoping decision applies as OpenCode/Pi. The checker already accepts `--cursor` and the stdin `.tool_input.command` shape Cursor sends. |
| Gemini, Rovo, Muse | Crewmate/scout-only backends per `AGENTS.md` section 4 | **No PreToolUse-equivalent mechanism documented** in the `harness-adapters` skill for any of these three. Not applicable until one exists. |

Grok, OpenCode, Pi, and Cursor are each structurally straightforward to wire, following the exact same template their existing arm/cd entries already use in the same file, and none of the four needs a change to `bin/fm-db-reset-pretool-check.sh` itself.
None is wired in this change because full parity was not the task's minimum bar and, for Grok and Pi specifically, the binaries are not installed on this host, so the wiring could not be validated against a real harness before being trusted - the same reasoning `docs/subagent-guard.md` already applies to the same two harnesses for the sibling delegation guard.

## Automated validation

`tests/fm-db-reset-pretool-check.test.sh` owns the acceptance matrix.
Every block and allow case runs through Codex-shaped stdin, Claude-shaped stdin, Grok-shaped stdin, OpenCode-shaped CLI, and Pi-shaped CLI entry forms, including a dedicated block of deliberate pipeline- and substitution-based bypass attempts (a pipe stage, a command substitution, a process substitution, a subshell group, a literal `bash -c`/`sh -c`/`eval` payload, a heredoc, and a here-string) that must still be denied, and a quote-split `su'pa'base` word that must still cook to the protected identity.
The suite also proves the fail-closed backstop for unsupported compound grammar (a loop wrapping a guarded command denies; a loop that only mentions `supabase` as data stays allowed), the deliberate lack of primary-checkout scoping (fires in a linked crewmate/scout task worktree), the fail-open transport behavior, the prefilter fast path, the direct policy CLI contract, the `--cursor` output shape, and that both `.claude/settings.json` and `.codex/hooks.json` carry the new entry.

Run:

```sh
bash -n bin/fm-db-reset-pretool-check.sh
shellcheck bin/fm-db-reset-pretool-check.sh tests/fm-db-reset-pretool-check.test.sh
node --check bin/fm-db-reset-command-policy.mjs
node --check bin/fm-arm-command-policy.mjs
tests/fm-db-reset-pretool-check.test.sh
tests/fm-arm-pretool-check.test.sh
tests/fm-cd-pretool-check.test.sh
```

## Live validation record, 2026-09-06

Validation ran in a git-initialized scratch project under this task's worktree, containing copies of `fm-db-reset-pretool-check.sh`, `fm-db-reset-command-policy.mjs`, `fm-arm-command-policy.mjs`, and `fm-hook-host-lib.sh` under `bin/`, an empty `AGENTS.md`, a `.claude/settings.json` wiring the checker on a Bash PreToolUse hook, and a `.codex/hooks.json` carrying only the db-reset entry from the real tracked file (extracted with the real `jq`-based self-verification intact).
No modified file was installed into the primary checkout or a live harness configuration, and no live watcher, fleet state, project database, or Herdr lifecycle command was used.

Each harness was asked to run two separate tool calls: a control `touch CONTROL_RAN`, then `supabase db reset --local`.

- **Claude Code 2.1.223** - blocked. The control file was created, and Claude reported the second call was denied, quoting the deny message verbatim: `[db-reset-direct] a direct \`supabase db reset\` bypasses the project's guarded reset wrapper, which refuses to reset a database stack it cannot verify is safe (a primary or corpus-holding stack needs an explicit human override). Run the project's guarded wrapper instead - for example \`pnpm db:reset\` or \`node scripts/db/safe-reset-local.mjs\` - never the raw supabase CLI.` Claude explicitly did not attempt to bypass the block.
- **codex-cli 0.149.0** - inconclusive. The session started and completed its `SessionStart`/`UserPromptSubmit` hooks, then `ERROR: You've hit your usage limit` before either tool call was issued, an account-level condition unrelated to this change. The Codex db-reset hook entry is byte-structurally identical to the already-validated arm/cd entries in the same file (same `bash -lc` template, same hook-file self-verification via `jq -e`, same payload-forward), and the classifier logic it invokes is the same one Claude validated above and the automated suite pins independently. Re-run once the account's usage limit resets (reported as 2026-09-21) to close this gap with real evidence.

The launch commands were:

```sh
claude -p "$PROMPT" --dangerously-skip-permissions --output-format text
codex exec --dangerously-bypass-hook-trust --dangerously-bypass-approvals-and-sandbox --skip-git-repo-check "$PROMPT"
```

## Known residual gaps

- Raw `docker exec ... psql` writes and package-runner indirection (`npx supabase ...`) are out of scope by design; see "Out of scope by design" above.
- Codex's live harness-level behavior for this specific hook is attempted but not yet confirmed (account usage limit); see the validation record above.
- Grok, OpenCode, Pi, and Cursor are not yet wired; see the harness/backend coverage review above for the bounded, mechanical follow-up each needs.
- A related but separate finding from the same audit: the class-one project's `holdsCorpusData(process.cwd())` check (`scripts/db/safe-reset-local.mjs:198`, `scripts/lib/stack-identity.mjs:89-91`) only checks the exact working directory for `supabase/seed/corpus.sql`, while the real `supabase` CLI walks upward for `supabase/config.toml`, so a direct `node` invocation from a subdirectory of a corpus-holding lane can waive the corpus check by accident. This is a class-one project fix and is out of scope here; it is recorded so it is not lost.
