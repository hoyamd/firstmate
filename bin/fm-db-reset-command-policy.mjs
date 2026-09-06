#!/usr/bin/env node
// Semantic policy for raw supabase database-reset shell commands.
//
// A guarded wrapper (a project's own scripts/db/safe-reset-local.mjs, run
// through pnpm db:reset or node directly) refuses to reset, push to, or
// migrate a database stack it cannot verify is safe. That guard is opt-in: an
// agent can still shell out to the raw `supabase db reset`, `supabase db
// push`, or `supabase migration up` and bypass it entirely. This policy
// denies exactly that class of direct invocation.
//
// The shell tokenizer, command-position analysis, and nested-execution-payload
// extraction are imported from bin/fm-arm-command-policy.mjs, the sole owner
// of firstmate's shell classification, so this guard never duplicates shell
// lexing. This policy never evaluates, expands, sources, or runs any byte of
// the submitted command; it inspects lexical command positions only.
// See docs/db-reset-guard.md for the full contract.

import {
  Lexer,
  splitProgram,
  commandPosition,
  shellInvocation,
  evalPayload,
  shellHeredocPayloads,
  shellHereStringPayloads,
} from "./fm-arm-command-policy.mjs";
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

const REASONS = {
  "db-reset-direct":
    "a direct `supabase db reset` bypasses the project's guarded reset wrapper, which refuses to reset a database stack it cannot verify is safe (a primary or corpus-holding stack needs an explicit human override). Run the project's guarded wrapper instead - for example `pnpm db:reset` or `node scripts/db/safe-reset-local.mjs` - never the raw supabase CLI.",
  "db-push-direct":
    "a direct `supabase db push` bypasses the same guarded safety check a raw reset does. Run the project's guarded wrapper instead of the raw supabase CLI.",
  "migration-up-direct":
    "a direct `supabase migration up` bypasses the same guarded safety check. Run the project's guarded wrapper instead of the raw supabase CLI.",
  "unclassifiable-db-command":
    "unsupported or malformed shell syntax contains a guarded supabase database command (db reset, db push, or migration up) and cannot be safely classified",
};

// Compound constructs this classifier does not model. Their presence alongside
// a raw mention of a guarded command fails closed, mirroring the
// broad-watcher-kill backstop in bin/fm-arm-command-policy.mjs.
const COMPOUND_KEYWORDS = new Set([
  "if", "then", "else", "elif", "fi", "for", "while", "until", "case", "esac", "do", "done", "function", "time", "coproc",
]);

function normalizeLineContinuations(source) {
  return source.replace(/\\\r?\n/g, "");
}

// Cheap raw-byte fallback used only when the command cannot be fully
// classified (a lex error, unsupported compound grammar, or recursion depth).
// It never itself denies a command that classifies cleanly as safe.
function rawMentionsDbCommand(command) {
  const normalized = normalizeLineContinuations(command);
  if (!/\bsupabase\b/.test(normalized)) return false;
  if (/\bdb\b/.test(normalized) && /\breset\b/.test(normalized)) return true;
  if (/\bdb\b/.test(normalized) && /\bpush\b/.test(normalized)) return true;
  if (/\bmigration\b/.test(normalized) && /\bup\b/.test(normalized)) return true;
  return false;
}

function basename(value) {
  return value.split("/").filter(Boolean).at(-1) || value;
}

// The supabase CLI (Cobra-based) always keeps a subcommand's group and leaf
// words adjacent - `db reset`, `db push`, `migration up` - with any flags
// (and their values) surrounding that pair rather than splitting it. Flag
// values that are not themselves prefixed by `-` can still appear as extra
// positional-looking words elsewhere in the list; scanning for the adjacent
// pair anywhere, rather than requiring it at a fixed position, tolerates that
// without losing precision.
function matchDbCommand(position) {
  if (!position.command) return "";
  if (basename(position.command.value) !== "supabase") return "";
  const positional = [];
  for (const word of position.words.slice(position.index + 1)) {
    if (word.value.startsWith("-")) continue;
    positional.push(word.value);
  }
  for (let i = 0; i < positional.length - 1; i += 1) {
    if (positional[i] === "db" && positional[i + 1] === "reset") return "db-reset-direct";
    if (positional[i] === "db" && positional[i + 1] === "push") return "db-push-direct";
    if (positional[i] === "migration" && positional[i + 1] === "up") return "migration-up-direct";
  }
  return "";
}

// Recursively finds a deny code anywhere the submitted text could actually
// execute: the top-level command list, subshell/brace groups, command and
// process substitutions, and literal (non-dynamic) sh/bash/zsh -c payloads,
// eval payloads, heredoc bodies, and here-strings. Opaque dynamic dataflow -
// a variable built from parts and later fed to eval or `bash -c "$VAR"` -
// cannot be proven statically and remains out of scope, exactly as
// bin/fm-arm-command-policy.mjs documents for the same class of construct.
function analyze(command, depth = 0) {
  if (depth > 12) {
    return { error: "recursion limit", found: rawMentionsDbCommand(command) ? "unclassifiable-db-command" : "" };
  }
  const lexed = new Lexer(command).tokenize();
  if (lexed.error) {
    return { error: lexed.error, found: rawMentionsDbCommand(command) ? "unclassifiable-db-command" : "" };
  }
  const { nodes } = splitProgram(lexed.tokens);
  let found = "";
  let unsupported = false;

  for (const tokens of nodes) {
    const position = commandPosition(tokens);
    const firstName = basename(position.words[0]?.value || "");
    if (COMPOUND_KEYWORDS.has(firstName)) unsupported = true;
    if (position.unresolvedWrapperOption) unsupported = true;

    const nestedTexts = [];
    for (const token of tokens) {
      if (token.type === "group") nestedTexts.push(token.content);
      if (token.type === "word") {
        for (const sub of token.subs) nestedTexts.push(sub.content);
      }
    }
    const shell = shellInvocation(position);
    if (shell?.kind === "command" && shell.payload?.literal && shell.payload.subs.length === 0) {
      nestedTexts.push(shell.payload.value);
    }
    const literalEvalPayload = evalPayload(position);
    if (literalEvalPayload !== null) nestedTexts.push(literalEvalPayload);
    for (const payload of shellHeredocPayloads(tokens, position)) nestedTexts.push(payload);
    for (const payload of shellHereStringPayloads(tokens, position)) nestedTexts.push(payload);

    for (const text of nestedTexts) {
      const nested = analyze(text, depth + 1);
      if (nested.found && !found) found = nested.found;
      if (nested.error && rawMentionsDbCommand(text)) unsupported = true;
    }

    const direct = matchDbCommand(position);
    if (direct && !found) found = direct;
  }

  if (unsupported && (found || rawMentionsDbCommand(command))) {
    return { error: "unsupported compound grammar", found: found || "unclassifiable-db-command" };
  }
  return { error: "", found };
}

function deny(code) {
  return { decision: "deny", code, reason: REASONS[code] };
}

function decision(command) {
  const analysis = analyze(command);
  if (!analysis.found) return { decision: "allow" };
  return deny(analysis.found);
}

function parseArguments(argv) {
  const result = { command: "", commandSet: false };
  for (let i = 0; i < argv.length; i += 1) {
    const name = argv[i];
    if (name === "--command") {
      if (i + 1 >= argv.length) throw new Error("--command requires a value");
      result.command = argv[i + 1];
      result.commandSet = true;
      i += 1;
      continue;
    }
    if (name.startsWith("--command=")) {
      result.command = name.slice("--command=".length);
      result.commandSet = true;
      continue;
    }
    throw new Error(`unknown argument: ${name}`);
  }
  return result;
}

function invokedDirectly() {
  const entry = process.argv[1];
  if (!entry) return false;
  const self = fileURLToPath(import.meta.url);
  try {
    return realpathSync(entry) === realpathSync(self);
  } catch {
    return entry === self;
  }
}

if (invokedDirectly()) {
  try {
    const args = parseArguments(process.argv.slice(2));
    if (!args.commandSet || !args.command) {
      process.stdout.write("allow\n");
    } else {
      const result = decision(args.command);
      if (result.decision === "allow") {
        process.stdout.write("allow\n");
      } else {
        process.stdout.write(`deny\t${result.code}\t${result.reason}\n`);
      }
    }
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}

export { decision };
