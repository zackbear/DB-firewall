// The shared PostgreSQL checks (checks/postgresql.sql in the repository,
// shipped as sql/checks_postgresql.sql): the Python tools run the same file.
import { readFileSync } from "node:fs";

export const CHECKS_FILE = new URL("../sql/checks_postgresql.sql", import.meta.url);

export interface GlobalCheck { name: string; info: boolean; sql: string }
export interface Checks {
  /** The tables the migration skips. */
  excluded: string[];
  /** @check and @info blocks, in file order. */
  checks: GlobalCheck[];
  queries: Record<string, string>;
}

/** Parse the file: "-- @excluded", "-- @check", "-- @info" and "-- @query"
 *  lines start a block, which runs to the next "-- @" line. */
export function parseChecks(text: string): Checks {
  const out: Checks = { excluded: [], checks: [], queries: {} };
  let cur: { kind: string; name: string; lines: string[] } | null = null;
  const flush = () => {
    if (!cur) return;
    const sql = cur.lines.join("\n").trim();
    if (!sql) throw new Error(`checks: ${cur.name} has no SQL`);
    if (cur.kind === "query") {
      if (out.queries[cur.name]) throw new Error(`checks: a second @query ${cur.name}`);
      out.queries[cur.name] = sql;
    } else out.checks.push({ name: cur.name, info: cur.kind === "info", sql });
  };
  for (const line of text.replace(/\r\n/g, "\n").split("\n")) {
    // Comment lines stay out of the SQL: a "$1" in one is no parameter.
    if (!line.startsWith("-- @")) { if (!line.trimStart().startsWith("--")) cur?.lines.push(line); continue; }
    const m = line.match(/^-- @(excluded|check|info|query) (\S.*)$/);
    if (!m) throw new Error(`checks: unknown line ${line}`);
    flush();
    cur = null;
    if (m[1] === "excluded") out.excluded.push(...m[2]!.trim().split(/\s+/));
    else cur = { kind: m[1]!, name: m[2]!.trim(), lines: [] };
  }
  flush();
  return out;
}

let cached: Checks | undefined;
export const CHECKS = (): Checks => (cached ??= parseChecks(readFileSync(CHECKS_FILE, "utf8")));

/** A named query from the file. */
export function q(name: string): string {
  const sql = CHECKS().queries[name];
  if (!sql) throw new Error(`checks: no @query ${name}`);
  return sql;
}
