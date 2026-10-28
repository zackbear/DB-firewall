#!/usr/bin/env node
// db-firewall: migrate | scan | verify, for PostgreSQL.
import { parseArgs } from "node:util";
import pg from "pg";
import { migrate } from "./migrate.js";
import { scan, type TableReport } from "./scan.js";
import { verify, type Check } from "./verify.js";

const USAGE = `Usage: db-firewall <command> [options]

Commands:
  migrate   Install the tenant RLS policies (run as an admin role)
  scan      Report which tables with the tenant column are protected
  verify    Connect as your app's role and test the isolation (needs --tenant)

Options:
  --url <url>        PostgreSQL URL (default: $DATABASE_URL)
  --column <name>    Tenant column (default: tenant_id)
  --schema <name>    Schema (default: public)
  --mode <mode>      migrate: permissive (default) or restrictive
  --tenant <id>      verify: a tenant id that exists in your data
  --exclude <glob>   scan/verify: skip tables matching (repeatable; replaces the defaults)
  --strict           scan: exit 1 if any table is unprotected
  --json             machine-readable output
  -h, --help

Exit codes: 0 ok; 1 a check failed or (scan --strict) a table is unprotected; 2 usage or connection error.
`;

async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv, allowPositionals: true,
    options: {
      url: { type: "string" }, column: { type: "string" }, schema: { type: "string" },
      mode: { type: "string" }, tenant: { type: "string" }, exclude: { type: "string", multiple: true },
      strict: { type: "boolean" }, json: { type: "boolean" }, help: { type: "boolean", short: "h" },
    },
  });
  const command = positionals[0];
  if (values.help || !command) { process.stdout.write(USAGE); return command || values.help ? 0 : 2; }
  const url = values.url ?? process.env.DATABASE_URL;
  if (!url) { process.stderr.write("db-firewall: --url or DATABASE_URL is required\n"); return 2; }
  const common = { schema: values.schema, column: values.column, exclude: values.exclude };

  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    if (command === "migrate") {
      await migrate(client, { ...common, mode: values.mode });
      const tables = await scan(client, common);
      print(values.json, { migrated: true, tables }, () =>
        `Migration applied. ${tables.filter((t) => t.protected).length} of ${tables.length} tables protected.\n`
        + tablesText(tables));
      return 0;
    }
    if (command === "scan") {
      const tables = await scan(client, common);
      print(values.json, tables, () => tablesText(tables));
      return values.strict && tables.some((t) => !t.protected) ? 1 : 0;
    }
    if (command === "verify") {
      if (!values.tenant) { process.stderr.write("db-firewall verify: --tenant is required\n"); return 2; }
      const result = await verify(client, { ...common, tenant: values.tenant });
      const failed = result.checks.filter((c) => c.ok === false);
      print(values.json, result, () => checksText(result.checks) +
        (failed.length ? `\n${failed.length} check(s) FAILED.\n` : "\nAll checks passed.\n"));
      return failed.length ? 1 : 0;
    }
    process.stderr.write(`db-firewall: unknown command ${command}\n\n${USAGE}`);
    return 2;
  } finally {
    await client.end();
  }
}

function print(json: boolean | undefined, data: unknown, text: () => string): void {
  process.stdout.write(json ? JSON.stringify(data, null, 2) + "\n" : text());
}

function tablesText(tables: TableReport[]): string {
  if (!tables.length) return "No tables with the tenant column.\n";
  return tables.map((t) => `${t.protected ? "OK  " : "FAIL"}  ${t.table}  (${t.policy_mode}` +
    (t.protected ? ")" : `; ${reasons(t)})`) +
    (t.stale_base_policy ? "  warning: stale base policy, re-run migrate" : "")).join("\n") + "\n";
}

function reasons(t: TableReport): string {
  const r = [];
  if (!t.rls_enabled) r.push("RLS off");
  else if (!t.rls_forced) r.push("RLS not forced");
  if (t.missing_policies.length) r.push(`missing ${t.missing_policies.join(",")}`);
  if (t.altered_policies.length) r.push(`altered ${t.altered_policies.join(",")}`);
  if (t.policy_mode === "permissive" && t.extra_permissive_policies.length) {
    r.push(`extra permissive ${t.extra_permissive_policies.join(",")}`);
  }
  if (t.predicate_check !== "ok") r.push(t.predicate_check);
  return r.join("; ");
}

function checksText(checks: Check[]): string {
  return checks.map((c) => `${c.ok === true ? "OK  " : c.ok === false ? "FAIL" : "--  "}  ` +
    `${c.table.padEnd(20)} ${c.check.padEnd(28)} ${c.detail}`).join("\n") + "\n";
}

main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (err) => {
  process.stderr.write(`db-firewall: ${(err as Error).message}\n`);
  process.exitCode = 2;
});
