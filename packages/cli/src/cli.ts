#!/usr/bin/env node
// db-firewall: migrate | scan | verify, for PostgreSQL.
import { parseArgs } from "node:util";
import pg from "pg";
import { TENANT_KEY_ENV, tenantKey } from "./key.js";
import { migrate } from "./migrate.js";
import { scan, type Context, type ScanResult, type TableReport } from "./scan.js";
import { verify, type Check } from "./verify.js";

const USAGE = `Usage: db-firewall <command> [options]

Commands:
  migrate   Install the tenant RLS policies (run as an admin role)
  scan      Report which tables with the tenant column are protected
  verify    Connect as your app's role and test the isolation (needs --tenant
            and DB_FIREWALL_TENANT_KEY)
  key       Print the database's tenant signing key (run as an admin role)

Options:
  --url <url>        PostgreSQL URL (default: $DATABASE_URL)
  --column <name>    Tenant column (default: tenant_id)
  --schema <name>    Schema (default: public; repeatable)
  --mode <mode>      migrate: permissive (default) or restrictive
  --context <ctx>    migrate/scan: signed (default) or plain. Signed: the app signs
                     the tenant per transaction with DB_FIREWALL_TENANT_KEY, so SQL
                     it runs cannot switch tenants. migrate installs that key when
                     set, else keeps the database's key or generates one.
  --harden-signals   migrate: revoke pg_terminate_backend / pg_cancel_backend from
                     PUBLIC in this database (needs a superuser), so tenants sharing
                     the app role cannot end each other's requests
  --harden           migrate: also revoke CREATE on the database and every schema,
                     TRIGGER and TRUNCATE on every table (default privileges
                     too), and pg_stat_activity, from PUBLIC and --app-role, by
                     any grantor (what verify fails on); needs a superuser.
                     Refuses if --app-role owns the database, a schema or a table
  --app-role <name>  migrate --harden: the app's role, revoked from as well
  --tenant <id>      verify: a tenant id that has rows in your data
  --write-probe      verify: also try a cross-tenant insert (rolled back, but it
                     fires BEFORE INSERT triggers and uses up a sequence value)
  --exclude <glob>   scan/verify: skip tables matching (repeatable; replaces the
                     defaults, which are the tables the migration skips)
  --strict           scan: exit 1 if any table is unprotected or none is found.
                     verify: also fail on anything the app role can read that is
                     not protected tenant data, and on SECURITY DEFINER functions
  --allow-global <glob>  verify --strict: schema.name of a table, view or
                     sequence, or schema.name(argtypes) of a function, that the
                     app may reach without tenant scoping (shared reference
                     data, say); repeatable
  --json             machine-readable output
  -h, --help

Exit codes: 0 ok; 1 a check failed (scan --strict: a table is unprotected or
none found); 2 usage or connection error; 3 verify: no failure, but a check was
inconclusive.
`;

async function main(argv: string[]): Promise<number> {
  const { values, positionals } = parseArgs({
    args: argv, allowPositionals: true,
    options: {
      url: { type: "string" }, column: { type: "string" }, schema: { type: "string", multiple: true },
      "write-probe": { type: "boolean" }, "harden-signals": { type: "boolean" },
      harden: { type: "boolean" }, "app-role": { type: "string" },
      "allow-global": { type: "string", multiple: true },
      mode: { type: "string" }, context: { type: "string" }, tenant: { type: "string" },
      exclude: { type: "string", multiple: true },
      strict: { type: "boolean" }, json: { type: "boolean" }, help: { type: "boolean", short: "h" },
    },
  });
  const command = positionals[0];
  if (values.help || !command) { process.stdout.write(USAGE); return command || values.help ? 0 : 2; }
  const url = values.url ?? process.env.DATABASE_URL;
  if (!url) { process.stderr.write("db-firewall: --url or DATABASE_URL is required\n"); return 2; }
  const context = (values.context ?? "signed").toLowerCase();
  if (context !== "signed" && context !== "plain") {
    process.stderr.write(`db-firewall: --context must be signed or plain, got ${values.context}\n`); return 2;
  }
  let key: Buffer | undefined;
  try { key = tenantKey(); } catch (err) { process.stderr.write(`db-firewall: ${(err as Error).message}\n`); return 2; }
  if (command === "verify" && !key) {
    process.stderr.write(`db-firewall verify: set ${TENANT_KEY_ENV} to the key your app uses ` +
                         "(db-firewall key prints the database's key)\n");
    return 2;
  }
  const common = { schemas: values.schema, column: values.column, exclude: values.exclude, context: context as Context };

  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    if (command === "migrate") {
      for (const schema of values.schema?.length ? values.schema : ["public"]) {
        await migrate(client, { schema, column: values.column, mode: values.mode, context,
                                hardenSignals: values["harden-signals"], harden: values.harden,
                                appRole: values["app-role"] });
      }
      const result = await scan(client, common);
      print(values.json, { migrated: true, ...result }, () => `Migration applied. ` +
        `${result.tables.filter((t) => t.protected).length} of ${result.tables.length} tables protected.\n` +
        tablesText(result));
      return 0;
    }
    if (command === "key") {
      const { rows } = await client.query("SELECT encode(key, 'hex') AS key FROM public._firewall_keys");
      if (!rows.length) { process.stderr.write("db-firewall: no key: run migrate first\n"); return 1; }
      process.stdout.write(`${rows[0].key}\n`);
      return 0;
    }
    if (command === "scan") {
      const result = await scan(client, common);
      print(values.json, result, () => tablesText(result));
      return values.strict && (!result.tables.length || result.tables.some((t) => !t.protected)) ? 1 : 0;
    }
    if (command === "verify") {
      if (!values.tenant) { process.stderr.write("db-firewall verify: --tenant is required\n"); return 2; }
      if (values["allow-global"]?.length && !values.strict) {
        process.stderr.write("db-firewall verify: --allow-global needs --strict\n"); return 2;
      }
      const result = await verify(client, { ...common, tenant: values.tenant, key: key!,
                                            writeProbe: values["write-probe"], strict: values.strict,
                                            allowGlobal: values["allow-global"] });
      const failed = result.checks.filter((c) => c.ok === false).length;
      const unsure = result.checks.filter((c) => c.ok === null).length;
      print(values.json, result, () => checksText(result.checks) + skippedText(result.excluded) +
        (failed ? `\n${failed} check(s) FAILED${unsure ? `, ${unsure} inconclusive` : ""}.\n`
          : unsure ? `\nNo failures, but ${unsure} check(s) inconclusive: not a pass.\n`
          : "\nAll checks passed.\n"));
      return failed ? 1 : unsure ? 3 : 0;
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

function tablesText({ tables, excluded }: ScanResult): string {
  if (!tables.length) return "FAIL  no tables with the tenant column (wrong --column or --schema?)\n" +
    skippedText(excluded);
  return tables.map((t) => `${t.protected ? "OK  " : "FAIL"}  ${t.schema}.${t.table}  (${t.policy_mode}, ` +
    `${t.tenant_context ?? "no policies"}` +
    (t.protected ? ")" : `; ${reasons(t)})`) +
    (t.stale_base_policy ? "  warning: stale base policy, re-run migrate" : "")).join("\n") + "\n" +
    skippedText(excluded);
}

function skippedText(excluded: string[]): string {
  return excluded.length ? `Skipped (excluded): ${excluded.join(", ")}\n` : "";
}

function reasons(t: TableReport): string {
  const r = [];
  if (t.tenant_context === "plain") r.push("plain tenant context, expected signed (re-run migrate, or scan --context plain)");
  if (!t.rls_enabled) r.push("RLS off");
  else if (!t.rls_forced) r.push("RLS not forced");
  if (t.missing_policies.length) r.push(`missing ${t.missing_policies.join(",")}`);
  if (t.altered_policies.length && t.tenant_context !== "plain") r.push(`altered ${t.altered_policies.join(",")}`);
  if (t.policy_mode === "permissive" && t.extra_permissive_policies.length) {
    r.push(`extra permissive ${t.extra_permissive_policies.join(",")}`);
  }
  if (t.predicate_check !== "ok") r.push(t.predicate_check);
  return r.join("; ");
}

function checksText(checks: Check[]): string {
  return checks.map((c) => `${c.ok === true ? "OK  " : c.ok === false ? "FAIL" : "--  "}  ` +
    `${c.table.padEnd(24)} ${c.check.padEnd(36)} ${c.detail}`).join("\n") + "\n";
}

main(process.argv.slice(2)).then((code) => { process.exitCode = code; }, (err) => {
  process.stderr.write(`db-firewall: ${(err as Error).message}\n`);
  process.exitCode = 2;
});
