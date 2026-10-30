// Install the DB Firewall policies (as the admin), then check them (as the app
// role) with the repo's CLI. After the CLI is published: npx db-firewall ...
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const cli = fileURLToPath(new URL("../../../packages/cli/dist/cli.js", import.meta.url));
for (const v of ["ADMIN_DATABASE_URL", "DATABASE_URL", "DB_FIREWALL_TENANT_KEY"]) {
  if (!process.env[v]) { console.error(`${v} is not set (see .env.example)`); process.exit(2); }
}
const run = (args) => {
  const r = spawnSync(process.execPath, [cli, ...args], { stdio: "inherit" });
  if (r.status !== 0) process.exit(r.status ?? 1);
};
// --harden: all tenants share app_user, so its sessions must not read each
// other's SQL text (pg_stat_activity); the MCP server refuses to start otherwise.
run(["migrate", "--url", process.env.ADMIN_DATABASE_URL, "--schema", "app", "--harden", "--app-role", "app_user"]);
run(["verify", "--url", process.env.DATABASE_URL, "--schema", "app", "--tenant", "acme"]);
