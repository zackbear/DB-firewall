import { queryRows } from "./adapters.js";

/**
 * Throw unless the connection's role is one RLS applies to. A superuser or a
 * BYPASSRLS role skips every policy, and a role in _firewall_bypass_roles
 * passes the firewall's policies, so tenant scoping would silently do nothing.
 * Also throws when the DB Firewall migration is not installed. Call it once at
 * start-up with the same client the app uses.
 */
export async function assertSafeRole(db: unknown): Promise<void> {
  let rows: any[];
  try {
    rows = await queryRows(db,
      "SELECT r.rolname, r.rolsuper, r.rolbypassrls, " +
      "public._firewall_is_bypass_role(current_user::text) AS fw_bypass " +
      "FROM pg_roles r WHERE r.rolname = current_user");
  } catch (err) {
    if (err instanceof TypeError) throw err;        // unsupported client: say so, not "migration"
    throw new Error("DB Firewall: could not check the role; is migrations/001_postgresql.sql " +
                    `installed? (${(err as Error).message})`);
  }
  const role = rows[0];
  if (!role) throw new Error("DB Firewall: current role not found in pg_roles");
  const why = role.rolsuper ? "is a superuser"
    : role.rolbypassrls ? "has BYPASSRLS"
    : role.fw_bypass ? "is in _firewall_bypass_roles"
    : undefined;
  if (why) {
    throw new Error(`DB Firewall: role ${role.rolname} ${why}, so row-level security does not ` +
                    "apply to it. Connect the app as a normal role.");
  }
}
