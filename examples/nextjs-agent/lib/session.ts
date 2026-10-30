// A demo login: a signed, HTTP-only cookie that names the user and their
// tenant. In your app the tenant comes from your own auth (the user's
// organization), never from the request body or the model.
import { SignJWT, jwtVerify } from "jose";

export const COOKIE = "starter_session";

/** The demo users and the tenant each belongs to (see db/seed.sql). */
export const USERS: Record<string, { name: string; tenant: string }> = {
  "alice@acme.test": { name: "Alice (Acme)", tenant: "acme" },
  "bob@globex.test": { name: "Bob (Globex)", tenant: "globex" },
};

function secret(name: string): Uint8Array {
  const v = process.env[name];
  if (!v || Buffer.byteLength(v) < 32) throw new Error(`${name} must be set, at least 32 bytes`);
  return new TextEncoder().encode(v);
}

export async function signSession(email: string): Promise<string> {
  const user = USERS[email];
  if (!user) throw new Error("unknown user");
  return new SignJWT({ tenant: user.tenant }).setProtectedHeader({ alg: "HS256" })
    .setSubject(email).setIssuedAt().setExpirationTime("8h").sign(secret("SESSION_SECRET"));
}

/** The session in the cookie, or null when it is missing or not valid. */
export async function readSession(cookie: string | undefined): Promise<{ email: string; tenant: string } | null> {
  if (!cookie) return null;
  try {
    const { payload } = await jwtVerify(cookie, secret("SESSION_SECRET"), { algorithms: ["HS256"] });
    return typeof payload.sub === "string" && typeof payload.tenant === "string"
      ? { email: payload.sub, tenant: payload.tenant } : null;
  } catch {
    return null;
  }
}

/** A short-lived token for the DB Firewall MCP server: it reads the tenant from tenant_id. */
export function mcpToken(tenant: string): Promise<string> {
  return new SignJWT({ tenant_id: tenant }).setProtectedHeader({ alg: "HS256" })
    .setIssuer("starter").setAudience("db-firewall-mcp").setExpirationTime("5m").sign(secret("MCP_JWT_SECRET"));
}
