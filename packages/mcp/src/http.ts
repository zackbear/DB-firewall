// Streamable HTTP, stateless: each request is a POST with a bearer token (a
// JWT), and the tenant comes from a claim in it after the signature, expiry,
// issuer and audience check out. A new server, bound to that tenant, serves
// that one request. No token, or a bad one: 401, and nothing runs. GET and
// DELETE (a stream, a session) have no use without sessions: 405.
import http from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose";
import { createServer, type ServerOptions } from "./server.js";

export interface HttpOptions extends ServerOptions {
  port: number;
  /** Default 127.0.0.1: put TLS and the public address in front of it. */
  host?: string;
  /** HS256 secret (at least 32 bytes), or the JWKS URL of an identity provider. One of the two. */
  jwtSecret?: string;
  jwksUrl?: string;
  /** The iss and aud tokens must carry. Both required: without them, any token from a shared identity provider would do. */
  issuer: string;
  audience: string;
  /** The claim that holds the tenant (default tenant_id). */
  tenantClaim?: string;
}

const MAX_BODY = 1 << 20;

function verifier(opts: HttpOptions): (token: string) => Promise<string> {
  if (!!opts.jwtSecret === !!opts.jwksUrl) throw new Error("DB Firewall MCP: give a JWT secret or a JWKS URL (one)");
  if (!opts.issuer || !opts.audience) {
    throw new Error("DB Firewall MCP: give the issuer and the audience the tokens must carry (--issuer, --audience)");
  }
  if (opts.jwtSecret && Buffer.byteLength(opts.jwtSecret) < 32) {
    throw new Error("DB Firewall MCP: the JWT secret must be at least 32 bytes");
  }
  const key: Uint8Array | JWTVerifyGetKey = opts.jwtSecret
    ? new TextEncoder().encode(opts.jwtSecret) : createRemoteJWKSet(new URL(opts.jwksUrl!));
  const algorithms = opts.jwtSecret ? ["HS256"] : ["RS256", "PS256", "ES256", "EdDSA"];
  const claim = opts.tenantClaim ?? "tenant_id";
  return async (token) => {
    const { payload } = await jwtVerify(token, key as any, {
      algorithms, issuer: opts.issuer, audience: opts.audience, requiredClaims: ["exp"],
    });
    const tenant = payload[claim];
    if (typeof tenant !== "string" || !tenant) throw new Error(`no ${claim} claim`);
    return tenant;
  };
}

function readBody(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const parts: Buffer[] = [];
    req.on("data", (b: Buffer) => {
      size += b.length;
      if (size > MAX_BODY) { reject(new Error("body too large")); req.destroy(); } else parts.push(b);
    });
    req.on("end", () => {
      if (!parts.length) return resolve(undefined);
      try { resolve(JSON.parse(Buffer.concat(parts).toString("utf8"))); } catch { reject(new Error("bad JSON")); }
    });
    req.on("error", reject);
  });
}

function fail(res: http.ServerResponse, status: number, message: string) {
  res.writeHead(status, { "content-type": "application/json",
                          ...(status === 401 ? { "www-authenticate": "Bearer" } : {}) });
  res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message }, id: null }));
}

/** Start the HTTP server on /mcp. Resolves once it listens. */
export async function startHttp(opts: HttpOptions): Promise<http.Server> {
  const verify = verifier(opts);
  const server = http.createServer(async (req, res) => {
    if (new URL(req.url ?? "/", "http://x").pathname !== "/mcp") return fail(res, 404, "not found");
    if (req.method !== "POST") { res.setHeader("allow", "POST"); return fail(res, 405, "method not allowed: POST only"); }
    const auth = req.headers.authorization ?? "";
    let tenant: string;
    try {
      if (!auth.startsWith("Bearer ")) throw new Error("no bearer token");
      tenant = await verify(auth.slice(7));
    } catch {
      return fail(res, 401, "DB Firewall MCP: a valid bearer token is required");   // no detail: no oracle
    }
    try {
      const body = await readBody(req);
      const mcp = createServer(opts, tenant);
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
      res.on("close", () => { transport.close().catch(() => {}); mcp.close().catch(() => {}); });
      await mcp.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch (e) {
      if (!res.headersSent) fail(res, 400, (e as Error).message);
    }
  });
  await new Promise<void>((resolve) => server.listen(opts.port, opts.host ?? "127.0.0.1", resolve));
  return server;
}
