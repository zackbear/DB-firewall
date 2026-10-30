import { COOKIE, USERS, signSession } from "@/lib/session.ts";

export async function POST(req: Request) {
  const email = String((await req.formData()).get("email") ?? "");
  if (!USERS[email]) return new Response("Unknown demo user", { status: 400 });
  const res = new Response(null, { status: 303, headers: { location: "/" } });
  res.headers.append("set-cookie",
    `${COOKIE}=${await signSession(email)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800` +
    (process.env.NODE_ENV === "production" ? "; Secure" : ""));
  return res;
}
