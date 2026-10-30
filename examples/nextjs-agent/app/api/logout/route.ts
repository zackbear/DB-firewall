import { COOKIE } from "@/lib/session.ts";

export function POST() {
  return new Response(null, { status: 303, headers: { location: "/",
    "set-cookie": `${COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0` } });
}
