import { cookies } from "next/headers";
import { COOKIE, USERS, readSession } from "@/lib/session.ts";
import Chat from "./chat.tsx";

export default async function Page() {
  const session = await readSession((await cookies()).get(COOKIE)?.value);
  if (!session) {
    return (
      <main className="login">
        <h1>DB Firewall agent starter</h1>
        <p>Sign in as one of two demo users. Each belongs to a different company (tenant). The agent
          queries the same tables for both, and PostgreSQL shows each user only their own company&apos;s rows.</p>
        <form action="/api/login" method="post">
          {Object.entries(USERS).map(([email, u]) => (
            <button key={email} name="email" value={email}>{u.name}</button>
          ))}
        </form>
      </main>
    );
  }
  return (
    <main className="app">
      <header>
        <span>{USERS[session.email]?.name ?? session.email} · tenant <code>{session.tenant}</code></span>
        <form action="/api/logout" method="post"><button>Sign out</button></form>
      </header>
      <Chat />
    </main>
  );
}
