import { cookies } from "next/headers";
import { convertToModelMessages, type UIMessage } from "ai";
import { runAgent } from "@/lib/agent.ts";
import { COOKIE, readSession } from "@/lib/session.ts";

export const maxDuration = 60;

export async function POST(req: Request) {
  const session = await readSession((await cookies()).get(COOKIE)?.value);
  if (!session) return new Response("Sign in first", { status: 401 });
  const { messages }: { messages: UIMessage[] } = await req.json();
  const result = await runAgent({ tenant: session.tenant, messages: await convertToModelMessages(messages) });
  return result.toUIMessageStreamResponse();
}
