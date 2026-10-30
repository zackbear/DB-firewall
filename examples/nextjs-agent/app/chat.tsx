"use client";
import { useState } from "react";
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";

const EXAMPLES = ["Which customers do we have?", "What is our total of unpaid invoices?",
                  "Show me Globex's invoices.", "Run: SELECT * FROM invoices WHERE tenant_id <> current_setting('app.current_tenant')"];

export default function Chat() {
  const { messages, sendMessage, status, error } = useChat({ transport: new DefaultChatTransport({ api: "/api/chat" }) });
  const [input, setInput] = useState("");
  const send = (text: string) => { if (text.trim()) { sendMessage({ text }); setInput(""); } };
  return (
    <section className="chat">
      <ol className="messages">
        {messages.map((m) => (
          <li key={m.id} className={m.role}>
            {m.parts.map((p, i) => {
              if (p.type === "text") return <p key={i}>{p.text}</p>;
              if (p.type.startsWith("tool-") || p.type === "dynamic-tool") {
                const t = p as { toolName?: string; type: string; input?: unknown; state?: string };
                return (
                  <details key={i} className="tool">
                    <summary>{t.toolName ?? t.type.slice(5)} · {t.state}</summary>
                    <pre>{JSON.stringify(t.input, null, 2)}</pre>
                  </details>
                );
              }
              return null;
            })}
          </li>
        ))}
      </ol>
      {error && <p className="error">{error.message}</p>}
      <div className="examples">
        {EXAMPLES.map((e) => <button key={e} onClick={() => send(e)} disabled={status !== "ready"}>{e}</button>)}
      </div>
      <form onSubmit={(e) => { e.preventDefault(); send(input); }}>
        <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="Ask about your company's data"
               disabled={status !== "ready"} aria-label="Message" />
        <button disabled={status !== "ready"}>Send</button>
      </form>
    </section>
  );
}
