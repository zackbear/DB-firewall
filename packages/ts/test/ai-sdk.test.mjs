// bindTenant with the real AI SDK: a mock model calls the tool; the tool's
// query runs as the tenant the server bound, whatever the model sends.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { generateText, tool } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { z } from "zod";
import { bindTenant, withTenant } from "../dist/index.js";
import { SCHEMA, appUrl, live, setup } from "./setup.mjs";

const usage = {
  inputTokens: { total: 1, noCache: 1, cacheRead: undefined, cacheWrite: undefined },
  outputTokens: { total: 1, text: 1, reasoning: undefined },
};

// The model asks for listDocs and tries to name tenant B in its arguments.
const model = () => new MockLanguageModelV4({
  doGenerate: async () => ({
    content: [{ type: "tool-call", toolCallId: "c1", toolName: "listDocs",
                input: JSON.stringify({ search: "", tenant_id: "B" }) }],
    finishReason: { unified: "tool-calls", raw: undefined },
    usage, warnings: [],
  }),
});

describe("AI SDK generateText", live, () => {
  let pool;
  before(async () => { await setup(); pool = new pg.Pool({ connectionString: appUrl(), max: 2 }); });
  after(async () => { await pool?.end(); });

  const tools = {
    listDocs: tool({
      description: "List documents",
      inputSchema: z.object({ search: z.string() }).passthrough(),   // let the model's extra key through
      execute: async (input) => {
        const rows = await withTenant(pool, async (c) =>
          (await c.query(`SELECT id FROM ${SCHEMA}.docs`)).rows);
        return { seen: input.tenant_id, ids: rows.map((r) => r.id) };
      },
    }),
  };

  it("each request's tool call runs as the bound tenant", async () => {
    const run = (tenant) => generateText({ model: model(), tools: bindTenant(tools, tenant), prompt: "list" });
    const [a, b] = await Promise.all([run("A"), run("B")]);
    assert.deepEqual(a.toolResults[0].output, { seen: "B", ids: [1] });   // asked for B, got A
    assert.deepEqual(b.toolResults[0].output, { seen: "B", ids: [2] });
  });

  it("unbound tools fail the call (no tenant)", async () => {
    const r = await generateText({ model: model(), tools, prompt: "list" });
    const err = r.steps[0].content.find((p) => p.type === "tool-error");
    assert.match(String(err?.error), /no tenant/);
  });
});
