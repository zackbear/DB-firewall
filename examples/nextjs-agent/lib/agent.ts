// The agent: Claude with the DB Firewall MCP server's tools. Each request
// gets a token for the signed-in user's tenant, so every tool call runs as
// that tenant inside PostgreSQL. The model never chooses the tenant.
import { createMCPClient } from "@ai-sdk/mcp";
import { anthropic } from "@ai-sdk/anthropic";
import { isStepCount, streamText, type LanguageModel, type ModelMessage } from "ai";
import { mcpToken } from "./session.ts";

const INSTRUCTIONS = `You answer questions about the user's company data in PostgreSQL.
Use list_tables and describe_table to learn the schema, then query with SQL.
You only ever see the user's own company: say so if asked about other companies.`;

export async function runAgent({ tenant, messages, model }: {
  tenant: string; messages: ModelMessage[]; model?: LanguageModel;
}) {
  const mcp = await createMCPClient({ transport: {
    type: "http", url: process.env.MCP_URL ?? "http://127.0.0.1:3333/mcp",
    headers: { authorization: `Bearer ${await mcpToken(tenant)}` } } });
  try {
    return streamText({
      model: model ?? anthropic(process.env.ANTHROPIC_MODEL ?? "claude-sonnet-5-5"),
      instructions: INSTRUCTIONS,
      messages,
      tools: await mcp.tools(),
      stopWhen: isStepCount(6),
      onFinish: ({ text, toolCalls, finishReason, rawFinishReason }) => {
        // A reply with no text and no tool call shows as an empty bubble: say why in the server log.
        if (!text && !toolCalls.length) console.warn(`agent: empty reply (finish reason: ${finishReason}, raw: ${rawFinishReason})`);
        return mcp.close();
      },
      onError: () => mcp.close(),
      onAbort: () => mcp.close(),
    });
  } catch (e) {
    await mcp.close();
    throw e;
  }
}
