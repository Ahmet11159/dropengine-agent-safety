# dropengine-agent-safety

Safety checks for AI agents, one call each, before the agent:

- **opens a URL** → `checkUrl()`
- **acts on text it did not write** (web pages, emails, documents, other tools' output) → `scanContent()` for prompt injection
- **installs an npm package** → `checkPackage()` for malware, known vulnerabilities, typosquatting and install scripts
- **takes any other risky action** → `preflightAction()` for one combined allow / warn / block decision

There is no account and no API key. Each call is paid with [x402](https://x402.org) in USDC on Base, from $0.005. The package has zero dependencies.

## Install

```bash
npm install dropengine-agent-safety @x402/fetch @x402/evm viem
```

Requires Node.js 20 or newer (or any runtime with `fetch` and `AbortSignal.timeout`). `@x402/fetch`, `@x402/evm` and `viem` are only needed for paying. The SDK accepts any `fetch` that can pay x402 challenges.

## Quick start

```ts
import { createAgentSafety, assertSafe } from "dropengine-agent-safety";
import { x402Client, wrapFetchWithPayment } from "@x402/fetch";
import { registerExactEvmScheme } from "@x402/evm/exact/client";
import { privateKeyToAccount } from "viem/accounts";

// A dedicated, low-balance wallet for your agent. Never use a treasury key.
const signer = privateKeyToAccount(process.env.AGENT_WALLET_KEY as `0x${string}`);
const client = new x402Client();
registerExactEvmScheme(client, { signer });
client.setSpendControls({ maxAmountPerPayment: "$0.05" }); // hard cap per call

const safety = createAgentSafety({ fetch: wrapFetchWithPayment(fetch, client) });

const verdict = await safety.checkUrl("https://example.com/login");
if (verdict.action === "block") throw new Error(verdict.reasons.join("; "));

// or let assertSafe throw on "block" (and on "warn" with { strict: true })
assertSafe(await safety.checkPackage("left-pad"), { strict: true });
```

Every method returns the same normalized shape:

```ts
{
  check: "check_url" | "scan_content" | "check_package" | "preflight_action",
  action: "allow" | "warn" | "block",   // unrecognized service values map to "warn", never "allow"
  riskScore: number | null,              // 0-100; null for preflightAction
  reasons: string[],                     // short, safe to show to a user or a model
  degraded: boolean,                     // true when part of the evidence was unavailable
  raw: { ... }                           // the full service response
}
```

`scanContent()` also returns `sanitizedContent`: the text with detected instructions neutralized, when the service provides it.

## API

| Method | Use it before | Price |
|---|---|---|
| `checkUrl(url)` | opening, fetching or clicking a URL | $0.005 |
| `scanContent(content, { contentType?, source? })` | following instructions found in external text | $0.005 |
| `checkPackage(name, { version? })` | `npm install` | $0.005 |
| `preflightAction({ action_type, intent, target, context? })` | a risky action; runs the relevant checks server-side | $0.02 |

`contentType` is one of `text`, `html`, `markdown`, `email`, `tool_output`, `api_response`, `document_text`.
`action_type` is one of `tool_call`, `install_package`, `open_url`, `use_external_content`, `wallet_interaction`, `transaction`, `token_interaction`, `purchase`, `custom`.

Prices are set by the service. The live 402 offer is authoritative, and your x402 client's spend controls decide what is paid.

Options for `createAgentSafety({ ... })`:

| Option | Default | |
|---|---|---|
| `fetch` | global `fetch` | Pass an x402-paying fetch. Without one, every call throws `PaymentRequiredError` with the price. |
| `baseUrl` | `https://mcp.dropenginehq.com` | |
| `timeoutMs` | `20000` | |
| `agentId` | none | Optional stable id for your agent; the service stores only a keyed hash. |

## Use as LLM tools

`createSafetyTools(safety)` returns four framework-neutral tools (`check_url_safety`, `scan_untrusted_content`, `check_npm_package`, `preflight_agent_action`). Each one has a name, a description, a JSON Schema for its parameters and an `execute` function. The tools never throw into the model loop. When a check cannot complete they return `action: "unknown"` and tell the model to treat the target as unverified.

**OpenAI function calling**

```ts
import { createSafetyTools } from "dropengine-agent-safety";

const safetyTools = createSafetyTools(safety);
const tools = safetyTools.map((t) => ({ type: "function", function: { name: t.name, description: t.description, parameters: t.parameters } }));
// when the model calls one:
const result = await safetyTools.find((t) => t.name === call.function.name)!.execute(JSON.parse(call.function.arguments));
```

**Vercel AI SDK**

```ts
import { tool, jsonSchema } from "ai";

const tools = Object.fromEntries(createSafetyTools(safety).map((t) => [
  t.name,
  tool({ description: t.description, inputSchema: jsonSchema(t.parameters), execute: t.execute }),
]));
```

Expose only what you need with `createSafetyTools(safety, { include: ["check_npm_package"] })`.

## Errors and payment state

Every failure is an `AgentSafetyError` with a `code`, an HTTP `status` and a `paymentState`:

| `paymentState` | Meaning | What to do |
|---|---|---|
| `not_charged` | Rejected before payment (invalid input, or `PaymentRequiredError`) | Fix the input or the payment setup; retrying is safe |
| `charged` | Payment settled but the check failed | Do not assume the target is safe |
| `unknown` | Timeout, network error, or the service could not confirm both settlement and result | Check your wallet before retrying |

`PaymentRequiredError.quote` holds the price (`amountUsd`, `network`, `asset`, `payTo`).

## What is sent

The URL, text, package name or action description you pass is sent to `mcp.dropenginehq.com` for analysis. A request also carries `X-Attribution-Source: sdk`, which carries no identity, and `X-Agent-Id` if you set `agentId`. The payment itself reveals your agent wallet's address, as every on-chain payment does. Do not send secrets or personal data in content you scan.

## Without the SDK

The same checks are available as an MCP server at `https://mcp.dropenginehq.com/api/agent-services` and as plain x402 HTTP endpoints described in `https://mcp.dropenginehq.com/openapi.json`.

## License

MIT
