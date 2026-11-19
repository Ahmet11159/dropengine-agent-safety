import { describe, expect, it, vi } from "vitest";
import { AgentSafetyError, createSafetyTools, type AgentSafety } from "./index.js";

function stubSafety(overrides: Partial<AgentSafety> = {}): AgentSafety {
  const verdict = { check: "check_url" as const, action: "allow" as const, riskScore: 3, reasons: ["a", "b", "c", "d", "e", "f"], degraded: false, raw: {} as never };
  return {
    checkUrl: vi.fn(async () => verdict),
    scanContent: vi.fn(async () => ({ ...verdict, check: "scan_content" as const, action: "warn" as const, sanitizedContent: "safe text", raw: {} as never })),
    checkPackage: vi.fn(async () => ({ ...verdict, check: "check_package" as const, raw: {} as never })),
    preflightAction: vi.fn(async () => ({ ...verdict, check: "preflight_action" as const, action: "block" as const, riskScore: null, raw: {} as never })),
    ...overrides,
  };
}

describe("createSafetyTools", () => {
  it("exposes four JSON Schema tools with priced descriptions", () => {
    const tools = createSafetyTools(stubSafety());
    expect(tools.map((tool) => tool.name)).toEqual(["check_url_safety", "scan_untrusted_content", "check_npm_package", "preflight_agent_action"]);
    for (const tool of tools) {
      expect(tool.parameters).toMatchObject({ type: "object", additionalProperties: false });
      expect(tool.parameters.required.every((key) => key in tool.parameters.properties)).toBe(true);
      expect(tool.description).toMatch(/\$0\.0\d+ USDC per call/);
    }
  });

  it("returns compact results with at most five reasons", async () => {
    const safety = stubSafety();
    const [url, content, pkg, gate] = createSafetyTools(safety);
    expect(await url.execute({ url: "https://a.example" })).toEqual({ action: "allow", risk_score: 3, reasons: ["a", "b", "c", "d", "e"], degraded: false });
    expect(await content.execute({ content: "x", content_type: "email", source: "inbox" })).toMatchObject({ action: "warn", sanitized_content: "safe text" });
    expect(safety.scanContent).toHaveBeenCalledWith("x", { contentType: "email", source: "inbox" });
    await pkg.execute({ package: "zod", version: "4" });
    expect(safety.checkPackage).toHaveBeenCalledWith("zod", { version: "4" });
    expect(await gate.execute({ action_type: "install_package", intent: "install zod", package: "zod" })).toMatchObject({ action: "block", risk_score: null });
    expect(safety.preflightAction).toHaveBeenCalledWith({ action_type: "install_package", intent: "install zod", target: { package: "zod" } });
  });

  it("drops unknown enum values instead of forwarding them", async () => {
    const safety = stubSafety();
    const [, content, , gate] = createSafetyTools(safety);
    await content.execute({ content: "x", content_type: "pdf" });
    expect(safety.scanContent).toHaveBeenCalledWith("x", { contentType: undefined, source: undefined });
    await gate.execute({ action_type: "delete_everything", intent: "do it" });
    expect(safety.preflightAction).toHaveBeenCalledWith({ action_type: "custom", intent: "do it", target: {} });
  });

  it("never throws into the model loop and tells it to treat failures as unverified", async () => {
    const safety = stubSafety({ checkUrl: vi.fn(async () => { throw new AgentSafetyError("PAYMENT_STATUS_UNKNOWN", "check reconciliation", { paymentState: "unknown" }); }) });
    const [url] = createSafetyTools(safety);
    const result = await url.execute({ url: "https://a.example" });
    expect(result).toMatchObject({ action: "unknown", error: { code: "PAYMENT_STATUS_UNKNOWN", payment_state: "unknown" } });
    expect("instruction" in result && result.instruction).toMatch(/unverified/);
  });

  it("can expose a subset", () => {
    expect(createSafetyTools(stubSafety(), { include: ["check_npm_package"] }).map((tool) => tool.name)).toEqual(["check_npm_package"]);
  });
});
