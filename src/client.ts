import { AgentSafetyError, PaymentRequiredError, UnsafeActionError, type PaymentState } from "./errors.js";
import type {
  CheckName, CheckPackageResult, CheckUrlResult, ContentType, ContentVerdict, FetchLike, PaymentQuote,
  PreflightActionInput, PreflightActionResult, SafetyAction, SafetyVerdict, ScanContentResult,
} from "./types.js";

export const DEFAULT_BASE_URL = "https://mcp.dropenginehq.com";
export const SDK_VERSION = "0.1.0";

export interface AgentSafetyOptions {
  /**
   * A fetch that pays x402 challenges, e.g. `wrapFetchWithPayment(fetch, x402Client)` from `@x402/fetch`.
   * Defaults to the global fetch, which surfaces each price as a PaymentRequiredError.
   */
  fetch?: FetchLike;
  /** Service origin. Defaults to the hosted DropEngine service. */
  baseUrl?: string;
  /** Per-call timeout in milliseconds (default 20000). */
  timeoutMs?: number;
  /** Optional stable id for your agent; the service stores only a keyed hash of it. */
  agentId?: string;
}

export interface AgentSafety {
  /** Before an agent opens or fetches a URL. $0.005 per call. */
  checkUrl(url: string): Promise<SafetyVerdict<CheckUrlResult>>;
  /** Before an agent follows instructions found in web pages, emails, documents or tool output. $0.005 per call. */
  scanContent(content: string, options?: { contentType?: ContentType; source?: string }): Promise<ContentVerdict>;
  /** Before an agent installs an npm package. $0.005 per call. */
  checkPackage(name: string, options?: { version?: string }): Promise<SafetyVerdict<CheckPackageResult>>;
  /** One combined decision before a risky action; runs the relevant checks server-side. $0.02 per call. */
  preflightAction(input: PreflightActionInput): Promise<SafetyVerdict<PreflightActionResult>>;
}

const URL_ACTIONS: Record<string, SafetyAction> = { allow: "allow", caution: "warn", block: "block" };
const CONTENT_ACTIONS: Record<string, SafetyAction> = { allow: "allow", caution: "warn", sanitize: "warn", block: "block" };
const GATE_ACTIONS: Record<string, SafetyAction> = { ALLOW: "allow", REQUIRE_APPROVAL: "warn", REVIEW: "warn", DENY: "block" };

/** Unrecognized values never map to "allow". */
function toAction(table: Record<string, SafetyAction>, value: unknown): SafetyAction {
  return typeof value === "string" && value in table ? table[value] : "warn";
}

function strings(value: unknown, limit = 10): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string").slice(0, limit) : [];
}

function decodeBase64Json(value: string): unknown {
  try {
    return JSON.parse(atob(value));
  } catch {
    return null;
  }
}

function microToUsd(amount: string): string {
  if (!/^\d+$/.test(amount)) return amount;
  const padded = amount.padStart(7, "0");
  const whole = padded.slice(0, -6).replace(/^0+(?=\d)/, "");
  const fraction = padded.slice(-6).replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole;
}

export function parsePaymentQuote(header: string | null, body: unknown): PaymentQuote | null {
  const source = (header ? decodeBase64Json(header) : null) ?? body;
  const accepts = source && typeof source === "object" ? (source as { accepts?: unknown }).accepts : null;
  const offer = Array.isArray(accepts) ? accepts[0] as Record<string, unknown> | undefined : undefined;
  if (!offer || typeof offer.amount !== "string") return null;
  return {
    amount: offer.amount,
    amountUsd: microToUsd(offer.amount),
    asset: String(offer.asset ?? ""),
    network: String(offer.network ?? ""),
    payTo: String(offer.payTo ?? ""),
  };
}

export function createAgentSafety(options: AgentSafetyOptions = {}): AgentSafety {
  const fetchImpl: FetchLike = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  const baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/+$/, "");
  const timeoutMs = options.timeoutMs ?? 20_000;

  async function post<T>(path: string, body: unknown): Promise<T> {
    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json",
      // Lets the service count SDK-originated calls; it carries no identity.
      "x-attribution-source": "sdk",
    };
    if (options.agentId) headers["x-agent-id"] = options.agentId.slice(0, 128);

    let response: Response;
    try {
      response = await fetchImpl(`${baseUrl}${path}`, {
        method: "POST", headers, body: JSON.stringify(body), signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (error) {
      const name = error instanceof Error ? error.name : "";
      if (name === "TimeoutError" || name === "AbortError") {
        throw new AgentSafetyError("TIMEOUT", `No response within ${timeoutMs} ms; payment status is unknown.`, { paymentState: "unknown", cause: error });
      }
      throw new AgentSafetyError("NETWORK_ERROR", error instanceof Error ? error.message : "Request failed", { paymentState: "unknown", cause: error });
    }

    const text = await response.text();
    let json: unknown = null;
    try { json = text ? JSON.parse(text) : null; } catch { /* handled below */ }

    if (response.status === 402) throw new PaymentRequiredError(parsePaymentQuote(response.headers.get("payment-required"), json));

    if (!response.ok) {
      const error = json && typeof json === "object" ? (json as { error?: { code?: unknown; message?: unknown } }).error : undefined;
      const paymentState: PaymentState = response.headers.get("payment-response") ? "charged"
        : response.status === 400 || response.status === 413 ? "not_charged" : "unknown";
      throw new AgentSafetyError(
        typeof error?.code === "string" ? error.code : `HTTP_${response.status}`,
        typeof error?.message === "string" ? error.message : `Service responded with HTTP ${response.status}`,
        { status: response.status, paymentState },
      );
    }
    if (!json || typeof json !== "object" || Array.isArray(json)) {
      throw new AgentSafetyError("INVALID_RESPONSE", "Service returned a non-JSON response", { status: response.status, paymentState: "unknown" });
    }
    return json as T;
  }

  function verdict<Raw extends Record<string, unknown>>(check: CheckName, action: SafetyAction, raw: Raw, riskScore: unknown, reasons: string[]): SafetyVerdict<Raw> {
    return {
      check, action, raw, reasons,
      riskScore: typeof riskScore === "number" ? riskScore : null,
      degraded: raw.degraded === true,
    };
  }

  return {
    async checkUrl(url) {
      const raw = await post<CheckUrlResult>("/api/check-url", { url });
      return verdict("check_url", toAction(URL_ACTIONS, raw.recommendation), raw, raw.risk_score, strings(raw.warnings));
    },

    async scanContent(content, scanOptions = {}) {
      const raw = await post<ScanContentResult>("/api/scan-content", {
        content,
        ...(scanOptions.contentType ? { content_type: scanOptions.contentType } : {}),
        ...(scanOptions.source ? { source: scanOptions.source } : {}),
      });
      const patterns = Array.isArray(raw.detected_patterns) ? raw.detected_patterns : [];
      const reasons = patterns.slice(0, 10).map((pattern) => `${pattern.type} (${pattern.severity})`);
      return {
        ...verdict("scan_content", toAction(CONTENT_ACTIONS, raw.recommendation), raw, raw.risk_score, reasons),
        sanitizedContent: typeof raw.sanitized_content === "string" ? raw.sanitized_content : null,
      };
    },

    async checkPackage(name, packageOptions = {}) {
      const raw = await post<CheckPackageResult>("/api/check-package", {
        ecosystem: "npm", package: name, ...(packageOptions.version ? { version: packageOptions.version } : {}),
      });
      const reasons = [
        ...(raw.known_malicious === true ? ["known malicious package"] : []),
        ...(raw.similar_to ? [`name resembles ${raw.similar_to}`] : []),
        ...strings(raw.warnings),
      ].slice(0, 10);
      return verdict("check_package", toAction(URL_ACTIONS, raw.recommendation), raw, raw.risk_score, reasons);
    },

    async preflightAction(input) {
      const raw = await post<PreflightActionResult>("/api/preflight-action", input);
      return verdict("preflight_action", toAction(GATE_ACTIONS, raw.decision), raw, null, strings(raw.reasons));
    },
  };
}

/**
 * Throws UnsafeActionError unless the verdict allows the action.
 * By default "warn" passes; set strict to block on warnings too.
 */
export function assertSafe<V extends SafetyVerdict<unknown>>(verdict: V, options: { strict?: boolean } = {}): V {
  if (verdict.action === "block" || (options.strict && verdict.action === "warn")) throw new UnsafeActionError(verdict);
  return verdict;
}
