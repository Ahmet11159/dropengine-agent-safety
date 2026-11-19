/** A fetch-compatible function. Pass one that pays x402 challenges (see README). */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export type CheckName = "check_url" | "scan_content" | "check_package" | "preflight_action";

/** Normalized outcome shared by every check. "warn" covers caution, sanitize, review and approval. */
export type SafetyAction = "allow" | "warn" | "block";

export interface SafetyVerdict<Raw = Record<string, unknown>> {
  check: CheckName;
  action: SafetyAction;
  /** 0-100 where the service provides one; null for the action gate. */
  riskScore: number | null;
  /** Short human-readable reasons, safe to show to a user or an LLM. */
  reasons: string[];
  /** True when the service answered with partial evidence (a provider was unavailable). */
  degraded: boolean;
  /** Full service response for anything the normalized fields do not cover. */
  raw: Raw;
}

export interface ContentVerdict extends SafetyVerdict<ScanContentResult> {
  /** Content with detected instructions neutralized, when the service returned it. */
  sanitizedContent: string | null;
}

export type ContentType = "text" | "html" | "markdown" | "email" | "tool_output" | "api_response" | "document_text";

export interface CheckUrlResult {
  success: boolean;
  recommendation: "allow" | "caution" | "block";
  risk_score: number;
  degraded: boolean;
  warnings: string[];
  [key: string]: unknown;
}

export interface ScanContentResult {
  safe: boolean;
  risk_score: number;
  risk_level: "low" | "medium" | "high" | "critical";
  recommendation: "allow" | "caution" | "sanitize" | "block";
  prompt_injection_detected: boolean;
  detected_patterns: { type: string; severity: "low" | "medium" | "high" | "critical" }[];
  sanitized_content?: string;
  degraded?: boolean;
  [key: string]: unknown;
}

export interface CheckPackageResult {
  success: true;
  ecosystem: "npm";
  package: string;
  resolved_version: string;
  risk_score: number;
  risk_level: "low" | "medium" | "high" | "critical";
  recommendation: "allow" | "caution" | "block";
  known_malicious: boolean | null;
  known_vulnerabilities: { id: string; summary: string | null; severity: string; fixed_version: string | null }[];
  typosquat_risk: string;
  similar_to: string | null;
  warnings: string[];
  degraded: boolean;
  [key: string]: unknown;
}

export type ActionType = "tool_call" | "install_package" | "open_url" | "use_external_content" | "wallet_interaction" | "transaction" | "token_interaction" | "purchase" | "custom";

export interface PreflightActionInput {
  action_type: ActionType;
  /** What the agent is about to do and why, 3-500 characters. */
  intent: string;
  target?: {
    url?: string;
    package?: string;
    content?: string;
    content_type?: ContentType;
    tool?: string;
    mcp_endpoint?: string;
    wallet?: string | { chain?: "base" | "base-sepolia"; address: string };
    transaction?: { chain: string; from: string; to: string; value: string; data: string };
    token?: { chain: string; token_address: string };
    claim?: string;
    capability?: string;
  };
  expected_cost?: { amount?: string; asset?: string; network?: string };
  context?: { agent_id?: string; purpose?: string; risk_tolerance?: "low" | "medium" | "high" };
}

export interface PreflightActionResult {
  success: true;
  decision: "ALLOW" | "DENY" | "REQUIRE_APPROVAL" | "REVIEW";
  risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  confidence: number;
  reasons: string[];
  recommended_action: "PROCEED" | "STOP" | "REQUEST_OWNER_APPROVAL" | "REVIEW_OR_RETRY";
  evidence_status: "incomplete" | "rule_evaluable";
  checks_run: string[];
  failed_checks: { tool: string; code: string }[];
  retryable: boolean;
  [key: string]: unknown;
}

export interface PaymentQuote {
  /** Price in USD as a decimal string, e.g. "0.005". */
  amountUsd: string;
  /** Atomic token amount as quoted by the server. */
  amount: string;
  asset: string;
  network: string;
  payTo: string;
}
