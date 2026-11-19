import type { PaymentQuote, SafetyVerdict } from "./types.js";

/**
 * "not_charged": the service failed before any payment settled; retrying is safe.
 * "unknown": settlement and result were not both confirmed; check your wallet before retrying.
 */
export type PaymentState = "not_charged" | "charged" | "unknown";

export class AgentSafetyError extends Error {
  readonly code: string;
  readonly status: number | null;
  readonly paymentState: PaymentState;

  constructor(code: string, message: string, options: { status?: number | null; paymentState?: PaymentState; cause?: unknown } = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = "AgentSafetyError";
    this.code = code;
    this.status = options.status ?? null;
    this.paymentState = options.paymentState ?? "not_charged";
  }
}

/** The service asked for an x402 payment that the supplied fetch did not make. */
export class PaymentRequiredError extends AgentSafetyError {
  readonly quote: PaymentQuote | null;

  constructor(quote: PaymentQuote | null) {
    super(
      "PAYMENT_REQUIRED",
      quote
        ? `This check costs $${quote.amountUsd} (${quote.network}). Pass an x402-paying fetch to createAgentSafety({ fetch }).`
        : "This check requires an x402 payment. Pass an x402-paying fetch to createAgentSafety({ fetch }).",
      { status: 402, paymentState: "not_charged" },
    );
    this.name = "PaymentRequiredError";
    this.quote = quote;
  }
}

/** Thrown by assertSafe() when a verdict does not allow the action. */
export class UnsafeActionError extends Error {
  readonly verdict: SafetyVerdict<unknown>;

  constructor(verdict: SafetyVerdict<unknown>) {
    const why = verdict.reasons.length ? `: ${verdict.reasons.slice(0, 3).join("; ")}` : "";
    super(`${verdict.check} returned ${verdict.action}${why}`);
    this.name = "UnsafeActionError";
    this.verdict = verdict;
  }
}
