import type { ClientSignals } from "./types";

/**
 * Collect advisory environment hints for the server-side risk engine.
 *
 * FORGEABLE BY DESIGN (ADR-0004): a competent bot fakes every field here, so
 * the server treats these as weight-capped hints that can raise suspicion and
 * never decide alone. Honest reports earn the bot-check discount; forged ones
 * simply forfeit it.
 */
export function collectSignals(): ClientSignals {
  // SSR / Node: no browser environment to inspect.
  if (typeof navigator === "undefined" || typeof window === "undefined") {
    return {};
  }
  const signals: ClientSignals = {};

  const nav = navigator as Navigator & { webdriver?: boolean };
  if (nav.webdriver === true) signals.webdriver = true;

  if (nav.languages?.length === 0) signals.no_languages = true;

  const win = window as unknown as { chrome?: unknown };
  if (win.chrome === undefined && /Chrome/.test(nav.userAgent ?? "")) {
    signals.headless = true;
  }

  return signals;
}
