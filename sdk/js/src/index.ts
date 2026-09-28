// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 xeylabs

export { XProtectClient, XProtectError } from "./client";
export type { XProtectOptions } from "./client";
export { solve, sha256, leadingZeroBits } from "./pow";
export type { SolveOptions } from "./pow";
export { collectSignals } from "./signals";
export type { Challenge, Solution, VerifyResult, Decision, ClientSignals } from "./types";
