// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

import type { BehavioralFeatures } from "./types";

/**
 * Privacy-preserving behavioral feature extraction (ADR-0011).
 *
 * Collects pointer/keyboard/scroll events locally and computes aggregate
 * features. NO raw trajectories, coordinates, key identities, or scroll
 * positions leave the device — only quantized statistical aggregates.
 *
 * FORGEABLE BY DESIGN (ADR-0004): a competent bot fakes these, so the
 * server treats them as weight-capped advisory signals. The cost of
 * faking convincingly at scale is the defense, not the impossibility.
 */

interface Point {
  x: number;
  y: number;
  t: number;
}

const MAX_POINTS = 200; // bound memory; sliding window
const COLLECT_MS = 30000; // stop collecting after 30s

export class BehavioralCollector {
  private points: Point[] = [];
  private keyDowns = new Map<string, number>();
  private dwells: number[] = [];
  private flights: number[] = [];
  private lastKeyUp = 0;
  private scrolls: number[] = [];
  private scrollReversals = 0;
  private lastScrollDir = 0;
  private active = false;

  private onMouseMove = (e: MouseEvent) => this.recordPoint(e.clientX, e.clientY);
  private onKeyDown = (e: KeyboardEvent) => {
    if (!this.keyDowns.has(e.code)) this.keyDowns.set(e.code, performance.now());
  };
  private onKeyUp = (e: KeyboardEvent) => {
    const down = this.keyDowns.get(e.code);
    const now = performance.now();
    if (down !== undefined) {
      this.dwells.push(now - down);
      this.keyDowns.delete(e.code);
      if (this.lastKeyUp > 0) this.flights.push(now - this.lastKeyUp);
      this.lastKeyUp = now;
    }
  };
  private onScroll = (e: Event) => {
    const y = window.scrollY;
    const now = performance.now();
    // Direction reversal detection (no absolute position stored)
    const dir = this.scrolls.length > 0 ? Math.sign(y - (this as any)._lastY || 0) : 0;
    if (dir !== 0 && this.lastScrollDir !== 0 && dir !== this.lastScrollDir) {
      this.scrollReversals++;
    }
    if (dir !== 0) this.lastScrollDir = dir;
    (this as any)._lastY = y;
    this.scrolls.push(now);
    void e;
  };

  /** Start collecting. Safe to call multiple times (idempotent). */
  start(): void {
    if (this.active || typeof window === "undefined") return;
    this.active = true;
    window.addEventListener("mousemove", this.onMouseMove, { passive: true });
    window.addEventListener("keydown", this.onKeyDown, { passive: true });
    window.addEventListener("keyup", this.onKeyUp, { passive: true });
    window.addEventListener("scroll", this.onScroll, { passive: true, capture: true });
    // Auto-stop after collection window
    setTimeout(() => this.stop(), COLLECT_MS);
  }

  /** Stop collecting and remove listeners. */
  stop(): void {
    if (!this.active) return;
    this.active = false;
    window.removeEventListener("mousemove", this.onMouseMove);
    window.removeEventListener("keydown", this.onKeyDown);
    window.removeEventListener("keyup", this.onKeyUp);
    window.removeEventListener("scroll", this.onScroll, { capture: true } as EventListenerOptions);
  }

  private recordPoint(x: number, y: number): void {
    // Throttle: max ~60Hz, skip duplicates
    const now = performance.now();
    const last = this.points[this.points.length - 1];
    if (last && now - last.t < 16) return;
    this.points.push({ x, y, t: now });
    if (this.points.length > MAX_POINTS) this.points.shift();
  }

  /**
   * Extract quantized aggregate features. No raw data leaves this function.
   * All values are rounded to reduce fingerprinting surface.
   */
  extract(): BehavioralFeatures {
    const f: BehavioralFeatures = { v: 1 };

    // --- Mouse trajectory features ---
    if (this.points.length >= 5) {
      const velocities: number[] = [];
      let directionChanges = 0;
      let lastAngle = 0;
      let totalDist = 0;

      for (let i = 1; i < this.points.length; i++) {
        const p0 = this.points[i - 1]!;
        const p1 = this.points[i]!;
        const dt = Math.max(p1.t - p0.t, 1);
        const dx = p1.x - p0.x;
        const dy = p1.y - p0.y;
        const dist = Math.hypot(dx, dy);
        totalDist += dist;
        velocities.push(dist / dt); // px per ms

        if (i > 1) {
          const angle = Math.atan2(dy, dx);
          let dAngle = Math.abs(angle - lastAngle);
          if (dAngle > Math.PI) dAngle = 2 * Math.PI - dAngle;
          if (dAngle > 0.5) directionChanges++; // significant turn
          lastAngle = angle;
        } else {
          lastAngle = Math.atan2(dy, dx);
        }
      }

      const mean = velocities.reduce((a, b) => a + b, 0) / velocities.length;
      const variance =
        velocities.reduce((a, b) => a + (b - mean) ** 2, 0) / velocities.length;

      f.mouse_points = this.points.length;
      f.mouse_mean_v = Math.round(mean * 1000) / 1000; // px/ms, 3 decimals
      f.mouse_var_v = Math.round(variance * 1000) / 1000;
      f.mouse_dir_changes = directionChanges;
      // Curvature: ratio of path length to straight-line distance.
      // Humans ~1.2-3.0 (curvy); bots ~1.0 (straight) or teleport (>10).
      const p0 = this.points[0]!;
      const pN = this.points[this.points.length - 1]!;
      const straight = Math.hypot(pN.x - p0.x, pN.y - p0.y);
      f.mouse_curvature = straight > 0 ? Math.round((totalDist / straight) * 100) / 100 : 0;
    } else {
      f.mouse_points = this.points.length;
    }

    // --- Keystroke features (timing only, no key identities) ---
    if (this.dwells.length > 0) {
      const mean =
        this.dwells.reduce((a, b) => a + b, 0) / this.dwells.length;
      f.key_dwells = this.dwells.length;
      f.key_mean_dwell = Math.round(mean); // ms
    }
    if (this.flights.length > 0) {
      const mean =
        this.flights.reduce((a, b) => a + b, 0) / this.flights.length;
      f.key_mean_flight = Math.round(mean); // ms
    }

    // --- Scroll features (counts only, no positions) ---
    f.scroll_events = this.scrolls.length;
    f.scroll_reversals = this.scrollReversals;

    return f;
  }
}
