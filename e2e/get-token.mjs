// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 xeylabs

// Full client flow against a live mythicd: challenge -> PoW solve -> verify.
// Prints the decision token to stdout. Reads MYTHIC_E2E_BASE from env.
import { MythicClient } from "../sdk/js/dist/index.js";

const base = process.env.MYTHIC_E2E_BASE;
if (!base) {
  console.error("MYTHIC_E2E_BASE not set");
  process.exit(1);
}

const client = new MythicClient({
  endpoint: base,
  siteKey: "e2e-test",
  useWorker: false, // main-thread grind; the Worker path is covered by the Playwright browser test
  collectBehavior: false, // Node has no pointer/keyboard to observe
});

const res = await client.getToken();
if (!res.token) {
  console.error("verify result contained no token");
  process.exit(1);
}
process.stdout.write(res.token);
