// Test only: shifts Date.now by the milliseconds written in the file named by UAI_TEST_SKEW_FILE, so a test can move
// a running agent's clock forward. Loaded with `node --import`; agent.mjs never imports it.
import { readFileSync } from "node:fs";
const real = Date.now.bind(Date);
Date.now = () => real() + Number(readFileSync(process.env.UAI_TEST_SKEW_FILE, "utf8") || 0);
