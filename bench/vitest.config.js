import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

/**
 * Configuration for `npm run bench:compare` only (bench/run-comparison.js).
 * `npm test` uses vitest's defaults and never picks the comparison up.
 */
export default defineConfig({
    test: {
        root: fileURLToPath(new URL('..', import.meta.url)),
        include: ['bench/run-comparison.js'],
        testTimeout: 10 * 60 * 1000,
        // Each simulated run swaps the global timers and resets every
        // module; nothing else may run alongside it.
        fileParallelism: false
    }
});
