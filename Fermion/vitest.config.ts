import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // React component tests run in a DOM; node:test files (src/*.test.js) are the
    // pure/unit suite run separately via `node --test`, so exclude them here.
    environment: 'jsdom',
    globals: true,
    include: ['src/ui/**/*.test.{ts,tsx}'],
    setupFiles: ['src/ui/test-setup.ts'],
  },
});
