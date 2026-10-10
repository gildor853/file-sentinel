import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/cli.ts", "src/cli-main.ts"],
      reporter: ["text", "json-summary"],
      thresholds: { statements: 95, branches: 90, functions: 95, lines: 95 },
    },
  },
});
