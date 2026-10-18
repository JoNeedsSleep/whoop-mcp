import { defineConfig, configDefaults } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // Dependency-free gateway/local suites use Node's own test runner.
    exclude: [...configDefaults.exclude, "web/**", "review-gateway/**", "restricted-local/**"],
  },
});
