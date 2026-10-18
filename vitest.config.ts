import { defineConfig, configDefaults } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // Dependency-free gateway/local/deployment suites use Node's own runner.
    exclude: [...configDefaults.exclude, "web/**", "review-gateway/**", "restricted-local/**", "deploy/**"],
  },
});
