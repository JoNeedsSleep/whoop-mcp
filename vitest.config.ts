import { defineConfig, configDefaults } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    // The gateway uses Node's built-in test runner and is run separately.
    exclude: [...configDefaults.exclude, "web/**", "review-gateway/**"],
  },
});
