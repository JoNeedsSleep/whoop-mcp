import { describe, it, expect } from "vitest";
import { render } from "@testing-library/react";
import { ConnectionGuide } from "./ConnectionGuide";

describe("ConnectionGuide", () => {
  it("describes both registered clients and the deployment requirement", () => {
    const { container } = render(<ConnectionGuide />);
    const text = container.textContent ?? "";
    expect(text).toContain("Codex");
    expect(text).toContain("Claude Code");
    expect(text).toContain("deployment required");
    expect(text).toContain("separate, revocable connection");
    expect(text).toContain("client ID codex");
    expect(text).toContain("client ID claude-code");
    expect(text).toContain("seven days");
  });

  it("does not offer a disabled service URL or commands that embed credentials", () => {
    const { container } = render(<ConnectionGuide />);
    const text = container.textContent ?? "";
    expect(text).not.toContain(`${window.location.origin}/mcp`);
    expect(text).not.toContain("Authorization: Bearer");
    expect(text).not.toContain("YOUR_TOKEN");
    expect(container.querySelector("button")).toBeNull();
    expect(Array.from(container.querySelectorAll("a"), (a) => a.href)).toEqual([
      "https://developers.openai.com/codex/mcp",
      "https://code.claude.com/docs/en/mcp",
    ]);
  });
});
