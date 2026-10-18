import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, fireEvent, cleanup } from "@testing-library/react";
import { TokensCard } from "./TokensCard";

const sampleToken = {
  id: "tok_1",
  label: "My laptop",
  createdAt: "2026-01-01T00:00:00.000Z",
  lastUsedAt: null,
  type: "oauth",
  expiresAt: "2026-01-01T01:00:00.000Z",
};

beforeEach(() => {
  vi.restoreAllMocks();
});

afterEach(() => {
  cleanup();
});

it("renders a label input next to the create button", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(JSON.stringify({ tokens: [] }), { status: 200 })
  );
  render(<TokensCard onUnauthorized={() => {}} />);
  await waitFor(() => expect(screen.getByText(/no tokens yet/i)).toBeInTheDocument());
  expect(screen.getByPlaceholderText(/label/i)).toBeInTheDocument();
});

it("renders a token's label in the table", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(JSON.stringify({ tokens: [sampleToken] }), { status: 200 })
  );
  render(<TokensCard onUnauthorized={() => {}} />);
  await waitFor(() => expect(screen.getByText("My laptop")).toBeInTheDocument());
});

it("opens a rename dialog prefilled with the current label", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(
    new Response(JSON.stringify({ tokens: [sampleToken] }), { status: 200 })
  );
  render(<TokensCard onUnauthorized={() => {}} />);
  await waitFor(() => expect(screen.getByText("My laptop")).toBeInTheDocument());

  fireEvent.click(screen.getByRole("button", { name: /rename/i }));

  await waitFor(() => expect(screen.getByText(/give this token a label/i)).toBeInTheDocument());
  const inputs = screen.getAllByPlaceholderText(/label/i) as HTMLInputElement[];
  const renameInput = inputs.find((input) => input.value === "My laptop");
  expect(renameInput).toBeDefined();
});
