ALTER TABLE "mcp_tokens" ADD COLUMN "expires_at" timestamp with time zone;
--> statement-breakpoint
ALTER TABLE "mcp_tokens" ADD COLUMN "client_id" text;
--> statement-breakpoint
-- Existing credentials had no fixed lifetime: require fresh authorization.
UPDATE "mcp_tokens" SET "expires_at" = now(), "revoked_at" = COALESCE("revoked_at", now());
--> statement-breakpoint
ALTER TABLE "mcp_tokens" ALTER COLUMN "expires_at" SET NOT NULL;
