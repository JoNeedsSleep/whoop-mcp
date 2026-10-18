import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";

export function ConnectionGuide() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Connect Codex and Claude Code</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        <div className="rounded-lg border border-border bg-muted p-3 text-sm">
          <p className="font-medium">Setup preview · connections are not enabled yet</p>
          <p className="mt-1 text-muted-foreground">
            Both clients are planned. Real connections will become available after the secure
            gateway is ready. This preview cannot connect to either assistant.
          </p>
        </div>

        <section className="flex flex-col gap-2" aria-label="Codex setup">
          <h3 className="text-sm font-medium">Codex</h3>
          <ol className="list-decimal space-y-1 pl-5 text-sm">
            <li>Add WHOOP as a Streamable HTTP MCP server using the approved gateway URL.</li>
            <li>Choose Authenticate to sign in through your browser.</li>
            <li>Use the WHOOP tools in Codex. Local app, CLI and IDE clients on the same host share MCP configuration.</li>
          </ol>
          <a className="text-sm underline" href="https://developers.openai.com/codex/mcp" target="_blank" rel="noreferrer">
            Codex setup reference
          </a>
        </section>

        <section className="flex flex-col gap-2" aria-label="Claude Code setup">
          <h3 className="text-sm font-medium">Claude Code</h3>
          <ol className="list-decimal space-y-1 pl-5 text-sm">
            <li>Add WHOOP as an HTTP MCP server using the same approved gateway URL.</li>
            <li>Open <code>/mcp</code> in Claude Code and complete browser sign-in.</li>
            <li>Use the WHOOP tools in Claude Code, including alongside Codex.</li>
          </ol>
          <a className="text-sm underline" href="https://code.claude.com/docs/en/mcp" target="_blank" rel="noreferrer">
            Claude Code setup reference
          </a>
        </section>

        <p className="text-sm text-muted-foreground">
          Planned access: a separate, revocable connection for each client, lasting seven days.
          Your OpenAI and Anthropic account credentials stay out of the WHOOP service.
          Tokens created here do not connect either client to the future gateway.
        </p>
      </CardContent>
    </Card>
  );
}
