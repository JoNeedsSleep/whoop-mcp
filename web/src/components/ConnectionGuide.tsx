import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";

export function ConnectionGuide() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Connect Codex and Claude Code</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-6">
        <div className="rounded-lg border border-border bg-muted p-3 text-sm">
          <p className="font-medium">Gateway setup · deployment required</p>
          <p className="mt-1 text-muted-foreground">
            The gateway supports both clients with separate browser sign-ins. Set up its
            protected HTTPS address first. This sample preview cannot connect to either assistant.
          </p>
        </div>

        <section className="flex flex-col gap-2" aria-label="Codex setup">
          <h3 className="text-sm font-medium">Codex</h3>
          <ol className="list-decimal space-y-1 pl-5 text-sm">
            <li>Add WHOOP as a Streamable HTTP MCP server using the approved gateway URL and client ID <code>codex</code>.</li>
            <li>Set the registered callback and listener port, then authenticate through your browser.</li>
            <li>Use the WHOOP tools in Codex. Local app, CLI and IDE clients on the same host share MCP configuration.</li>
          </ol>
          <a className="text-sm underline" href="https://developers.openai.com/codex/mcp" target="_blank" rel="noreferrer">
            Codex setup reference
          </a>
        </section>

        <section className="flex flex-col gap-2" aria-label="Claude Code setup">
          <h3 className="text-sm font-medium">Claude Code</h3>
          <ol className="list-decimal space-y-1 pl-5 text-sm">
            <li>Add WHOOP as an HTTP MCP server using the same approved gateway URL and client ID <code>claude-code</code>.</li>
            <li>Set the fixed callback port to match its gateway registration.</li>
            <li>Open <code>/mcp</code> in Claude Code and complete browser sign-in.</li>
            <li>Use the WHOOP tools in Claude Code, including alongside Codex.</li>
          </ol>
          <a className="text-sm underline" href="https://code.claude.com/docs/en/mcp" target="_blank" rel="noreferrer">
            Claude Code setup reference
          </a>
        </section>

        <p className="text-sm text-muted-foreground">
          Each client gets a separate, revocable connection lasting seven days.
          Your OpenAI and Anthropic account credentials stay out of the WHOOP service.
          Use the gateway owner page to revoke either client. Tokens created here are not gateway credentials.
        </p>
      </CardContent>
    </Card>
  );
}
