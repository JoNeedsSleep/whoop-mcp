import { useEffect, useState } from "react";
import { toast } from "sonner";
import { CopyIcon, Loader2Icon } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardAction, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogTrigger,
  AlertDialogContent,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogAction,
  AlertDialogCancel,
} from "@/components/ui/alert-dialog";
import { api, isUnauthorized, type TokenSummary } from "@/lib/api";

const errorMessage = (err: unknown) => (err instanceof Error ? err.message : "Something went wrong");

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString();
}

interface TokenRowProps {
  token: TokenSummary;
  onRevoke: (id: string) => Promise<void>;
  onRename: (token: TokenSummary) => void;
}

function TokenRow({ token, onRevoke, onRename }: TokenRowProps) {
  const [open, setOpen] = useState(false);
  const [revoking, setRevoking] = useState(false);

  async function handleConfirm() {
    setRevoking(true);
    try {
      await onRevoke(token.id);
      setOpen(false);
    } catch {
      // error already reported by onRevoke; keep the dialog open
    } finally {
      setRevoking(false);
    }
  }

  return (
    <TableRow>
      <TableCell>{token.label ? token.label : <span className="text-muted-foreground">—</span>}</TableCell>
      <TableCell>{token.type}</TableCell>
      <TableCell>{formatDate(token.expiresAt)}</TableCell>
      <TableCell>{formatDate(token.createdAt)}</TableCell>
      <TableCell>{token.lastUsedAt ? formatDate(token.lastUsedAt) : "Never"}</TableCell>
      <TableCell>
        <div className="flex justify-end gap-2">
          <Button variant="outline" size="sm" onClick={() => onRename(token)}>
            Rename
          </Button>
          <AlertDialog open={open} onOpenChange={setOpen}>
            <AlertDialogTrigger render={<Button variant="destructive" size="sm" />}>
              Revoke
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Revoke this token?</AlertDialogTitle>
                <AlertDialogDescription>
                  Any application using this token will immediately lose access. This can't be undone.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction variant="destructive" onClick={handleConfirm} disabled={revoking}>
                  Revoke
                </AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
      </TableCell>
    </TableRow>
  );
}

export function TokensCard({ onUnauthorized }: { onUnauthorized: () => void }) {
  const [tokens, setTokens] = useState<TokenSummary[] | null>(null);
  const [creating, setCreating] = useState(false);
  const [newToken, setNewToken] = useState<string | null>(null);
  const [newLabel, setNewLabel] = useState("");
  const [renaming, setRenaming] = useState<TokenSummary | null>(null);
  const [renameLabel, setRenameLabel] = useState("");
  const [renameSaving, setRenameSaving] = useState(false);

  async function fetchTokens() {
    try {
      const { tokens: fetched } = await api.listTokens();
      setTokens(fetched);
    } catch (err) {
      if (isUnauthorized(err)) onUnauthorized();
      else toast.error(errorMessage(err));
    }
  }

  useEffect(() => {
    fetchTokens();
  }, []);

  async function handleCreate() {
    setCreating(true);
    try {
      const { token } = await api.createToken(newLabel.trim() || undefined);
      setNewToken(token);
      setNewLabel("");
    } catch (err) {
      if (isUnauthorized(err)) onUnauthorized();
      else toast.error(errorMessage(err));
    } finally {
      setCreating(false);
    }
  }

  async function handleRevoke(id: string) {
    try {
      await api.revokeToken(id);
      toast.success("Token revoked");
      await fetchTokens();
    } catch (err) {
      if (isUnauthorized(err)) {
        onUnauthorized();
        return;
      }
      toast.error(errorMessage(err));
      throw err;
    }
  }

  async function handleRevokeAll() {
    try { await api.revokeAllTokens(); await fetchTokens(); toast.success("All tokens revoked"); }
    catch (err) { if (isUnauthorized(err)) onUnauthorized(); else toast.error(errorMessage(err)); }
  }

  function handleRenameClick(token: TokenSummary) {
    setRenaming(token);
    setRenameLabel(token.label ?? "");
  }

  async function handleRenameSave() {
    if (!renaming) return;
    setRenameSaving(true);
    try {
      await api.updateTokenLabel(renaming.id, renameLabel.trim() || null);
      toast.success("Label updated");
      setRenaming(null);
      await fetchTokens();
    } catch (err) {
      if (isUnauthorized(err)) {
        onUnauthorized();
        return;
      }
      toast.error(errorMessage(err));
    } finally {
      setRenameSaving(false);
    }
  }

  async function handleCopy() {
    if (!newToken) return;
    try {
      await navigator.clipboard.writeText(newToken);
      toast.success("Copied to clipboard");
    } catch {
      toast.error("Could not copy to clipboard");
    }
  }

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle>Access tokens</CardTitle>
          <CardDescription>You stay signed in for seven days. Assistant access and personal tokens also last seven days and can be revoked here.</CardDescription>
          <CardAction>
            <div className="flex gap-2">
              <Input
                value={newLabel}
                onChange={(e) => setNewLabel(e.target.value)}
                placeholder="Label (optional)"
                maxLength={100}
                className="w-40"
              />
              <Button onClick={handleCreate} disabled={creating}>
                {creating ? <Loader2Icon className="animate-spin" /> : null}
                Create token
              </Button>
            </div>
          </CardAction>
        </CardHeader>
        <CardContent>
          <AlertDialog>
            <AlertDialogTrigger render={<Button variant="destructive" size="sm" />}>Revoke all access tokens</AlertDialogTrigger>
            <AlertDialogContent><AlertDialogHeader><AlertDialogTitle>Revoke all access tokens?</AlertDialogTitle>
              <AlertDialogDescription>Every OAuth and personal token will stop working. Clients must reconnect.</AlertDialogDescription>
            </AlertDialogHeader><AlertDialogFooter><AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction variant="destructive" onClick={handleRevokeAll}>Revoke all</AlertDialogAction>
            </AlertDialogFooter></AlertDialogContent>
          </AlertDialog>
          {tokens === null ? (
            <div className="flex justify-center py-8">
              <Loader2Icon className="size-5 animate-spin text-muted-foreground" role="status" aria-label="Loading tokens" />
            </div>
          ) : tokens.length === 0 ? (
            <p className="text-sm text-muted-foreground">No tokens yet.</p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Label</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Last used</TableHead>
                  <TableHead />
                </TableRow>
              </TableHeader>
              <TableBody>
                {tokens.map((token) => (
                  <TokenRow key={token.id} token={token} onRevoke={handleRevoke} onRename={handleRenameClick} />
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Dialog
        open={newToken !== null}
        onOpenChange={(open) => {
          if (!open) {
            setNewToken(null);
            fetchTokens();
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Token created</DialogTitle>
            <DialogDescription>
              Copy this token now — for security it won't be shown again.
            </DialogDescription>
          </DialogHeader>
          <div className="flex items-center gap-2">
            <code className="flex-1 overflow-x-auto rounded-lg border border-border bg-muted px-2.5 py-1.5 text-sm">
              {newToken}
            </code>
            <Button variant="outline" size="icon" aria-label="Copy token" onClick={handleCopy}>
              <CopyIcon />
            </Button>
          </div>
          <p className="text-sm text-muted-foreground">
            Codex and Claude Code connections are pending the secure gateway. This token is not
            a gateway credential.
          </p>
          <DialogFooter showCloseButton />
        </DialogContent>
      </Dialog>

      <Dialog
        open={renaming !== null}
        onOpenChange={(open) => {
          if (!open) setRenaming(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename token</DialogTitle>
            <DialogDescription>Give this token a label to help you identify it later.</DialogDescription>
          </DialogHeader>
          <Input
            value={renameLabel}
            onChange={(e) => setRenameLabel(e.target.value)}
            placeholder="Label (optional)"
            maxLength={100}
          />
          <DialogFooter>
            <Button variant="outline" onClick={() => setRenaming(null)} disabled={renameSaving}>
              Cancel
            </Button>
            <Button onClick={handleRenameSave} disabled={renameSaving}>
              {renameSaving ? <Loader2Icon className="animate-spin" /> : null}
              Save
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
