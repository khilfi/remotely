// Known hosts (SS-05; UX-08: the Vault page's second tab since 0.6.0): the SSH host keys trusted so far, one per host,
// port and key type. Removing a key
// makes the next connection ask again; it is audited. Trusting and replacing keys happen in the terminal,
// where the fingerprint is shown before anything is sent.

import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { SearchIcon, ShieldCheckIcon, Trash2Icon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { HelpTip } from "@/components/HelpTip";
import { useReadOnlyReason } from "@/components/Presentation";
import { WhyDisabled } from "@/components/WhyDisabled";
import { api, errorMessage, type KnownHost } from "@/lib/api";
import { formatWhen, plural } from "@/lib/format";

interface Props {
  /** True while the page is shown, so the list is read again when the user comes back. */
  active: boolean;
}

function address(k: KnownHost) {
  const host = k.host.includes(":") && !k.host.startsWith("[") ? `[${k.host}]` : k.host;
  return `${host}:${k.port}`;
}

export function KnownHostsPage({ active }: Props) {
  // FD-03: removing a trusted key is blocked by the read-only lock.
  const readOnly = useReadOnlyReason();
  const [hosts, setHosts] = useState<KnownHost[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [text, setText] = useState("");
  const [removing, setRemoving] = useState<KnownHost | null>(null);

  const load = useCallback(() => {
    api.knownHosts().then(
      (list) => {
        setHosts(list);
        setLoaded(true);
      },
      (err) => toast.error(errorMessage(err)),
    );
  }, []);

  useEffect(() => {
    if (active) load();
  }, [active, load]);

  const shown = useMemo(() => {
    const needle = text.trim().toLowerCase();
    if (!needle) return hosts;
    return hosts.filter((k) =>
      [k.host, String(k.port), k.keyType, k.fingerprint].some((f) => f.toLowerCase().includes(needle)),
    );
  }, [hosts, text]);

  return (
    <div className="flex flex-col gap-4">
      <p className="flex max-w-3xl items-center gap-1 text-sm text-muted-foreground">
        Remove a key when a host was rebuilt; the next connection then asks again.
        <HelpTip topic="page.knownHosts" />
      </p>
      <div className="relative max-w-sm">
        <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
        <Input
          className="pl-8"
          placeholder="Search hosts and fingerprints"
          value={text}
          onChange={(e) => setText(e.target.value)}
          aria-label="Search known hosts"
        />
      </div>
      {loaded && hosts.length === 0 ? (
        <EmptyState
          icon={ShieldCheckIcon}
          title="No trusted hosts yet"
          description="Host keys you trust in the terminal are listed here."
        />
      ) : (
        <div className="rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Host</TableHead>
                <TableHead>Key type</TableHead>
                <TableHead>Fingerprint (SHA-256)</TableHead>
                <TableHead>Trusted</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead className="w-12">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.map((k) => (
                <TableRow key={k.id}>
                  <TableCell className="font-medium" data-mask="address">
                    {address(k)}
                  </TableCell>
                  <TableCell className="text-muted-foreground">{k.keyType}</TableCell>
                  <TableCell>
                    <code className="font-mono text-xs break-all select-all">{k.fingerprint}</code>
                  </TableCell>
                  <TableCell className="whitespace-nowrap text-muted-foreground">{formatWhen(k.firstSeenAt)}</TableCell>
                  <TableCell className="whitespace-nowrap text-muted-foreground">{formatWhen(k.lastSeenAt)}</TableCell>
                  <TableCell>
                    <WhyDisabled reason={readOnly}>
                      <Button
                        variant="ghost"
                        size="icon-sm"
                        aria-label={`Remove the key of ${address(k)}`}
                        title="Remove"
                        disabled={readOnly !== null}
                        onClick={() => setRemoving(k)}
                      >
                        <Trash2Icon />
                      </Button>
                    </WhyDisabled>
                  </TableCell>
                </TableRow>
              ))}
              {shown.length === 0 && hosts.length > 0 && (
                <TableRow>
                  <TableCell colSpan={6} className="text-center text-muted-foreground">
                    No host matches.
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </div>
      )}
      {hosts.length > 0 && <p className="text-xs text-muted-foreground">{plural(hosts.length, "trusted key")}</p>}
      {removing && (
        <ConfirmDialog
          title={`Remove the key of ${address(removing)}?`}
          description={
            <>
              The next connection to this host will show its fingerprint and ask again. Remove a key only when you know
              why it changed, for example after the host was rebuilt.
            </>
          }
          confirmLabel="Remove key"
          onConfirm={async () => {
            await api.removeKnownHost(removing.id);
            toast.success(`Removed the key of ${address(removing)}`);
            load();
          }}
          onClose={() => setRemoving(null)}
        />
      )}
    </div>
  );
}
