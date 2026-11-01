// Known hosts (SS-05; UX-08: the Vault page's second tab since 0.6.0): the SSH host keys trusted so far, one per host,
// port and key type. Removing a key makes the next connection ask again; it is audited. Trusting and replacing keys
// happen in the terminal, where the fingerprint is shown before anything is sent. UX-07: the search row with the
// tab's "?", one row menu per key (copy the fingerprint, remove), long fingerprints shortened with the whole one on
// hover.

import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { CopyIcon, SearchIcon, ShieldCheckIcon, Trash2Icon } from "lucide-react";
import { DropdownMenuItem, DropdownMenuSeparator } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { EmptyState } from "@/components/EmptyState";
import { HelpTip } from "@/components/HelpTip";
import { useReadOnlyReason } from "@/components/Presentation";
import { RowMenu } from "@/components/RowMenu";
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

/** "Ed25519", "RSA", "ECDSA P-256", or the name as OpenSSH gives it. */
function keyType(name: string) {
  switch (name) {
    case "ssh-ed25519":
      return "Ed25519";
    case "tls-certificate":
      return "HTTPS certificate (WinRM)";
    case "ssh-rsa":
    case "rsa-sha2-256":
    case "rsa-sha2-512":
      return "RSA";
    case "ecdsa-sha2-nistp256":
      return "ECDSA P-256";
    case "ecdsa-sha2-nistp384":
      return "ECDSA P-384";
    case "ecdsa-sha2-nistp521":
      return "ECDSA P-521";
    default:
      return name;
  }
}

async function copyFingerprint(k: KnownHost) {
  try {
    await navigator.clipboard.writeText(k.fingerprint);
    toast.success("Copied the fingerprint");
  } catch (err) {
    toast.error(`Could not copy: ${errorMessage(err)}`);
  }
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

  if (loaded && hosts.length === 0) {
    return (
      <EmptyState
        icon={ShieldCheckIcon}
        title="No trusted hosts yet"
        description="The first connection to a host shows its key; the keys you trust are listed here."
        help="page.knownHosts"
      />
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <div className="relative w-full max-w-sm">
          <SearchIcon className="absolute top-1/2 left-2.5 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            className="pl-8"
            placeholder="Search hosts and fingerprints"
            value={text}
            onChange={(e) => setText(e.target.value)}
            aria-label="Search known hosts"
          />
        </div>
        <HelpTip topic="page.knownHosts" />
        {hosts.length > 0 && (
          <span className="ml-auto text-sm text-muted-foreground">{plural(hosts.length, "trusted key")}</span>
        )}
      </div>
      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-48">Host</TableHead>
              <TableHead className="w-28">Key</TableHead>
              <TableHead>Fingerprint</TableHead>
              <TableHead className="w-44">Trusted</TableHead>
              <TableHead className="w-44">Last seen</TableHead>
              <TableHead className="w-10">
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
                <TableCell className="text-muted-foreground" title={k.keyType}>
                  {keyType(k.keyType)}
                </TableCell>
                <TableCell className="max-w-0">
                  <code className="block truncate font-mono text-xs" title={k.fingerprint}>
                    {k.fingerprint}
                  </code>
                </TableCell>
                <TableCell className="whitespace-nowrap text-muted-foreground">{formatWhen(k.firstSeenAt)}</TableCell>
                <TableCell className="whitespace-nowrap text-muted-foreground">{formatWhen(k.lastSeenAt)}</TableCell>
                <TableCell>
                  <RowMenu label={address(k)}>
                    <DropdownMenuItem onSelect={() => void copyFingerprint(k)}>
                      <CopyIcon />
                      Copy the fingerprint
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      variant="destructive"
                      disabled={readOnly !== null}
                      onSelect={() => setRemoving(k)}
                    >
                      <Trash2Icon />
                      Remove the key…
                    </DropdownMenuItem>
                  </RowMenu>
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
      {removing && (
        <ConfirmDialog
          title={`Remove the key of ${address(removing)}?`}
          description="The next connection shows its fingerprint and asks again. Remove a key only when you know why it changed, such as a rebuilt host."
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
