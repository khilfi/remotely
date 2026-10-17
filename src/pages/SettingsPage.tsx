// Settings: the vmrun.exe path (configurable, never hard-coded), the folders scanned for VMs (VM-01),
// power action limits (VM-06) and update checks (FD-14). The theme switch is in the top bar.

import { useEffect, useState } from "react";
import { FolderIcon, XIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { api, errorMessage, type Settings } from "@/lib/api";

interface Props {
  /** Called after a setting changes, so the sidebar status and update banner refresh. */
  onChanged: () => void;
}

type Message = { ok: boolean; text: string } | null;

function StatusLine({ message }: { message: Message }) {
  if (!message) return null;
  return (
    <p className={message.ok ? "text-sm text-muted-foreground" : "text-sm text-destructive"} role="status">
      {message.text}
    </p>
  );
}

export function SettingsPage({ onChanged }: Props) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [path, setPath] = useState("");
  const [vmrunMessage, setVmrunMessage] = useState<Message>(null);
  const [updateMessage, setUpdateMessage] = useState<Message>(null);
  const [newFolder, setNewFolder] = useState("");
  const [folderMessage, setFolderMessage] = useState<Message>(null);
  const [powerOnLimit, setPowerOnLimit] = useState("");
  const [powerMessage, setPowerMessage] = useState<Message>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    api.settings().then(
      (s) => {
        setSettings(s);
        setPath(s.vmrunPathSaved ?? "");
        setPowerOnLimit(String(s.powerOnLimit));
      },
      (err) => setVmrunMessage({ ok: false, text: errorMessage(err) }),
    );
  }, []);

  async function saveVmrun(next: string | null) {
    try {
      const s = await api.setVmrunPath(next);
      setSettings(s);
      setPath(s.vmrunPathSaved ?? "");
      setVmrunMessage({
        ok: s.vmrunPathInUse !== null,
        text: s.vmrunPathInUse ? `Using ${s.vmrunPathInUse}` : "vmrun.exe was not found",
      });
      onChanged();
    } catch (err) {
      setVmrunMessage({ ok: false, text: errorMessage(err) });
    }
  }

  async function saveFolders(folders: string[]) {
    try {
      const s = await api.setScanFolders(folders);
      setSettings(s);
      setNewFolder("");
      setFolderMessage(null);
      onChanged();
    } catch (err) {
      setFolderMessage({ ok: false, text: errorMessage(err) });
    }
  }

  async function savePowerActions() {
    try {
      const s = await api.setPowerOnLimit(Number(powerOnLimit));
      setSettings(s);
      setPowerOnLimit(String(s.powerOnLimit));
      setPowerMessage({ ok: true, text: "Saved. Applies from the next action on." });
    } catch (err) {
      setPowerMessage({ ok: false, text: errorMessage(err) });
    }
  }

  async function setUpdateChecks(enabled: boolean) {
    try {
      setSettings(await api.setUpdateChecks(enabled));
      setUpdateMessage(null);
      onChanged();
    } catch (err) {
      setUpdateMessage({ ok: false, text: errorMessage(err) });
    }
  }

  async function checkNow() {
    setChecking(true);
    try {
      const found = await api.checkForUpdate();
      setUpdateMessage({
        ok: true,
        text: found ? `Version ${found.version} is available.` : "You have the latest version.",
      });
      if (found) onChanged();
    } catch (err) {
      setUpdateMessage({ ok: false, text: `Could not check for updates: ${errorMessage(err)}` });
    } finally {
      setChecking(false);
    }
  }

  return (
    <div className="flex max-w-3xl flex-col gap-6">
      <Card>
        <CardHeader>
          <CardTitle>VMware Workstation</CardTitle>
          <CardDescription>
            Every VM action runs through vmrun.exe. Leave the path empty to find it automatically: the registry first,
            then the default install folders.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2">
          <Label htmlFor="vmrun-path">vmrun.exe path</Label>
          <Input
            id="vmrun-path"
            className="font-mono"
            placeholder="Found automatically"
            spellCheck={false}
            value={path}
            onChange={(e) => setPath(e.currentTarget.value)}
          />
          <p className="text-sm text-muted-foreground">
            In use: <span className="font-mono">{settings?.vmrunPathInUse ?? "not found"}</span>
          </p>
          <StatusLine message={vmrunMessage} />
        </CardContent>
        <CardFooter className="gap-2">
          <Button onClick={() => void saveVmrun(path)}>Save</Button>
          <Button variant="outline" onClick={() => void saveVmrun(null)}>
            Find automatically
          </Button>
        </CardFooter>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>VM folders</CardTitle>
          <CardDescription>
            Remotely lists every VM in VMware Workstation&apos;s library. Add folders that hold other VMs; they are
            searched for .vmx files up to five folder levels down.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3">
          {settings && settings.scanFolders.length > 0 && (
            <ul className="grid gap-1">
              {settings.scanFolders.map((folder) => (
                <li key={folder} className="flex items-center gap-2 rounded-md border px-3 py-1.5">
                  <FolderIcon className="size-4 shrink-0 text-muted-foreground" />
                  <span className="min-w-0 flex-1 truncate font-mono text-sm" title={folder}>
                    {folder}
                  </span>
                  <Button
                    size="icon-sm"
                    variant="ghost"
                    aria-label={`Stop scanning ${folder}`}
                    onClick={() => void saveFolders(settings.scanFolders.filter((f) => f !== folder))}
                  >
                    <XIcon />
                  </Button>
                </li>
              ))}
            </ul>
          )}
          <form
            className="flex gap-2"
            onSubmit={(e) => {
              e.preventDefault();
              if (settings && newFolder.trim()) void saveFolders([...settings.scanFolders, newFolder.trim()]);
            }}
          >
            <Label htmlFor="scan-folder" className="sr-only">
              Folder to scan
            </Label>
            <Input
              id="scan-folder"
              className="font-mono"
              placeholder="D:\VMs"
              spellCheck={false}
              value={newFolder}
              onChange={(e) => setNewFolder(e.currentTarget.value)}
            />
            <Button type="submit" variant="outline" disabled={!settings || !newFolder.trim()}>
              Add folder
            </Button>
          </form>
          <StatusLine message={folderMessage} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Power actions</CardTitle>
          <CardDescription>
            Starting many VMs at once can saturate the host&apos;s disk and CPU. Bulk starts power on this many at a
            time; the rest wait their turn.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2">
          <Label htmlFor="power-on-limit">VMs powered on at once</Label>
          <Input
            id="power-on-limit"
            type="number"
            min={1}
            max={32}
            className="w-28"
            value={powerOnLimit}
            onChange={(e) => setPowerOnLimit(e.currentTarget.value)}
          />
          <StatusLine message={powerMessage} />
        </CardContent>
        <CardFooter>
          <Button onClick={() => void savePowerActions()} disabled={!settings}>
            Save
          </Button>
        </CardFooter>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Updates</CardTitle>
          <CardDescription>
            Remotely checks GitHub Releases at start and every 24 hours. Every update is signature-checked, and
            installing always asks first. Turn checks off at air-gapped sites.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3">
          <div className="flex items-center gap-3">
            <Switch
              id="update-checks"
              checked={settings?.updateChecks ?? true}
              disabled={!settings}
              onCheckedChange={(checked) => void setUpdateChecks(checked)}
            />
            <Label htmlFor="update-checks">Check for updates</Label>
          </div>
          <StatusLine message={updateMessage} />
        </CardContent>
        <CardFooter>
          <Button variant="outline" onClick={() => void checkNow()} disabled={checking || !settings?.updateChecks}>
            {checking ? "Checking…" : "Check now"}
          </Button>
        </CardFooter>
      </Card>
    </div>
  );
}
