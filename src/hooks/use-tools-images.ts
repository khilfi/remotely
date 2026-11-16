// VM-15: the VMware Tools images beside vmrun.exe (Workstation 26 has only windows.iso), read once per mount. null
// until read, when Workstation's folder isn't known, or when the read failed: then the guest alone decides
// (src/lib/vm-settings.ts vmwareToolsReason), as the core does when the command runs.

import { useEffect, useState } from "react";
import { api } from "@/lib/api";

export function useToolsImages(enabled = true): string[] | null {
  const [images, setImages] = useState<string[] | null>(null);
  useEffect(() => {
    if (!enabled) return;
    let live = true;
    api.vmToolsImages().then(
      (found) => {
        if (live) setImages(found);
      },
      () => {
        if (live) setImages(null);
      },
    );
    return () => {
      live = false;
    };
  }, [enabled]);
  return images;
}
