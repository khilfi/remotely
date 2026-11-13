-- 0.8.0 G6: address pools (VM-32), static addresses for unattended deploys.
--
-- address_pools
--   A range of IPv4 addresses on one network of one hypervisor, per workspace (rule 5), each row with its user. `network`
--   is the launch templates' network as JSON (remotely_core::catalog::templates::Network, `{"kind": "nat"}`,
--   `{"kind": "vmnet", "number": 2}`...); `first_ip` and `last_ip` are dotted IPv4 text in one subnet of `prefix`
--   (/8 to /30), neither its network nor its broadcast address, at most 4096 addresses; `gateway` (optional) is in that
--   subnet; `dns` is JSON ["192.0.2.53", ...], at most 3. The gateway and the DNS servers are never handed out. Names are
--   unique per workspace. Adding, changing and deleting one is audited (`address_pool_changed`, no approval tier) and
--   refused by the read-only lock (crate::address_pools). Not in the trash and not in FD-07 exports: a pool describes this
--   PC's networks, and its leases the VMs made here.
--
-- address_leases
--   An address of a pool that is taken: `claimed` by a deploy job while it makes the VM (`job_id`, `vm_name`, no
--   `vm_key` yet), then `assigned` to the VM it made (`vm_key`, the VM's key as `vms.vmx_path`). One row per address
--   (UNIQUE(pool_id, ip)): of two deploys claiming one address, the second insert finds it taken. A lease stays the VM's
--   until the VM is deleted (Remotely's delete, a stack teardown included, frees it, whatever workspace has the VM now);
--   a claim the app left (a restart mid-deploy) goes after a day. A pool with leases can't be deleted; ON DELETE
--   CASCADE only covers the rows of one deleted with none.

CREATE TABLE address_pools (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL COLLATE NOCASE,
    hypervisor    TEXT NOT NULL CHECK (hypervisor IN ('vmware', 'virtualbox')),
    network       TEXT NOT NULL,
    first_ip      TEXT NOT NULL,
    last_ip       TEXT NOT NULL,
    prefix        INTEGER NOT NULL CHECK (prefix BETWEEN 8 AND 30),
    gateway       TEXT,
    dns           TEXT NOT NULL DEFAULT '[]',
    notes         TEXT,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (workspace_id, name)
);

CREATE TABLE address_leases (
    pool_id       TEXT NOT NULL REFERENCES address_pools(id) ON DELETE CASCADE,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    ip            TEXT NOT NULL,
    vm_key        TEXT COLLATE NOCASE,
    vm_name       TEXT NOT NULL,
    job_id        TEXT,
    state         TEXT NOT NULL CHECK (state IN ('claimed', 'assigned')),
    created_at    TEXT NOT NULL,
    UNIQUE (pool_id, ip)
);

CREATE INDEX address_leases_by_workspace ON address_leases (workspace_id, pool_id);
CREATE INDEX address_leases_by_vm ON address_leases (vm_key);
