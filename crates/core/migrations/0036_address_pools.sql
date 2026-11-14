-- 0.8.0 G6: address pools (VM-32), static addresses for unattended deploys.
--
-- address_pools
--   A range of IPv4 addresses on one network of one hypervisor, per workspace (rule 5), each row with its user. `network`
--   is the launch templates' network as JSON (remotely_core::catalog::templates::Network, `{"kind": "nat"}`,
--   `{"kind": "vmnet", "number": 2}`...); `host_adapter` names VirtualBox's host-only adapter for a VirtualBox host-only
--   pool (NULL for every other); `network_key` is the network of this PC it resolves to through VM-11's host network
--   report (`bridged` for any bridged network, `vmware:vmnet8` for Workstation's NAT, host-only and custom vmnets,
--   `virtualbox:hostonly:<adapter>`), the same in every workspace, refreshed whenever the pool is used. `first_ip` and
--   `last_ip` are dotted IPv4 text in one subnet of `prefix` (/8 to /30), neither its network nor its broadcast address,
--   at most 4096 addresses; `gateway` (optional) is in that subnet; `dns` is JSON ["192.0.2.53", ...], at most 3. The
--   gateway and the DNS servers are never handed out. Names are unique per workspace (and without letter case, also
--   beyond ASCII, in crate::address_pools). Adding, changing and deleting one is audited (`address_pool_changed`, no
--   approval tier) and refused by the read-only lock. Not in the trash and not in FD-07 exports: a pool describes this
--   PC's networks, and its leases the VMs made here.
--
-- address_leases
--   An address that is taken on a network of this PC: `claimed` by a deploy job while it makes the VM (`job_id`,
--   `vm_name`, no `vm_key` yet), then `assigned` to the VM it made (`vm_key`, the VM's key as `vms.vmx_path`; required).
--   One row per address and network across all workspaces (UNIQUE(network_key, ip)): workspaces keep their own pools,
--   but this PC's NAT, host-only and bridged networks are the PC's, so of two deploys claiming one address, in one
--   workspace or two, the second insert finds it taken. A claim whose job isn't open any more (cancelled, failed, or the
--   app stopped) counts as free at once and goes when the address is claimed again, and at start after a day. A lease
--   stays the VM's until the VM is deleted (Remotely's delete, a stack teardown included, frees it, whatever workspace has
--   the VM now). A pool with leases can't be deleted, so ON DELETE CASCADE never finds one.

CREATE TABLE address_pools (
    id            TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL COLLATE NOCASE,
    hypervisor    TEXT NOT NULL CHECK (hypervisor IN ('vmware', 'virtualbox')),
    network       TEXT NOT NULL,
    host_adapter  TEXT,
    network_key   TEXT NOT NULL COLLATE NOCASE,
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

CREATE INDEX address_pools_by_network ON address_pools (network_key);

CREATE TABLE address_leases (
    pool_id       TEXT NOT NULL REFERENCES address_pools(id) ON DELETE CASCADE,
    workspace_id  TEXT NOT NULL REFERENCES workspaces(id),
    user_id       TEXT NOT NULL REFERENCES users(id),
    network_key   TEXT NOT NULL COLLATE NOCASE,
    ip            TEXT NOT NULL,
    vm_key        TEXT COLLATE NOCASE,
    vm_name       TEXT NOT NULL,
    job_id        TEXT,
    state         TEXT NOT NULL CHECK (state IN ('claimed', 'assigned')),
    created_at    TEXT NOT NULL,
    CHECK (state = 'claimed' OR vm_key IS NOT NULL),
    UNIQUE (pool_id, ip),
    UNIQUE (network_key, ip)
);

CREATE INDEX address_leases_by_workspace ON address_leases (workspace_id, pool_id);
CREATE INDEX address_leases_by_vm ON address_leases (vm_key);
CREATE INDEX address_leases_by_job ON address_leases (job_id);
