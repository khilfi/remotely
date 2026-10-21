-- 0.4.0 Q5: VM-18 Oracle VirtualBox VMs next to VMware Workstation ones.
--
-- vms.vmx_path stays the VM's key and the target key in jobs and the audit log: a VMware VM's .vmx
-- path, or a VirtualBox VM's UUID (lower case, no braces), which VBoxManage takes and which stays the
-- same when the VM is renamed or moved. No .vmx path can be a UUID, so the two never collide.
--   hypervisor   which hypervisor runs the VM; every VM found before 0.4.0 is a Workstation VM.
--   config_path  a VirtualBox VM's settings file (.vbox); NULL for VMware, whose .vmx is the key.
ALTER TABLE vms ADD COLUMN hypervisor TEXT NOT NULL DEFAULT 'vmware'
    CHECK (hypervisor IN ('vmware', 'virtualbox'));
ALTER TABLE vms ADD COLUMN config_path TEXT;
