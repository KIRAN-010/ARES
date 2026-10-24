# VirtualBox recovery adapter

The adapter is real command-execution code but was tested using a fake driver in the development environment. Validate it against a disposable VM before demonstrating it. The controller must run **on the host where VBoxManage manages the VM**. A Kali guest normally cannot manage its outer VirtualBox host; use a Linux host controller or a deliberately configured virtualization lab.

## Prepare a disposable guest

1. Create an isolated VM with synthetic data only. Use an internal or host-only network and disable shared folders, shared clipboard and drag-and-drop. Do not connect an unknown sample to bridged networking.
2. Install your harmless workload and guest telemetry collection. Shut down cleanly and create a known-clean snapshot.
3. Find exact UUIDs using read-only commands:

```bash
VBoxManage list vms
VBoxManage snapshot YOUR_VM_UUID list --machinereadable
```

4. Export settings in the controller shell and start MJ:

```bash
export MJ_ENABLE_VM=1
export MJ_VM_ALLOWLIST=YOUR_LOWERCASE_VM_UUID
.venv/bin/mj serve
```

5. Register kind `vm`, its owned lab IP, only permitted ports, its VM UUID and clean snapshot UUID. The placeholder values above must be replaced with actual UUIDs.

## Actions

| Action | Preconditions | Execution | Verification |
|---|---|---|---|
| `vm_quarantine` | Running, allowlisted VM with a connected adapter | Disconnect each enabled adapter's cable | All applicable cable states are off |
| `vm_reconnect` | Running VM; earlier verified quarantine | Restore the adapter states captured by that quarantine | Cable states match captured values |
| `vm_restore` | Powered-off VM; registered snapshot UUID | `VBoxManage snapshot UUID restore SNAPSHOT_UUID` | Current snapshot UUID and powered-off state match |

Each action requires a separate operator approval. A quarantine proposal preserves the pre-action adapter state and references recent events. Partial network failures trigger a best-effort restoration of earlier cable states, followed by verification.

Snapshot restore discards post-snapshot changes and has no general automatic compensation. The tool does not force-poweroff the VM or silently take an extra snapshot. The operator must preserve any needed disk/memory evidence first. Successful hypervisor verification does not mean guest applications are healthy or every artifact of compromise is gone; run independent health checks afterward.

The Helpbot can propose quarantine after suspicious events on a registered VM. Snapshot restore/reconnect are explicit operator proposals in Recovery, avoiding an agent-driven destructive recovery chain. Network quarantine is not full VM containment if host integration channels remain enabled.

Command contract reference: [Oracle VirtualBox VBoxManage documentation](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/vboxmanage.html).
