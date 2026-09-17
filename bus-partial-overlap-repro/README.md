# crosvm bus partial-overlap repro

Defensive VMM research materials for a Firecracker-style bus containment gap in crosvm:

- `Bus::get_device` matches on access **start** only; full `data` len is forwarded to the device.
- Guest MMIO/PIO exits can deliver `(addr, len)` that starts in-range and extends past the registration.
- Concrete host impact found: **VFIO platform** `region_read`/`region_write` **panic DoS** when access spans past region end. PCI VFIO BARs are mitigated by full BAR containment.
- Secondary: `PciVirtualConfigMmio::read` can panic on undersized reads.

## Contents

| Path | What |
|------|------|
| `guest-module/` | Out-of-tree Linux kmod (`target=vfio\|pci_vcfg\|cmos\|all`) |
| `DEVICE_LEN_AUDIT.md` | Device handler len-check audit |
| `DEVICE_HANDLERS.md` | CMOS/PIC/i8042/virtio-mmio outcomes |
| `PANIC_REPRO.md` | How to trigger host panic DoS |
| `REPORT.md` | Overall findings |
| `bus_partial_overlap_test_excerpt.rs` | Unit test documenting bus footgun |

**Not an escape / RCE payload.** Impact demonstrated is panic DoS (and contract hygiene).

Upstream crosvm: https://github.com/google/crosvm
