# Host panic reproduction notes

Checkout: `/workspace/crosvm` @ `da538111ff153bb5c95cfcc5a736d0cb18af3f1d` (`da53811`).

Defensive VMM verification only — **DoS (process abort), not RCE / escape**.

Guest module: `guest-module/bus_partial_overlap.c` (`target=vfio` / `pci_vcfg`).

---

## 1. PRIMARY — VfioPlatformDevice / region_read|write

### Panic conditions (source)

| Step | File:line | Behavior |
|------|-----------|----------|
| Bus start-only dispatch | `devices/src/bus.rs:433-441` | `offset < range.len` only |
| Full slice to device | `devices/src/bus.rs:735`, `:777` | entire `data` forwarded |
| Platform `read`/`write` | `devices/src/platform/vfio_platform.rs:68-74` | → `read_mmio` / `write_mmio` |
| `find_region` | `vfio_platform.rs:160-170` | **start** in `[start, start+length)` only — end unchecked |
| `read_mmio` | `vfio_platform.rs:334-338` | `region_read(index, data, offset)` then lazy mmap |
| `write_mmio` | `vfio_platform.rs:345-349` | `region_write(...)` then lazy mmap |
| **PANIC read** | `devices/src/vfio.rs:1818-1828` | `if size > stub.size \|\| addr + size > stub.size { panic!(...) }` |
| **PANIC write** | `devices/src/vfio.rs:1855-1868` | same size check (+ write flag) |

MMIO registration: `arch/src/sys/linux.rs:251-254` inserts each
`allocate_regions` range onto `mmio_bus` (`vfio_platform.rs:173-198`).

### Guest trigger

```text
GPA = vfio_platform_region_base
LEN = region size (bytes)

readq  at GPA + LEN - 4     # 8-byte: start in-range (LEN>=4), end = GPA+LEN+4
readl  at GPA + LEN - 2     # 4-byte alternate
writeq at GPA + LEN - 4     # optional; region_write same panic
```

Module:

```bash
sudo insmod ./bus_partial_overlap.ko target=vfio \
  vfio_base=0x<GPA> vfio_len=0x<LEN>
```

### Expected host abort message

```text
tried to read VFIO region with invalid arguments: index=..., addr=0x..., size=0x8
```

or for write:

```text
tried to write VFIO region with invalid arguments: index=..., addr=0x..., size=0x8
```

Typical stack (symbols vary with opt level):

```text
VfioDevice::region_read
VfioPlatformDevice::read_mmio
VfioPlatformDevice::read   (BusDevice)
Bus::read
... vcpu MMIO exit path ...
```

### Why PCI VFIO will not hit this

Same `region_read`/`region_write` helpers are used from
`devices/src/pci/vfio_pci.rs` BAR paths, but generic `PciDevice` `BusDevice`
impl requires **`[addr, addr+len) ⊆ BAR`** via `find_bar_and_offset`
(`devices/src/pci/pci_device.rs:557-620`) before `read_bar`/`write_bar`.
Partial-overlap past BAR end → no BAR match → error log, **no** `region_*`.

Only **`--vfio-platform`** / `VfioPlatformDevice` lacks that containment.

### Timing caveat

`read_mmio` calls `region_read` **then** `regions_mmap()`. First trap with
oversized `data` panics **before** mmap. If a prior in-bounds access already
mmap'd the region into stage-2, later guest accesses may not exit to crosvm;
the spanning probe must still take the trap path (fresh VM / first touch).

Non-mmapable regions always stay on the `region_*` path.

---

## 2. SECONDARY — PciVirtualConfigMmio::read undersized

### Guest-reachable? **YES** (normal x86_64 crosvm)

| Step | File:line |
|------|-----------|
| Range helper | `x86_64/src/lib.rs:1989-1996` — `start = max(ram_end_2MB, 4*GB)`; len = `2 * pcie_cfg_mmio.len` |
| Bus insert | `x86_64/src/lib.rs:1145-1152` |
| ACPI hint | `x86_64/src/lib.rs:2244-2248` — AML Name **`VCFG`** = start |
| **PANIC** | `devices/src/pci/pci_root.rs:920-936` — logs if `len != 4`, then `data[0..4].copy_from_slice` always |
| Write safe | `pci_root.rs:939-947` — early `return` on bad len |

Default ECAM size `0x400_0000` (`DEFAULT_PCIE_CFG_MMIO_SIZE`); VCFG window
is twice that. When guest RAM &lt; 4GiB, VCFG base is often **`0x100000000`**.

### Guest trigger

```bash
sudo insmod ./bus_partial_overlap.ko target=pci_vcfg \
  pci_vcfg_base=0x100000000   # or ACPI VCFG value
```

`readb` → `len=1` → panic; `readw` → `len=2` → same.

### Expected host behavior

1. `error!(... unexpected read ... len = 1)`
2. Panic / bounds abort on `data[0..4]` (slice index), e.g. Rust panic
   attempting to copy 4 bytes into a 1-byte buffer.

**Not** the classic “oversized past registration” shape: undersized access
anywhere in the VCFG window. Oversized `len=8` logs then copies 4 bytes — no
panic.

---

## 3. Non-panic probes (still valid bus-footgun demos)

CMOS / PIC / i8042 / virtio-mmio: see `DEVICE_LEN_AUDIT.md` SAFE table.
`target=cmos` or `target=mmio` — host should keep running.

---

## Dylan quick checklist

1. Build guest module against guest headers.
2. Start crosvm with **`--vfio-platform`** device; note MMIO GPA + size.
3. In guest, **before** other drivers hammer that MMIO:
   `insmod ... target=vfio vfio_base=... vfio_len=...`
4. Confirm host process aborted with VFIO region panic string.
5. Optional: `target=pci_vcfg pci_vcfg_base=...` on a stock VM (no VFIO needed).
6. Document: impact = DoS; FC-style bus containment would block #1 at the bus.
