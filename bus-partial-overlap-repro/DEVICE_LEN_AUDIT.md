# Device handler `data.len()` audit (Bus partial-overlap follow-on)

Checkout: `/workspace/crosvm` @ `da53811` (`da538111ff153bb5c95cfcc5a736d0cb18af3f1d`).

Scope: `BusDevice` / `BusDeviceSync` `read`/`write` under `devices/`, plus callees they feed with the guest `data` slice. Threat model: guest MMIO/PIO exit → `Bus::read`/`write` dispatches on **start address only** (`devices/src/bus.rs:433-441`) and forwards the **full** `data` slice (`:735`, `:777`), so `[offset, offset+len)` may extend past the device registration (and past device-internal region size).

---

## Verdict

**YES — genuine unsafe handlers found.**

Not memory corruption / RCE in the audited paths. Concrete host **panic DoS** when a guest-sized access starts inside a VFIO platform MMIO region and extends past the region end. Secondary panic bugs exist (wrong-size / empty slice) that are adjacent but not the classic “oversized past registration” shape.

**FC-style bus containment** therefore upgrades from **hygiene-only** to **blocks a concrete bug** (at least the VFIO platform panic DoS). Still not proven host memory corruption.

---

## RISKY findings

| # | Device / path | Class | File:line | Guest trigger | Impact |
|---|---------------|-------|-----------|---------------|--------|
| 1 | **VfioPlatformDevice** → `VfioDevice::region_{read,write}` | RISKY | `devices/src/platform/vfio_platform.rs:160-170` (`find_region` start-only), `:334-353` (`read_mmio`/`write_mmio`); `devices/src/vfio.rs:1818-1828`, `:1855-1868` | MMIO start in region, `len` past end (e.g. 8-byte access at `region_end-4`). Bus still dispatches; `find_region` accepts; `region_*` then panics. Hits on first trap before lazy mmap, and on any non-mmapable region always. | **Host panic DoS** (process abort). No OOB copy — panics *before* `read_exact_at` / `write_all_at`. |
| 2 | **PciVirtualConfigMmio::read** | RISKY | `devices/src/pci/pci_root.rs:920-936` | Any read with `data.len() != 4` (or unaligned offset). **Oversized** (`len=8`): logs then `data[0..4].copy_from_slice` — no panic. **Undersized** (`len=1`/`2`): **panic** on `data[0..4]`. Write path correctly `return`s (`:939-947`). | Panic DoS on undersized MMIO read; oversized is logic/log noise only. |
| 3 | **ProxyDevice::{read,write}** | RISKY (latent) | `devices/src/proxy.rs:569-587` | `write`: `buffer[0..data.len()]` into `[u8; 8]` → panic if `len > 8`. `read`: `buffer[0..len]` same bound. | Panic if bus ever sees `len>8`. **Normal KVM MMIO/PIO exits are ≤8**, so not the partial-overlap DoS; still a fixed-size assumption. |
| 4 | **Pflash::write** | RISKY (edge) | `devices/src/pflash.rs:142-147` | `data.len() > 1` rejected; **`len == 0`** still does `data[0]`. | Panic on empty slice. KVM does not issue `len=0`; oversized writes are ignored (SAFE for overlap). |

### #1 detail (primary)

```text
Bus::get_device: offset < range.len          // start only
  → VfioPlatformDevice::read/write
  → find_region(addr): start ∈ [start, start+length)   // end unchecked
  → region_read/write(index, data, offset)
       if addr + data.len() > stub.size { panic!(...) }
```

Same panic helpers are used from **VFIO PCI** `read_bar`/`write_bar` (`devices/src/pci/vfio_pci.rs:2031-2072`), but the generic `PciDevice` `BusDevice` impl requires **full BAR containment** via `find_bar_and_offset` (`devices/src/pci/pci_device.rs:557-620`) before calling `read_bar`/`write_bar`. So **PCI VFIO is mitigated for this overlap class**; **platform VFIO is not**.

No host memory corruption identified on this path — impact is DoS.

---

## Notable SAFE / BOUNDED patterns

| Device | Pattern | Cite |
|--------|---------|------|
| CMOS | `if data.len() != 1 { return; }` before `data[0]` | `devices/src/cmos.rs:312-314`, `:357-359` |
| PIC | `len != 1` → warn + return | `devices/src/irqchip/pic.rs:105-107`, `:121-123` |
| PIT | same | `devices/src/pit.rs:221-223`, `:238-240` |
| i8042 | compound `data.len() == 1 && …` | `devices/src/i8042.rs:40-50` |
| Serial / Debugcon | `len != 1` early return | `devices/src/serial.rs:454-456`, `:471-473`; `devices/src/debugcon.rs:68-81` |
| ACPIPM | per-register `data.len()` + `offset+len` within register window before index/copy | `devices/src/acpi.rs:494-553`, `:564-667` |
| Ioapic | reject empty/`len>8`; IOWIN write requires `len==4`; read copies min(4, len) | `devices/src/irqchip/ioapic.rs:161-211` |
| APIC (userspace) | `valid_mmio`: aligned + `len==4` else return before `copy_from_slice` / `try_into` | `devices/src/irqchip/apic.rs:190-233` |
| virtio-mmio | `len != 4` warn+return; config uses `copy_config` (`get`/`min`) | `devices/src/virtio/virtio_mmio_device.rs:173-180`, `:232-239`; `devices/src/virtio/mod.rs:232-244` |
| Pl030 / Vmwdt / VirtCpufreqV2 write | `try_from` / `try_into` → warn+return | e.g. `devices/src/pl030.rs:100-106` |
| Goldfish battery / VirtualPmc | exact `size_of::<u32>()` gate before `copy_from_slice` | `devices/src/bat.rs:547-553`, `:617-623`; `devices/src/pmc_virt.rs:60-66`, `:73-79` |
| PciConfigIo / PciConfigMmio | reject / fill `0xff` when access crosses dword boundary (`start+len > 4`) | `devices/src/pci/pci_root.rs:711-721`, `:821-829`; config write `offset+len > 4` early return (`:385-386`, `:667-668`) |
| **PciDevice BARs** | `find_bar_and_offset` requires `[addr, addr+len) ⊆ BAR` | `devices/src/pci/pci_device.rs:557-620` — secondary containment for all `PciDevice` MMIO BARs (virtio-pci, GPU, VFIO-PCI, …) |
| FwCfg | read `len!=1` NOP; selector write `len!=2` NOP | `devices/src/fw_cfg.rs:297-326` |
| Pflash read | `offset + data.len() >= image_size` → error return (no copy) | `devices/src/pflash.rs:115-117` |

---

## What was *not* found

- No guest-reachable **unchecked `copy_from_slice` into a fixed stack/heap buffer larger than `data`** that would corrupt adjacent host memory on oversized `data` from this bus footgun.
- Common x86 PIO toys (CMOS, PIC, PIT, i8042, serial) **filter length** and ignore oversized accesses.
- Virtio-mmio rejects non-4-byte sizes; config path is slice-bounded.
- PCI BAR devices get an extra full-containment check even when the bus does not.

---

## FC bus containment vs this audit

| Prior framing | Updated |
|---------------|---------|
| Hygiene / defense-in-depth; devices mostly len-filter | **Still true for most devices** |
| No concrete device bug pinned | **Superseded:** platform VFIO `region_read`/`region_write` **panic** on end-past-region is guest-triggerable given bus start-only dispatch |
| Severity | **DoS (panic), not memory corruption / RCE** from findings above |

Porting FC’s “whole access must lie in range” check **blocks finding #1** at the bus (and would also stop odd oversized deliveries to #2/#3). It does **not** by itself fix undersized `PciVirtualConfigMmio::read` (`len<4`) or empty `Pflash::write` — those need local `return` after the length check (write already does; read does not).

---

## Method notes

- Enumerated `impl BusDevice` / `BusDeviceSync` under `devices/`.
- Grepped for `data[i]`, `copy_from_slice`, `try_into().unwrap`, fixed `[u8; N]` fills, and `panic!` near handlers.
- Prioritized guest-reachable IO/MMIO registrations; treated test-only mocks as out of scope.
- Did not invent findings; lines cited against tip `da53811`.
