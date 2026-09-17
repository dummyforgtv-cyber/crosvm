# crosvm Bus partial-overlap — reproducer + reachability

Checkout: `/workspace/crosvm` @ `da538111ff153bb5c95cfcc5a736d0cb18af3f1d` (`da53811`)

## Guest-reachable? **YES**

Guest MMIO/PIO exits feed `(address, data.len())` into `Bus::read`/`write` with **no** check that `[addr, addr+len)` ⊆ device range.

### Evidence (file:line)

| Step | Location |
|------|----------|
| Start-only device lookup | `devices/src/bus.rs:433-441` (`get_device`: `offset < range.len`) |
| Full slice forwarded | `devices/src/bus.rs:735` `read`, `:777` `write` → device gets entire `data` |
| MMIO exit → bus | `src/crosvm/sys/linux/vcpu.rs:389-397` (`VcpuExit::Mmio` → `mmio_bus.read/write`) |
| PIO exit → bus | `src/crosvm/sys/linux/vcpu.rs:375-383` (`VcpuExit::Io` → `io_bus.read/write`) |
| KVM supplies len | `hypervisor/src/kvm/mod.rs:1170-1182` (`handle_mmio`: `mmio.data[..mmio.len]`); `:1196-1208` (`handle_io`: `io.size`) |
| virtio-mmio 4-byte gate | `devices/src/virtio/virtio_mmio_device.rs:174-180`, `:233-239`; region `VIRTIO_MMIO_REGION_SZ = 0x200` at `:42` |
| Small PIO ranges | CMOS `0x70`/`0x2` — `x86_64/src/lib.rs:2159`; i8042 `0x062`/`0x3` or `0x061`/`0x4` — `:2107-2109`; PIC `0x20`/`0x2` — `devices/src/irqchip/kvm/x86_64.rs:667` |

**Adjacent-device sketch:** guest 8-byte MMIO at `A_end-4` with A|B abutting → one `KVM_EXIT_MMIO` `len=8` (GPAs outside memslots) → crosvm invokes **only A** with overrun; B never sees bytes (unit test asserts this).

**virtio-mmio:** rejects `len != 4`, so wrong-sized overruns no-op there; a **4-byte** access at offset `0x1FE` into a `0x200` region still starts in-range and extends past registration. Does **not** make all guest partial overruns impossible.

## Host panic DoS (device-len audit follow-on)

See **`DEVICE_LEN_AUDIT.md`** and **`PANIC_REPRO.md`**.

| Target | Guest trigger | Host impact |
|--------|---------------|-------------|
| **VfioPlatformDevice** (PRIMARY) | `readq`/`writeq` at `region_end-4` | `region_read`/`region_write` panic (`vfio.rs:1818-1868`) |
| **PciVirtualConfigMmio** (SECONDARY) | `readb`/`readw` on VCFG MMIO | `data[0..4]` panic (`pci_root.rs:920-936`) |
| PCI VFIO BARs | same shape | **Mitigated** — `find_bar_and_offset` full containment |

Guest module `target=vfio` / `target=pci_vcfg` is the live repro. Impact: **DoS only**, not RCE.

## Unit test

- **Full path:** `/workspace/crosvm/devices/src/bus.rs`
- **Test name:** `bus::tests::bus_partial_overlap_past_device_range_still_dispatches`
- **Proves:** bus API footgun (not a live guest binary). Start in A, end past A into B's addresses → A still called with full len; B untouched; `read` returns `true`.
- **On tip:** **PASS** (asserts current unsafe contract). Would need flipped expectations if FC-style reject lands.

### Dylan repro

```bash
cd /workspace/crosvm  # or clone https://github.com/google/crosvm && cd crosvm
git submodule update --init third_party/minijail
# rust-toolchain pins 1.88.0; also need make, libcap-dev, libclang-dev
cargo test -p devices --features test-util \
  bus_partial_overlap_past_device_range_still_dispatches -- --nocapture
```

Captured log: `./crosvm-bus-partial-overlap-test.log` (this directory).

## vs Firecracker `753888c`

FC bus requires the whole access to fall inside the device range before dispatch. crosvm has no equivalent. FC-style containment **blocks the VFIO platform panic DoS** at the bus.

## Recommendation

**Do not treat as host-only / deprioritize on that basis** — guest can hit the bus path via MMIO/PIO exits, and platform VFIO yields a concrete host panic.

Porting the FC containment check is **reasonable hygiene** and now **blocks a known DoS**. Still frame severity as panic DoS pending any further memory-safety findings — not "P0 RCE proven."

## Device-handler outcomes (host)

See **`DEVICE_HANDLERS.md`** (CMOS/PIC/i8042/virtio-mmio) and **`DEVICE_LEN_AUDIT.md`** (VFIO / pci_vcfg / ProxyDevice / Pflash).

## Guest module

Path: **`guest-module/`** (`bus_partial_overlap.c`, Makefile, README). Panic procedure: **`PANIC_REPRO.md`**.

```bash
# Inside x86_64 guest with matching headers:
cd guest-module && make

# Safe bus-footgun demo (host lives):
sudo insmod ./bus_partial_overlap.ko target=cmos

# PRIMARY — kill crosvm if --vfio-platform mapped at GPA:
sudo insmod ./bus_partial_overlap.ko target=vfio \
  vfio_base=0x<gpa> vfio_len=0x<len>

# SECONDARY — undersized VCFG read (stock x86_64 crosvm):
sudo insmod ./bus_partial_overlap.ko target=pci_vcfg \
  pci_vcfg_base=0x100000000   # or ACPI VCFG

dmesg | tail -30
sudo rmmod bus_partial_overlap   # only if host survived
```
