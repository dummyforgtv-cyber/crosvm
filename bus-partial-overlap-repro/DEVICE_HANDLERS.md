# Host behavior when guest triggers Bus partial-overlap

Checkout: `/workspace/crosvm` @ `da53811`.

Dispatch (unchanged): `get_device` only checks `offset < range.len`
(`devices/src/bus.rs:433-441`); `Bus::read`/`write` (`:735`, `:777`) pass
the **full** `data` slice. Guest path:
`vcpu.rs:375-397` ← KVM `handle_io`/`handle_mmio` (`hypervisor/.../kvm/mod.rs:1170-1220`).

## CMOS / RTC — `0x70` len `2`

- Registration: `x86_64/src/lib.rs:2159` — `io_bus.insert(..., 0x70, 0x2)`.
- Handler: `devices/src/cmos.rs:311-400`.

| Guest access | Bus call | Handler result |
|--------------|----------|----------------|
| `inl 0x70` (len=4) | `Cmos::read` offset=0, len=4 | **Ignore** — `if data.len() != 1 { return; }` (`:357-359`). Buffer already zeroed by `Bus::read`. |
| `outl 0x70` (len=4) | `Cmos::write` offset=0, len=4 | **Ignore** — same check (`:312-314`). |
| `inl 0x71` (len=4) | offset=1, len=4 (2 bytes past reg) | **Ignore** — len≠1. |
| `inb` with offset∉{0,1} | N/A via this registration | Would **panic** (`:347`, `:398`) but bus cannot produce offset≥2 while range.len=2. |

**No stack buffer, no log on oversized len, no panic on the guest-reachable oversize path.**

## i8042 — `0x61` len `4` or `0x62` len `3`

- Registration: `x86_64/src/lib.rs:2106-2109`.
- Handler: `devices/src/i8042.rs:39-58`.

Only acts when `data.len() == 1` and `address` is `0x61` or `0x64`.
Oversized `inl`/`outl`: **silent no-op** (no warn). If PIT owns speaker
(`0x62`/`0x3`), `inl @ 0x62` is a true range overrun but still ignored by
the len==1 guard.

## PIC — `0x20`/`0xa0`/`0x4d0` each len `2`

- Registration: `devices/src/irqchip/kvm/x86_64.rs:667-669`.
- Handler: `devices/src/irqchip/pic.rs:104-137`.

`inl 0x20` (len=4): **warn** `"PIC: Bad read size: 4"` and return
(`:121-123`). Same for write (`:105-107`). No panic, no OOB.

## PIT — `0x40` len `8`, speaker `0x61` len `1`

- Handler: `devices/src/pit.rs:218-259` — same pattern: len≠1 → **warn** + return.

## virtio-mmio — region `0x200`

- Size: `virtio_mmio_device.rs:42`.
- Gate: read/write require `data.len() == 4` else **warn** + return (`:174-180`, `:233-239`).
- 4-byte access at offset `0x1FE` (start in-range, 2 bytes past end): accepted by len gate; `offset >= VIRTIO_MMIO_CONFIG (256)` → `device.read_config(0xFE, data)` (`:183-186`).
- `copy_config` (`virtio/mod.rs:232-244`) uses `slice::get` / `get_mut` and truncates — **no OOB** identified.

## Honesty bar

| Finding | Verdict |
|---------|---------|
| Guest can force Bus to call device with overrun len | **Yes** |
| Concrete device memory OOB / RCE in CMOS, PIC, i8042, virtio-mmio `copy_config` | **Not found** |
| Host panic on these oversize paths | **No** (CMOS panic only on impossible offset) |
| Best description | Contract bug / defense-in-depth gap; device handlers mostly len-filter |

Guest module: `guest-module/` (PIO always; MMIO via `mmio_base=`).
