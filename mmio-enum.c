/*
 * mmio-enum.c
 *
 * Standalone PCI config-space + MMIO emulator.  Sits on the named pipes that
 * thin-server-enum writes to, and answers both config-space (packet_type==1)
 * and MMIO (packet_type==2) transactions for a single virtual device at
 * (dev, fn) = (0, 0):
 *   - config space: same plain memory-controller header as emu-enum.c's
 *     device 0, so run_enum.sh's existing enumeration checks still pass
 *     unmodified when this is swapped in for emu-enum.
 *   - MMIO: a flat backing buffer, addressed BAR-relative -- the incoming
 *     physical address is translated against the BAR0 base this device was
 *     actually assigned (observed in its own cfg[] during the kernel's BAR
 *     sizing/assignment config writes), the same way a real device's
 *     address decoder works against its own programmed BAR register.
 *
 * Replaces the Simics cosim endpoint for testing the MMIO relay path
 * (kernel -> chardev -> daemon-enum -> thin-server-enum -> mmio-enum)
 * without a simulator or RTL.
 *
 * Usage:
 *   CXL_LOG_FILE=logs/mmio_enum.log \
 *   CXL_RELAY_SERVER_PATH=/tmp/cosim_enum_pipes \
 *   ./mmio-enum
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

#include "log.h"

#define PIPE_PATH_ENV "CXL_RELAY_SERVER_PATH"
#define CFG_SIZE      4096
#define MMIO_SIZE     0x10000   /* 64 KiB backing buffer for the one BAR */

/* ------------------------------------------------------------------ */
/*  simics_transaction_t + MAX_PAYLOAD -- shared definition            */
/* ------------------------------------------------------------------ */

#include "simics_transaction.h"

/* ------------------------------------------------------------------ */
/*  Virtual device: one plain memory controller at 00.0                */
/* ------------------------------------------------------------------ */

#define PCI_DEVFN(dev, fn)  ((((dev) & 0x1f) << 3) | ((fn) & 0x07))

static uint8_t cfg[CFG_SIZE];
static uint8_t mmio[MMIO_SIZE];

static void w16(uint8_t *c, int off, uint16_t v)
{
    c[off]     = v & 0xff;
    c[off + 1] = (v >> 8) & 0xff;
}

static void w32(uint8_t *c, int off, uint32_t v)
{
    c[off]     =  v        & 0xff;
    c[off + 1] = (v >>  8) & 0xff;
    c[off + 2] = (v >> 16) & 0xff;
    c[off + 3] = (v >> 24) & 0xff;
}

/*
 * Common PCI type-0 header (mirrors emu-enum.c's device 0):
 *   VID   = 0x8086 (Intel)
 *   Class = 0x050210 (Memory Controller, CXL, prog-if 0x10)
 *   BAR0  = 64-bit memory, PCIe capability at 0x40.
 */
static void build_header(void)
{
    memset(cfg, 0xff, CFG_SIZE);   /* absent registers read as all-ones */
    memset(cfg, 0x00, 0x40);       /* standard header: zero then fill    */

    w16(cfg, 0x00, 0x8086);        /* Vendor ID                          */
    w16(cfg, 0x02, 0x1234);        /* Device ID                          */
    w16(cfg, 0x04, 0x0006);        /* Command: Memory Space + Bus Master */
    w16(cfg, 0x06, 0x0010);        /* Status: Capabilities List present  */
    cfg[0x08] = 0x01;              /* Revision ID                        */
    cfg[0x09] = 0x10;              /* Prog IF: CXL Memory Device         */
    cfg[0x0a] = 0x02;              /* Sub-class: Memory Controller       */
    cfg[0x0b] = 0x05;              /* Base Class: Memory Controller      */
    cfg[0x0e] = 0x00;              /* Header type: type-0, single func   */
    cfg[0x34] = 0x40;              /* Capabilities pointer -> PCIe cap   */

    w16(cfg, 0x2c, 0x8086);        /* Subsystem Vendor ID                */
    w16(cfg, 0x2e, 0x1234);        /* Subsystem Device ID                */

    /* BAR0: 64-bit, memory, non-prefetchable */
    w32(cfg, 0x10, 0x00000004);    /* BAR0 low: 64-bit indicator         */
    w32(cfg, 0x14, 0x00000000);    /* BAR0 high                          */

    /* PCIe Capability at 0x40 (Endpoint) */
    cfg[0x40] = 0x10;              /* Cap ID: PCIe                       */
    cfg[0x41] = 0x00;              /* Next cap: none                     */
    w16(cfg, 0x42, 0x0002);        /* PCIe Capabilities: Endpoint        */
}

static uint32_t cfg_read(uint32_t offset, uint32_t size)
{
    uint32_t val = 0;

    if (offset + size > CFG_SIZE)
        return ~0u;

    memcpy(&val, &cfg[offset], size);
    return val;
}

/*
 * BAR0 low dword: bits below the BAR's decode size are hardwired in real
 * hardware, not storage -- that's what makes both size probing (write
 * 0xFFFFFFFF, read back a size-shaped mask) and real address assignment
 * work. A plain memcpy store, as this emulator did before, reads back
 * whatever raw bytes were written: probing with 0xFFFFFFFF then reads
 * back 0xFFFFFFFF verbatim (bit0=1 looks like an I/O BAR, not memory),
 * so the PCI core can't compute a sane size and leaves the BAR
 * <unassigned> -- independent of, and easily mistaken for, cosim_enum_bus's
 * separate MMIO-window-reservation failure mode.
 */
#define BAR0_SIZE_MASK_LOW   (~((uint32_t)MMIO_SIZE - 1) & 0xfffffff0u)
#define BAR0_FIXED_FLAGS_LOW 0x4u   /* memory space, 64-bit, non-prefetchable */

static void cfg_write(uint32_t offset, uint32_t size, uint32_t val)
{
    if (offset + size > CFG_SIZE)
        return;

    if (offset == 0x10 && size == 4)
        val = (val & BAR0_SIZE_MASK_LOW) | BAR0_FIXED_FLAGS_LOW;

    memcpy(&cfg[offset], &val, size);
}

/*
 * bar0_base - the BAR0 address the kernel actually assigned this device.
 *
 * The kernel's BAR-sizing/assignment writes (probe with 0xFFFFFFFF, read
 * back the size, then write the real address) are ordinary config writes,
 * so they flow through cfg_write() like any other -- by the time a request
 * with packet_type==2 arrives, cfg[0x10..0x17] already holds the real
 * assigned address. Low 4 bits of the low dword are BAR flags (memory
 * space / type / prefetchable), not part of the address.
 */
static uint64_t bar0_base(void)
{
    uint32_t lo, hi;

    memcpy(&lo, &cfg[0x10], 4);
    memcpy(&hi, &cfg[0x14], 4);
    return ((uint64_t)hi << 32) | (lo & ~0xfULL);
}

/*
 * mem_read/mem_write - answer packet_type==2 (MMIO) transactions.
 *
 * addr is the full CPU physical address a real readl()/writel() would use
 * (cosim_mmio_test computes it from the device's actual pci_resource_start()).
 * Translate it against the BAR0 base this device was actually assigned
 * before indexing into the backing buffer -- exactly what a real device's
 * address decoder does against its own programmed BAR register.
 */
static uint64_t mem_read(uint64_t addr, uint32_t size)
{
    uint64_t base = bar0_base();
    uint64_t off;
    uint64_t val = 0;

    if (addr < base)
        return ~0ull;

    off = addr - base;
    if (off + size > MMIO_SIZE || size > sizeof(val))
        return ~0ull;

    memcpy(&val, &mmio[off], size);
    return val;
}

static void mem_write(uint64_t addr, uint32_t size, uint64_t val)
{
    uint64_t base = bar0_base();
    uint64_t off;

    if (addr < base)
        return;

    off = addr - base;
    if (off + size > MMIO_SIZE || size > sizeof(val))
        return;

    memcpy(&mmio[off], &val, size);
}

/* ------------------------------------------------------------------ */
/*  Named pipe I/O (identical to emu-enum.c)                           */
/* ------------------------------------------------------------------ */

static int req_fd = -1;
static int rep_fd = -1;

static int open_pipes(const char *path)
{
    char req[1024], rep[1024];

    snprintf(req, sizeof(req), "%s/request_server_pipe", path);
    snprintf(rep, sizeof(rep), "%s/reply_server_pipe",   path);

    mkfifo(req, 0777);
    mkfifo(rep, 0777);

    req_fd = open(req, O_RDWR);
    if (req_fd < 0) { perror("open request_server_pipe"); return -1; }

    rep_fd = open(rep, O_RDWR);
    if (rep_fd < 0) { perror("open reply_server_pipe"); return -1; }

    LOG("mmio-enum: pipes opened: %s", path);
    return 0;
}

static void xread(int fd, void *buf, size_t len)
{
    char *p = buf;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) { perror("read pipe"); exit(1); }
        p += n; len -= n;
    }
}

static void xwrite(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) { perror("write pipe"); exit(1); }
        p += n; len -= n;
    }
}

/* ------------------------------------------------------------------ */

/*
 * serve - answer config-space (packet_type==1) and MMIO (packet_type==2)
 * transactions from thin-server-enum, for the single device at devfn 0.
 * Any other devfn gets the standard "absent device" response on config
 * reads, matching emu-enum.c's only_dev0-friendly behaviour.
 */
static void serve(void)
{
    simics_transaction_t req, rsp;

    while (1) {
        xread(req_fd, &req, sizeof(req));

        unsigned devfn    = PCI_DEVFN(req.dev_no, req.fun_no);
        uint32_t size     = req.data_size;
        int      is_write = req.r0w1;
        int      is_mmio  = (req.packet_type == 2);

        memset(&rsp, 0, sizeof(rsp));
        rsp.packet_number = req.packet_number;
        rsp.cmp_status    = 0;

        if (is_mmio) {
            uint64_t addr = req.physical_address;

            LOG("%s MMIO addr=0x%llx size=%u",
                is_write ? "W" : "R", (unsigned long long)addr, size);

            if (is_write) {
                uint64_t val = 0;
                memcpy(&val, req.data, size);
                mem_write(addr, size, val);
            } else {
                uint64_t val = mem_read(addr, size);
                memcpy(rsp.data, &val, size);
                LOG("  -> 0x%llx", (unsigned long long)val);
            }
        } else {
            uint32_t offset = (uint32_t)req.physical_address;

            LOG("%s CFG  devfn=%u offset=0x%x size=%u%s",
                is_write ? "W" : "R", devfn, offset, size,
                devfn == PCI_DEVFN(0, 0) ? "" : " (absent)");

            if (devfn != PCI_DEVFN(0, 0)) {
                /* No device here: reads return all-ones, writes dropped. */
                if (!is_write) {
                    uint32_t ones = ~0u;
                    memcpy(rsp.data, &ones, size);
                }
            } else if (is_write) {
                uint32_t val = 0;
                memcpy(&val, req.data, size);
                cfg_write(offset, size, val);
            } else {
                uint32_t val = cfg_read(offset, size);
                memcpy(rsp.data, &val, size);
                LOG("  -> 0x%x", val);
            }
        }

        xwrite(rep_fd, &rsp, sizeof(rsp));
    }
}

int main(void)
{
    log_init(getenv("CXL_LOG_FILE"));

    const char *pipe_path = getenv(PIPE_PATH_ENV);
    if (!pipe_path) {
        fprintf(stderr, "mmio-enum: %s not set\n", PIPE_PATH_ENV);
        log_close();
        return 1;
    }

    build_header();
    LOG("mmio-enum: ready -- dev0 00.0 mem (DID=0x1234), MMIO backing buffer %u bytes",
        MMIO_SIZE);

    if (open_pipes(pipe_path) < 0) {
        log_close();
        return 1;
    }

    serve();

    close(req_fd);
    close(rep_fd);
    log_close();
    return 0;
}
