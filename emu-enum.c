/*
 * emu-enum.c
 *
 * Standalone PCI config-space emulator.  Sits on the named pipes that
 * thin-server-enum writes to, and answers config-space transactions for a
 * small table of virtual devices matched by (dev, fn):
 *   00.0  plain memory controller
 *   01.0  CXL-compliant memory device (carries the CXL PCIe-Device DVSEC)
 *
 * Replaces the Simics cosim endpoint for testing without a simulator.
 *
 * Usage:
 *   CXL_LOG_FILE=logs/emu_enum.log \
 *   CXL_RELAY_SERVER_PATH=/tmp/cosim_enum_pipes \
 *   ./emu-enum
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

/* ------------------------------------------------------------------ */
/*  simics_transaction_t + MAX_PAYLOAD -- shared definition            */
/* ------------------------------------------------------------------ */

#include "simics_transaction.h"

/* ------------------------------------------------------------------ */
/*  Virtual devices                                                    */
/* ------------------------------------------------------------------ */

#define PCI_DEVFN(dev, fn)  ((((dev) & 0x1f) << 3) | ((fn) & 0x07))

/*
 * CXL PCIe-Device DVSEC constants (mirror drivers/cxl/cxlpci.h and
 * include/uapi/linux/pci_regs.h).  cxl_pci finds this capability with
 * pci_find_dvsec_capability(CXL_DVSEC_VENDOR_ID, CXL_DVSEC_PCIE_DEVICE).
 */
#define PCI_EXT_CAP_ID_DVSEC        0x23
#define CXL_DVSEC_VENDOR_ID         0x1E98
#define CXL_DVSEC_PCIE_DEVICE       0          /* DVSEC ID */
#define CXL_DVSEC_CAP_OFFSET        0xA
#define   CXL_DVSEC_MEM_CAPABLE     (1u << 2)
#define   CXL_DVSEC_HDM_COUNT(n)    (((n) & 3) << 4)
#define CXL_DVSEC_CTRL_OFFSET       0xC
#define   CXL_DVSEC_MEM_ENABLE      (1u << 2)
#define CXL_DVSEC_RANGE_SIZE_LOW0   0x1C
#define   CXL_DVSEC_MEM_INFO_VALID  (1u << 0)
#define   CXL_DVSEC_MEM_ACTIVE      (1u << 1)

/* virtual device */
struct vdev {
    unsigned devfn;             /* PCI_DEVFN(dev, fn) this device occupies */
    uint8_t  cfg[CFG_SIZE];	/* config space, CFG_SIZE = 4096 */
};

#define NUM_VDEVS 2
static struct vdev vdevs[NUM_VDEVS];

static void w16(uint8_t *cfg, int off, uint16_t v)
{
    cfg[off]     = v & 0xff;
    cfg[off + 1] = (v >> 8) & 0xff;
}

static void w32(uint8_t *cfg, int off, uint32_t v)
{
    cfg[off]     =  v        & 0xff;
    cfg[off + 1] = (v >>  8) & 0xff;
    cfg[off + 2] = (v >> 16) & 0xff;
    cfg[off + 3] = (v >> 24) & 0xff;
}

/*
 * Common PCI type-0 header shared by both devices:
 *   VID   = 0x8086 (Intel)
 *   Class = 0x050210 (Memory Controller, CXL, prog-if 0x10)
 *   BAR0  = 64-bit memory, PCIe capability at 0x40.
 */
static void build_header(uint8_t *cfg, uint16_t did)
{
    memset(cfg, 0xff, CFG_SIZE);   /* absent registers read as all-ones  */
    memset(cfg, 0x00, 0x40);       /* standard header: zero then fill     */

    w16(cfg, 0x00, 0x8086);        /* Vendor ID                           */
    w16(cfg, 0x02, did);           /* Device ID                           */
    w16(cfg, 0x04, 0x0006);        /* Command: Memory Space + Bus Master  */
    w16(cfg, 0x06, 0x0010);        /* Status: Capabilities List present   */
    cfg[0x08] = 0x01;              /* Revision ID                         */
    cfg[0x09] = 0x10;              /* Prog IF: CXL Memory Device          */
    cfg[0x0a] = 0x02;              /* Sub-class: Memory Controller        */
    cfg[0x0b] = 0x05;              /* Base Class: Memory Controller       */
    cfg[0x0e] = 0x00;              /* Header type: type-0, single func    */
    cfg[0x34] = 0x40;              /* Capabilities pointer -> PCIe cap    */

    w16(cfg, 0x2c, 0x8086);        /* Subsystem Vendor ID                 */
    w16(cfg, 0x2e, did);           /* Subsystem Device ID                 */

    /* BAR0: 64-bit, memory, non-prefetchable */
    w32(cfg, 0x10, 0x00000004);    /* BAR0 low: 64-bit indicator          */
    w32(cfg, 0x14, 0x00000000);    /* BAR0 high                           */

    /* PCIe Capability at 0x40 (Endpoint) */
    cfg[0x40] = 0x10;              /* Cap ID: PCIe                        */
    cfg[0x41] = 0x00;              /* Next cap: none                      */
    w16(cfg, 0x42, 0x0002);        /* PCIe Capabilities: Endpoint         */
}

/* Device 0: a plain memory controller, no CXL DVSEC. */
static void build_mem_device(uint8_t *cfg)
{
    build_header(cfg, 0x1234);
}

/*
 * Device 1: a CXL-compliant memory device.
 *
 * Adds the CXL PCIe-Device DVSEC as an extended capability at 0x100, which
 * cxl_pci locates via pci_find_dvsec_capability().  With it the kernel
 * recognises the device as CXL (clearing "Device DVSEC not present").
 *
 * NOTE: full CXL.mem bring-up additionally needs the CXL component/device
 * registers in BAR/MMIO space (found via the Register Locator DVSEC), which
 * this config-space-only emulator does not back.  So cxl_pci recognises the
 * device but cannot complete CXL.mem init.
 */
static void build_cxl_device(uint8_t *cfg)
{
    const int pos = 0x100;         /* first PCIe extended capability       */

    build_header(cfg, 0x1235);

    /* Extended Capability header: DVSEC, cap version 1, no next cap. */
    w32(cfg, pos, PCI_EXT_CAP_ID_DVSEC | (1u << 16) | (0u << 20));

    /* DVSEC Header1: CXL vendor, revision 1, length 0x3C. */
    w32(cfg, pos + 0x4,
        CXL_DVSEC_VENDOR_ID | (1u << 16) | (0x3Cu << 20));

    /* DVSEC Header2: DVSEC ID = PCIe-Device DVSEC (0). */
    w16(cfg, pos + 0x8, CXL_DVSEC_PCIE_DEVICE);

    /* CXL Capability: mem capable, one HDM decoder. */
    w16(cfg, pos + CXL_DVSEC_CAP_OFFSET,
        CXL_DVSEC_MEM_CAPABLE | CXL_DVSEC_HDM_COUNT(1));

    /* CXL Control: memory enabled. */
    w16(cfg, pos + CXL_DVSEC_CTRL_OFFSET, CXL_DVSEC_MEM_ENABLE);

    /* Range 0 size-low: 256 MB, mem info valid + active. */
    w32(cfg, pos + CXL_DVSEC_RANGE_SIZE_LOW0,
        0x10000000u | CXL_DVSEC_MEM_INFO_VALID | CXL_DVSEC_MEM_ACTIVE);
}

static uint32_t cfg_read(const uint8_t *cfg, uint32_t offset, uint32_t size)
{
    uint32_t val = 0;

    if (offset + size > CFG_SIZE)
        return ~0u;

    memcpy(&val, &cfg[offset], size);
    return val;
}

static void cfg_write(uint8_t *cfg, uint32_t offset, uint32_t size, uint32_t val)
{
    if (offset + size > CFG_SIZE)
        return;

    /* Command register is writable; BARs during sizing are writable */
    memcpy(&cfg[offset], &val, size);
}

static struct vdev *find_vdev(unsigned devfn)
{
    int i;

    for (i = 0; i < NUM_VDEVS; i++)
        if (vdevs[i].devfn == devfn)
            return &vdevs[i];
    return NULL;
}

/* Device 0 at 00.0 (plain mem), device 1 at 01.0 (CXL). */
static void build_devices(void)
{
    vdevs[0].devfn = PCI_DEVFN(0, 0);
    build_mem_device(vdevs[0].cfg);

    vdevs[1].devfn = PCI_DEVFN(1, 0);
    build_cxl_device(vdevs[1].cfg);
}

/* ------------------------------------------------------------------ */
/*  Named pipe I/O                                                     */
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

    /* Open in O_RDWR to avoid blocking waiting for the other end */
    req_fd = open(req, O_RDWR);
    if (req_fd < 0) { perror("open request_server_pipe"); return -1; }

    rep_fd = open(rep, O_RDWR);
    if (rep_fd < 0) { perror("open reply_server_pipe"); return -1; }

    LOG("emu-enum: pipes opened: %s", path);
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
 * serve - answer config-space transactions from thin-server-enum.
 *
 * Each transaction is matched to a virtual device by (dev_no, fun_no).  Slots
 * with no device return all-ones on reads (so the kernel skips them) and drop
 * writes -- this is what makes only the populated slots enumerate instead of
 * aliasing one device into all 32.
 */
static void serve(void)
{
    simics_transaction_t req, rsp;

    while (1) {
        xread(req_fd, &req, sizeof(req));

        unsigned     devfn  = PCI_DEVFN(req.dev_no, req.fun_no);
        uint32_t     offset = (uint32_t)req.physical_address;
        uint32_t     size   = req.data_size;
        int          is_write = req.r0w1;
        struct vdev *d      = find_vdev(devfn);

        LOG("%s bus=%u dev=%u fn=%u offset=0x%x size=%u%s",
            is_write ? "W" : "R",
            req.bus_no, req.dev_no, req.fun_no,
            offset, size, d ? "" : " (absent)");

        memset(&rsp, 0, sizeof(rsp));
        rsp.packet_number = req.packet_number;
        rsp.cmp_status    = 0;

        if (!d) {
            /* No device here: reads return all-ones, writes are dropped. */
            if (!is_write) {
                uint32_t ones = ~0u;
                memcpy(rsp.data, &ones, size);
            }
        } else if (is_write) {
            uint32_t val = 0;
            memcpy(&val, req.data, size);
            cfg_write(d->cfg, offset, size, val);
        } else {
            uint32_t val = cfg_read(d->cfg, offset, size);
            memcpy(rsp.data, &val, size);
            LOG("  -> 0x%x", val);
        }

        xwrite(rep_fd, &rsp, sizeof(rsp));
    }
}

int main(void)
{
    log_init(getenv("CXL_LOG_FILE"));

    const char *pipe_path = getenv(PIPE_PATH_ENV);
    if (!pipe_path) {
        fprintf(stderr, "emu-enum: %s not set\n", PIPE_PATH_ENV);
        log_close();
        return 1;
    }

    build_devices();
    LOG("emu-enum: ready -- dev0 00.0 mem (DID=0x1234), dev1 01.0 CXL (DID=0x1235)");

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
