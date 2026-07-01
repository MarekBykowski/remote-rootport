/*
 * enum-emu.c
 *
 * Standalone PCI config-space emulator.  Sits on the named pipes that
 * thin-server-enum writes to, responds with the config-space image of a
 * virtual CXL Type-3 memory device.
 *
 * Replaces the Simics cosim endpoint for testing without a simulator.
 *
 * Usage:
 *   CXL_LOG_FILE=logs/enum_emu.log \
 *   CXL_RELAY_SERVER_PATH=/tmp/cosim_enum_pipes \
 *   ./enum-emu
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
#define MAX_PAYLOAD   256
#define CFG_SIZE      4096

/* ------------------------------------------------------------------ */
/*  simics_transaction_t -- must match thin-server-enum.c              */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t packet_number;
    uint32_t packet_type;
    uint32_t sim_type;
    uint32_t bus_no;
    uint32_t dev_no;
    uint32_t fun_no;
    uint32_t cfg_type;
    uint32_t control_status;
    uint64_t physical_address;
    uint32_t r0w1;
    uint32_t data_size;
    uint8_t  data[MAX_PAYLOAD];
    uint32_t reg_value;
    uint32_t fixed_first_size;
    uint32_t unaligned_value;
    uint32_t fbe;
    uint32_t fixed_last_size;
    uint32_t lbe;
    uint32_t cmp_status;
    uint32_t response1;
    uint32_t response2;
} simics_transaction_t;

/* ------------------------------------------------------------------ */
/*  Virtual device config space                                        */
/* ------------------------------------------------------------------ */

/*
 * Virtual CXL Type-3 memory device:
 *   VID  = 0x8086 (Intel)
 *   DID  = 0x1234 (placeholder)
 *   Class= 0x050210 (Memory Controller, CXL)
 */
static uint8_t cfg[CFG_SIZE];

static void cfg_write16(int off, uint16_t v)
{
    cfg[off]     = v & 0xff;
    cfg[off + 1] = (v >> 8) & 0xff;
}

static void cfg_write32(int off, uint32_t v)
{
    cfg[off]     =  v        & 0xff;
    cfg[off + 1] = (v >>  8) & 0xff;
    cfg[off + 2] = (v >> 16) & 0xff;
    cfg[off + 3] = (v >> 24) & 0xff;
}

static void build_config_space(void)
{
    memset(cfg, 0xff, sizeof(cfg)); /* default: all-ones (device absent) */
    memset(cfg, 0x00, 0x40);       /* standard header: zero then fill   */

    cfg_write16(0x00, 0x8086);     /* Vendor ID  */
    cfg_write16(0x02, 0x1234);     /* Device ID  */
    cfg_write16(0x04, 0x0006);     /* Command: Memory Space + Bus Master */
    cfg_write16(0x06, 0x0010);     /* Status: Capabilities List present  */
    cfg[0x08] = 0x01;              /* Revision ID */
    cfg[0x09] = 0x10;              /* Prog IF */
    cfg[0x0a] = 0x02;              /* Sub-class: Memory Controller */
    cfg[0x0b] = 0x05;              /* Base Class: Memory Controller */
    cfg[0x0e] = 0x00;              /* Header type: type-0, single function */
    cfg[0x34] = 0x40;              /* Capabilities pointer */

    cfg_write16(0x2c, 0x8086);     /* Subsystem Vendor ID */
    cfg_write16(0x2e, 0x1234);     /* Subsystem Device ID */

    /* BAR0: 64-bit, memory, non-prefetchable, 256 MB */
    cfg_write32(0x10, 0x00000004); /* BAR0 low:  64-bit indicator */
    cfg_write32(0x14, 0x00000000); /* BAR0 high */

    /* PCIe Capability at offset 0x40 */
    cfg[0x40] = 0x10;              /* Cap ID: PCIe */
    cfg[0x41] = 0x00;              /* Next cap: none */
    cfg_write16(0x42, 0x0002);     /* PCIe Capabilities: Endpoint */
}

static uint32_t cfg_read(uint32_t offset, uint32_t size)
{
    uint32_t val = 0;

    if (offset + size > CFG_SIZE)
        return ~0u;

    memcpy(&val, &cfg[offset], size);
    return val;
}

static void cfg_write(uint32_t offset, uint32_t size, uint32_t val)
{
    if (offset + size > CFG_SIZE)
        return;

    /* Command register is writable; BARs during sizing are writable */
    memcpy(&cfg[offset], &val, size);
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

    LOG("enum-emu: pipes opened: %s", path);
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

static void serve(void)
{
    simics_transaction_t req, rsp;

    while (1) {
        xread(req_fd, &req, sizeof(req));

        uint32_t offset = (uint32_t)req.physical_address;
        uint32_t size   = req.data_size;
        int      is_write = req.r0w1;

        LOG("%s bus=%u dev=%u fn=%u offset=0x%x size=%u",
            is_write ? "W" : "R",
            req.bus_no, req.dev_no, req.fun_no,
            offset, size);

        memset(&rsp, 0, sizeof(rsp));
        rsp.packet_number = req.packet_number;
        rsp.cmp_status    = 0;

        if (is_write) {
            uint32_t val = 0;
            memcpy(&val, req.data, size);
            cfg_write(offset, size, val);
        } else {
            uint32_t val = cfg_read(offset, size);
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
        fprintf(stderr, "enum-emu: %s not set\n", PIPE_PATH_ENV);
        log_close();
        return 1;
    }

    build_config_space();
    LOG("enum-emu: ready (VID=0x8086 DID=0x1234 Class=0x050210)");

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
