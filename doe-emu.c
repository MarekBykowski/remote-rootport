/*
 * doe-emu.c
 *
 * Software emulator of a CXL device DOE mailbox.
 * Replaces simv — opens the same named pipes (request_server_pipe /
 * reply_server_pipe) and implements the DOE mailbox state machine.
 *
 * Currently supports:
 *   - DOE Discovery (VID=0x0001, Type=0x00)
 *
 * Extend doe_process() for CMA, SPDM, etc.
 *
 * Usage:
 *   export CXL_RELAY_SERVER_PATH=/path/to/pipes
 *   ./doe-emu
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define PIPE_PATH_ENV  "CXL_RELAY_SERVER_PATH"
#define MAX_PAYLOAD    256
#define DOE_BUF_DWORDS 68   /* 2 headers + 256/4 payload */

/* DOE register offsets relative to cap base */
#define DOE_REG_CTRL    0x08
#define DOE_REG_STATUS  0x0c
#define DOE_REG_WRITE   0x10
#define DOE_REG_READ    0x14

/* DOE Status bits */
#define DOE_STATUS_BUSY              0x00000001
#define DOE_STATUS_ERROR             0x00000004
#define DOE_STATUS_DATA_OBJECT_READY 0x80000000

/* DOE Control bits */
#define DOE_CTRL_ABORT  0x00000001
#define DOE_CTRL_GO     0x80000000

/* DOE Discovery protocol */
#define DOE_VID_PCISIG  0x0001
#define DOE_TYPE_DISC   0x00
#define DOE_TYPE_CMA    0x01
#define DOE_TYPE_SPDM   0x02

/* simics_transaction_t — must match cxl_relay/cxl_tlp_fifo.h exactly */
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

/* Supported protocols advertised via DOE Discovery */
static const struct { uint16_t vid; uint8_t type; } protocols[] = {
    { DOE_VID_PCISIG, DOE_TYPE_DISC },
    { DOE_VID_PCISIG, DOE_TYPE_CMA  },
    { DOE_VID_PCISIG, DOE_TYPE_SPDM },
};
#define NUM_PROTOCOLS ((int)(sizeof(protocols) / sizeof(protocols[0])))

/* DOE mailbox state machine */
static struct {
    uint32_t status;

    uint32_t req_buf[DOE_BUF_DWORDS];
    int      req_len;

    uint32_t rsp_buf[DOE_BUF_DWORDS];
    int      rsp_len;
    int      rsp_idx;

    uint32_t cap_base;
    int      cap_detected;
} doe;

static int req_fd = -1;
static int rep_fd = -1;

/* ------------------------------------------------------------------ */
/* Protocol handlers                                                   */
/* ------------------------------------------------------------------ */

static void doe_handle_discovery(void)
{
    if (doe.req_len < 3) {
        doe.status = DOE_STATUS_ERROR;
        return;
    }

    uint32_t index = doe.req_buf[2] & 0xFF;
    uint32_t next  = (index + 1 < NUM_PROTOCOLS) ? index + 1 : 0;

    printf("doe-emu: discovery index=%u\n", index);

    doe.rsp_buf[0] = DOE_VID_PCISIG | ((uint32_t)DOE_TYPE_DISC << 16);
    doe.rsp_buf[1] = 4;  /* length in DWORDs */

    if (index < NUM_PROTOCOLS) {
        doe.rsp_buf[2] = protocols[index].vid |
                         ((uint32_t)protocols[index].type << 16);
        doe.rsp_buf[3] = next;
        printf("doe-emu: → VID=0x%04x Type=0x%02x next=%u\n",
               protocols[index].vid, protocols[index].type, next);
    } else {
        doe.rsp_buf[2] = 0;
        doe.rsp_buf[3] = 0;
        printf("doe-emu: → end of list\n");
    }

    doe.rsp_len = 4;
    doe.rsp_idx = 0;
    doe.status  = DOE_STATUS_DATA_OBJECT_READY;
}

static void doe_process(void)
{
    if (doe.req_len < 2) {
        printf("doe-emu: malformed request (len=%d)\n", doe.req_len);
        doe.status = DOE_STATUS_ERROR;
        return;
    }

    uint16_t vid  = doe.req_buf[0] & 0xFFFF;
    uint8_t  type = (doe.req_buf[0] >> 16) & 0xFF;

    printf("doe-emu: processing VID=0x%04x Type=0x%02x\n", vid, type);

    if (vid == DOE_VID_PCISIG && type == DOE_TYPE_DISC) {
        doe_handle_discovery();
    } else {
        printf("doe-emu: unsupported protocol\n");
        doe.status = DOE_STATUS_ERROR;
    }
}

/* ------------------------------------------------------------------ */
/* Register read / write                                               */
/* ------------------------------------------------------------------ */

static uint32_t reg_read(uint32_t reg)
{
    switch (reg) {
    case DOE_REG_STATUS:
        printf("doe-emu: STATUS → 0x%08x\n", doe.status);
        return doe.status;

    case DOE_REG_READ:
        if (doe.rsp_idx >= doe.rsp_len) {
            printf("doe-emu: READ overrun\n");
            return 0xFFFFFFFF;
        }
        printf("doe-emu: READ[%d] → 0x%08x\n",
               doe.rsp_idx, doe.rsp_buf[doe.rsp_idx]);
        return doe.rsp_buf[doe.rsp_idx];

    default:
        printf("doe-emu: unhandled read reg=0x%02x\n", reg);
        return 0;
    }
}

static void reg_write(uint32_t reg, uint32_t val)
{
    switch (reg) {
    case DOE_REG_CTRL:
        printf("doe-emu: CTRL ← 0x%08x\n", val);
        if (val & DOE_CTRL_ABORT) {
            printf("doe-emu: ABORT\n");
            doe.req_len = doe.rsp_len = doe.rsp_idx = 0;
            doe.status  = 0;
        }
        if (val & DOE_CTRL_GO) {
            printf("doe-emu: GO\n");
            doe_process();
            doe.req_len = 0;
        }
        break;

    case DOE_REG_WRITE:
        printf("doe-emu: WRITE[%d] ← 0x%08x\n", doe.req_len, val);
        if (doe.req_len < DOE_BUF_DWORDS)
            doe.req_buf[doe.req_len++] = val;
        break;

    case DOE_REG_READ:
        /* host writes 0 to ack each DWORD and advance pointer */
        if (val == 0) {
            doe.rsp_idx++;
            printf("doe-emu: READ ack → %d/%d\n", doe.rsp_idx, doe.rsp_len);
            if (doe.rsp_idx >= doe.rsp_len) {
                doe.status  = 0;
                doe.rsp_idx = doe.rsp_len = 0;
                printf("doe-emu: response consumed\n");
            }
        }
        break;

    default:
        printf("doe-emu: unhandled write reg=0x%02x val=0x%08x\n", reg, val);
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Named pipe I/O                                                      */
/* ------------------------------------------------------------------ */

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
    if (rep_fd < 0) { perror("open reply_server_pipe");   return -1; }

    printf("doe-emu: pipes opened (%s)\n", path);
    return 0;
}

static void xread(int fd, void *buf, size_t len)
{
    char *p = buf;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) { perror("read"); exit(1); }
        p += n; len -= n;
    }
}

static void xwrite(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) { perror("write"); exit(1); }
        p += n; len -= n;
    }
}

/* ------------------------------------------------------------------ */
/* Main loop                                                           */
/* ------------------------------------------------------------------ */

static void run(void)
{
    simics_transaction_t req, rsp;

    for (;;) {
        xread(req_fd, &req, sizeof(req));

        if (req.control_status & 0x1) {  /* QUIT_SIM_MASK */
            printf("doe-emu: quit received\n");
            break;
        }

        uint32_t offset = (uint32_t)req.physical_address;

        /* auto-detect DOE cap base from first access */
        if (!doe.cap_detected) {
            if (req.r0w1 == 0)
                doe.cap_base = offset - DOE_REG_STATUS;  /* first read = STATUS */
            else
                doe.cap_base = offset - DOE_REG_WRITE;   /* first write = WRITE mailbox */
            doe.cap_detected = 1;
            printf("doe-emu: cap_base=0x%x (auto-detected)\n", doe.cap_base);
        }

        uint32_t reg = offset - doe.cap_base;
        uint32_t val = 0;

        memset(&rsp, 0, sizeof(rsp));
        rsp.packet_number = req.packet_number;
        rsp.packet_type   = req.packet_type;
        rsp.sim_type      = req.sim_type;
        rsp.data_size     = 4;
        rsp.r0w1          = req.r0w1;
        rsp.cmp_status    = 0;

        if (req.r0w1 == 0) {
            val = reg_read(reg);
            memcpy(rsp.data, &val, 4);
        } else {
            memcpy(&val, req.data, 4);
            reg_write(reg, val);
        }

        xwrite(rep_fd, &rsp, sizeof(rsp));
    }
}

int main(void)
{
    const char *path = getenv(PIPE_PATH_ENV);
    if (!path) {
        fprintf(stderr, "doe-emu: %s not set\n", PIPE_PATH_ENV);
        return 1;
    }

    memset(&doe, 0, sizeof(doe));

    if (open_pipes(path) < 0)
        return 1;

    printf("doe-emu: ready\n");
    run();

    close(req_fd);
    close(rep_fd);
    return 0;
}
