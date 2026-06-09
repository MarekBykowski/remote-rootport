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
#include "log.h"

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
#define DOE_TYPE_CMA_SPDM            0x01   /* CMA/SPDM */
#define DOE_TYPE_SECURED_CMA_SPDM    0x02   /* Secured CMA/SPDM */

#define DOE_VID_CXL     0x1E98
#define DOE_TYPE_CXL_TABLE_ACCESS  0x02   /* CXL CDAT */

/* SPDM request / response codes (DMTF DSP0274) */
#define SPDM_GET_VERSION    0x84
#define SPDM_GET_CAPS       0xE1
#define SPDM_NEG_ALGOS      0xE3
#define SPDM_RSP_VERSION    0x04
#define SPDM_RSP_CAPS       0x61
#define SPDM_RSP_ALGOS      0x63
#define SPDM_RSP_ERROR      0x7F
#define SPDM_ERR_UNSUP      0x07

/* SPDM Capabilities flags (responder) */
#define SPDM_CAP_CERT       (1u << 2)
#define SPDM_CAP_CHAL       (1u << 3)
#define SPDM_CAP_MEAS       (2u << 4)   /* measurements without signing */

/* SPDM algorithm selectors */
#define SPDM_ASYM_RSA2048   (1u << 1)   /* RSA-2048-PKCS1v15-SHA256 */
#define SPDM_HASH_SHA256    (1u << 0)
#define SPDM_MEAS_DMTF      (1u << 0)

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
    { DOE_VID_PCISIG, DOE_TYPE_DISC              },
    { DOE_VID_PCISIG, DOE_TYPE_CMA_SPDM               },
    { DOE_VID_PCISIG, DOE_TYPE_SECURED_CMA_SPDM       },
    { DOE_VID_CXL,    DOE_TYPE_CXL_TABLE_ACCESS  },
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

    LOG("doe-emu: discovery index=%u", index);

    doe.rsp_buf[0] = DOE_VID_PCISIG | ((uint32_t)DOE_TYPE_DISC << 16);
    doe.rsp_buf[1] = 4;  /* length in DWORDs */

    if (index < NUM_PROTOCOLS) {
        doe.rsp_buf[2] = protocols[index].vid |
                         ((uint32_t)protocols[index].type << 16);
        doe.rsp_buf[3] = next;
        LOG("doe-emu: → VID=0x%04x Type=0x%02x next=%u",
            protocols[index].vid, protocols[index].type, next);
    } else {
        doe.rsp_buf[2] = 0;
        doe.rsp_buf[3] = 0;
        LOG("doe-emu: → end of list");
    }

    doe.rsp_len = 4;
    doe.rsp_idx = 0;
    doe.status  = DOE_STATUS_DATA_OBJECT_READY;
}

/* ------------------------------------------------------------------ */
/* SPDM handler (carried over CMA / Secured-CMA DOE types)            */
/* ------------------------------------------------------------------ */

static void spdm_finish(uint8_t doe_type, int spdm_bytes)
{
    uint8_t *rsp = (uint8_t *)&doe.rsp_buf[2];
    while (spdm_bytes & 3)
        rsp[spdm_bytes++] = 0;
    int dwords = spdm_bytes / 4;
    doe.rsp_buf[0] = DOE_VID_PCISIG | ((uint32_t)doe_type << 16);
    doe.rsp_buf[1] = 2 + dwords;
    doe.rsp_len    = 2 + dwords;
    doe.rsp_idx    = 0;
    doe.status     = DOE_STATUS_DATA_OBJECT_READY;
}

static void spdm_error(uint8_t doe_type, uint8_t errcode)
{
    uint8_t *rsp = (uint8_t *)&doe.rsp_buf[2];
    rsp[0] = 0x10; rsp[1] = SPDM_RSP_ERROR; rsp[2] = errcode; rsp[3] = 0;
    spdm_finish(doe_type, 4);
    LOG("doe-emu: SPDM error 0x%02x", errcode);
}

static void spdm_handle(uint8_t doe_type)
{
    if (doe.req_len < 3) {
        doe.status = DOE_STATUS_ERROR;
        return;
    }

    uint8_t *req = (uint8_t *)&doe.req_buf[2];
    uint8_t *rsp = (uint8_t *)&doe.rsp_buf[2];
    uint8_t  ver  = req[0];
    uint8_t  code = req[1];

    LOG("doe-emu: SPDM ver=0x%02x code=0x%02x", ver, code);

    switch (code) {

    case SPDM_GET_VERSION: {
        rsp[0] = 0x10; rsp[1] = SPDM_RSP_VERSION;
        rsp[2] = 0;    rsp[3] = 0;   /* param1, param2 */
        rsp[4] = 0;    rsp[5] = 0;   /* reserved */
        rsp[6] = 2;    rsp[7] = 0;   /* VersionNumberEntryCount, pad */
        /* 16-bit version entries: [15:12]=major [11:8]=minor [7:4]=update [3:0]=alpha */
        uint16_t *v = (uint16_t *)(rsp + 8);
        v[0] = 0x1000;  /* 1.0 */
        v[1] = 0x1200;  /* 1.2 */
        spdm_finish(doe_type, 12);
        LOG("doe-emu: SPDM → VERSION (1.0, 1.2)");
        break;
    }

    case SPDM_GET_CAPS: {
        uint32_t flags = SPDM_CAP_CERT | SPDM_CAP_CHAL | SPDM_CAP_MEAS;
        rsp[0] = ver;  rsp[1] = SPDM_RSP_CAPS;
        rsp[2] = 0;    rsp[3] = 0;   /* param1, param2 */
        rsp[4] = 0;    rsp[5] = 12;  /* reserved, CTExponent (4096 µs) */
        rsp[6] = 0;    rsp[7] = 0;   /* reserved */
        memcpy(rsp + 8, &flags, 4);
        spdm_finish(doe_type, 12);
        LOG("doe-emu: SPDM → CAPABILITIES flags=0x%08x", flags);
        break;
    }

    case SPDM_NEG_ALGOS: {
        /* 36-byte ALGORITHMS response (SPDM 1.0/1.2, no extended structs) */
        uint32_t asym = SPDM_ASYM_RSA2048;
        uint32_t hash = SPDM_HASH_SHA256;
        uint16_t len  = 36;
        memset(rsp, 0, 36);
        rsp[0] = ver;  rsp[1] = SPDM_RSP_ALGOS;
        rsp[2] = 0;    rsp[3] = 0;           /* Param1=NumAlgStruct, Param2=0 */
        memcpy(rsp +  4, &len,  2);           /* Length */
        rsp[6] = SPDM_MEAS_DMTF;             /* MeasurementSpecificationSel */
        memcpy(rsp +  8, &asym, 4);           /* BaseAsymSel */
        memcpy(rsp + 12, &hash, 4);           /* BaseHashSel */
        spdm_finish(doe_type, 36);
        LOG("doe-emu: SPDM → ALGORITHMS asym=RSA2048 hash=SHA256");
        break;
    }

    default:
        spdm_error(doe_type, SPDM_ERR_UNSUP);
        break;
    }
}

static void doe_process(void)
{
    if (doe.req_len < 2) {
        LOG("doe-emu: malformed request (len=%d)", doe.req_len);
        doe.status = DOE_STATUS_ERROR;
        return;
    }

    uint16_t vid  = doe.req_buf[0] & 0xFFFF;
    uint8_t  type = (doe.req_buf[0] >> 16) & 0xFF;

    LOG("doe-emu: processing VID=0x%04x Type=0x%02x", vid, type);

    if (vid == DOE_VID_PCISIG && type == DOE_TYPE_DISC) {
        doe_handle_discovery();
    } else if (vid == DOE_VID_PCISIG &&
               (type == DOE_TYPE_CMA_SPDM || type == DOE_TYPE_SECURED_CMA_SPDM)) {
        spdm_handle(type);
    } else {
        LOG("doe-emu: unsupported protocol");
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
        LOG("doe-emu: STATUS → 0x%08x", doe.status);
        return doe.status;

    case DOE_REG_READ:
        if (doe.rsp_idx >= doe.rsp_len) {
            LOG("doe-emu: READ overrun");
            return 0xFFFFFFFF;
        }
        LOG("doe-emu: READ[%d] → 0x%08x",
            doe.rsp_idx, doe.rsp_buf[doe.rsp_idx]);
        return doe.rsp_buf[doe.rsp_idx];

    default:
        LOG("doe-emu: unhandled read reg=0x%02x", reg);
        return 0;
    }
}

static void reg_write(uint32_t reg, uint32_t val)
{
    switch (reg) {
    case DOE_REG_CTRL:
        LOG("doe-emu: CTRL ← 0x%08x", val);
        if (val & DOE_CTRL_ABORT) {
            LOG("doe-emu: ABORT");
            doe.req_len = doe.rsp_len = doe.rsp_idx = 0;
            doe.status  = 0;
        }
        if (val & DOE_CTRL_GO) {
            LOG("doe-emu: GO");
            doe_process();
            doe.req_len = 0;
        }
        break;

    case DOE_REG_WRITE:
        LOG("doe-emu: WRITE[%d] ← 0x%08x", doe.req_len, val);
        if (doe.req_len < DOE_BUF_DWORDS)
            doe.req_buf[doe.req_len++] = val;
        break;

    case DOE_REG_READ:
        /* host writes 0 to ack each DWORD and advance pointer */
        if (val == 0) {
            doe.rsp_idx++;
            LOG("doe-emu: READ ack → %d/%d", doe.rsp_idx, doe.rsp_len);
            if (doe.rsp_idx >= doe.rsp_len) {
                doe.status  = 0;
                doe.rsp_idx = doe.rsp_len = 0;
                LOG("doe-emu: response consumed");
            }
        }
        break;

    default:
        LOG("doe-emu: unhandled write reg=0x%02x val=0x%08x", reg, val);
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

    req_fd = open(req, O_RDWR);
    if (req_fd < 0) { perror("open request_server_pipe"); return -1; }

    rep_fd = open(rep, O_RDWR);
    if (rep_fd < 0) { perror("open reply_server_pipe");   return -1; }

    LOG("doe-emu: pipes opened (%s)", path);
    return 0;
}

static void pipe_read(int fd, void *buf, size_t len)
{
    char *p = buf;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) { perror("read"); exit(1); }
        p += n; len -= n;
    }
}

static void pipe_write(int fd, const void *buf, size_t len)
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
        pipe_read(req_fd, &req, sizeof(req));

        if (req.control_status & 0x1) {  /* QUIT_SIM_MASK */
            LOG("doe-emu: quit received");
            break;
        }

        uint32_t offset = (uint32_t)req.physical_address;

        /* detect cap_base from first STATUS read; ignore writes until then */
        if (!doe.cap_detected) {
            if (req.r0w1 == 1) {
                /* kernel may write CTRL (ABORT) before first STATUS read — skip */
                memset(&rsp, 0, sizeof(rsp));
                rsp.packet_number = req.packet_number;
                rsp.packet_type   = req.packet_type;
                rsp.sim_type      = req.sim_type;
                rsp.data_size     = 4;
                rsp.r0w1          = req.r0w1;
                pipe_write(rep_fd, &rsp, sizeof(rsp));
                continue;
            }
            doe.cap_base    = offset - DOE_REG_STATUS;
            doe.cap_detected = 1;
            LOG("doe-emu: cap_base=0x%x (auto-detected)", doe.cap_base);
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

        pipe_write(rep_fd, &rsp, sizeof(rsp));
    }
}

int main(void)
{
    log_init(getenv("CXL_LOG_FILE"));

    const char *path = getenv(PIPE_PATH_ENV);
    if (!path) {
        fprintf(stderr, "doe-emu: %s not set\n", PIPE_PATH_ENV);
        log_close();
        return 1;
    }

    memset(&doe, 0, sizeof(doe));

    if (open_pipes(path) < 0) {
        log_close();
        return 1;
    }

    LOG("doe-emu: ready");
    run();

    close(req_fd);
    close(rep_fd);
    log_close();
    return 0;
}

/*
 * Expected doe-emu.log for a successful DOE Discovery exchange:
 *
 * Cap base detection (kernel triggered by PCI rescan):
 *   cap_base=0x190     first read at offset 0x19c (STATUS) → cap_base = 0x19c - 0x0c = 0x190
 *   STATUS → 0x00      kernel checks BUSY=0 before submitting
 *   STATUS → 0x00      kernel checks BUSY=0 again (some drivers poll twice)
 *
 * Request phase — kernel fills the write mailbox:
 *   WRITE[0] ← 0x00000001   DOE header DWORD 0: VID=0x0001, Type=0x00 (Discovery)
 *   WRITE[1] ← 0x00000003   DOE header DWORD 1: length=3 DWORDs
 *   WRITE[2] ← 0x00000000   payload: index=0 (query first protocol)
 *   CTRL ← 0x80000000       kernel sets GO bit
 *   GO                       doe_process() fires
 *   processing VID=0x0001 Type=0x00
 *   discovery index=0        looking up protocol at index 0
 *   → VID=0x0001 Type=0x00 next=1   responding with Discovery itself, next index=1
 *
 * Response phase — kernel reads the mailbox:
 *   STATUS → 0x80000000   DATA_OBJECT_READY set
 *   READ[0] → 0x00000001  response DWORD 0: VID=0x0001, Type=0x00
 *   READ ack → 1/4
 *   READ[1] → 0x00000004  response DWORD 1: length=4
 *   READ ack → 2/4
 *   READ[2] → 0x00000001  response DWORD 2: protocol entry VID=0x0001, Type=0x00
 *   STATUS → 0x80000000   kernel re-checks STATUS mid-read (normal)
 *   READ ack → 3/4
 *   READ[3] → 0x00000001  response DWORD 3: next=1
 *   READ ack → 4/4
 *   response consumed      all DWORDs read, STATUS cleared
 *   STATUS → 0x00000000   kernel confirms STATUS cleared, exchange complete
 */
