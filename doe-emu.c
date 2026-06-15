/*
 * doe-emu.c
 *
 * Software emulator of a CXL device DOE mailbox.
 * Replaces simv — opens the same named pipes (request_server_pipe /
 * reply_server_pipe) and implements the DOE mailbox state machine.
 *
 * Supports:
 *   - DOE Discovery (VID=0x0001, Type=0x00)
 *   - SPDM 1.2: GET_VERSION, GET_CAPABILITIES, NEGOTIATE_ALGORITHMS,
 *               GET_DIGESTS, GET_CERTIFICATE, CHALLENGE
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

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <openssl/err.h>

#include "log.h"

#define PIPE_PATH_ENV  "CXL_RELAY_SERVER_PATH"
#define MAX_PAYLOAD    256
#define DOE_BUF_DWORDS 256  /* 2 headers + up to ~1KB payload (cert chain + RSA sig) */

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

/* DOE protocol IDs */
#define DOE_VID_PCISIG               0x0001
#define DOE_TYPE_DISC                0x00
#define DOE_TYPE_CMA_SPDM            0x01
#define DOE_TYPE_SECURED_CMA_SPDM   0x02

#define DOE_VID_CXL                  0x1E98
#define DOE_TYPE_CXL_TABLE_ACCESS    0x02

/* SPDM request codes (DMTF DSP0274) */
#define SPDM_GET_VERSION    0x84
#define SPDM_GET_CAPS       0xE1
#define SPDM_NEG_ALGOS      0xE3
#define SPDM_GET_DIGESTS    0x81
#define SPDM_GET_CERT       0x82
#define SPDM_CHALLENGE      0x83

/* SPDM response codes */
#define SPDM_RSP_VERSION    0x04
#define SPDM_RSP_CAPS       0x61
#define SPDM_RSP_ALGOS      0x63
#define SPDM_RSP_DIGESTS    0x01
#define SPDM_RSP_CERT       0x02
#define SPDM_RSP_CHAL_AUTH  0x03
#define SPDM_RSP_ERROR      0x7F
#define SPDM_ERR_UNSUP      0x07

/*
 * SPDM 1.2 Capabilities flags (DSP0274 Table 12)
 * Bit 1: CERT_CAP, Bit 2: CHAL_CAP, Bits 3-4: MEAS_CAP
 */
#define SPDM_CAP_CERT       (1u << 1)
#define SPDM_CAP_CHAL       (1u << 2)
#define SPDM_CAP_MEAS_SIG   (2u << 3)   /* measurements with signing */

/* SPDM algorithm selectors */
#define SPDM_ASYM_RSA2048   (1u << 1)
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
    { DOE_VID_PCISIG, DOE_TYPE_CMA_SPDM          },
    { DOE_VID_PCISIG, DOE_TYPE_SECURED_CMA_SPDM  },
    { DOE_VID_CXL,    DOE_TYPE_CXL_TABLE_ACCESS   },
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
/* Crypto context (generated once at startup)                          */
/* ------------------------------------------------------------------ */

#define CHAIN_MAX 8192

static struct {
    EVP_PKEY *pkey;
    uint8_t   chain[CHAIN_MAX];
    size_t    chain_len;
    uint8_t   chain_hash[32];  /* SHA-256 of the CertChain structure */
} g_crypto;

/*
 * SPDM transcript buffer.
 * Accumulates every SPDM payload (both requests and responses,
 * excluding DOE headers) from GET_VERSION through CHALLENGE request.
 * Used as signing input for CHALLENGE_AUTH.
 */
#define TRANSCRIPT_MAX 65536
static uint8_t  g_transcript[TRANSCRIPT_MAX];
static size_t   g_transcript_len;

static void transcript_reset(void)
{
    g_transcript_len = 0;
}

static void transcript_append(const uint8_t *data, size_t len)
{
    if (g_transcript_len + len > TRANSCRIPT_MAX) {
        LOG("doe-emu: transcript overflow, truncating");
        len = TRANSCRIPT_MAX - g_transcript_len;
    }
    memcpy(g_transcript + g_transcript_len, data, len);
    g_transcript_len += len;
}

static int crypto_init(void)
{
    EVP_PKEY_CTX *kctx;
    X509 *cert;
    X509_NAME *name;
    unsigned char *p;
    int dlen;
    uint8_t cert_der[4096];
    uint8_t root_hash[32];
    uint16_t chain_total;

    /* Generate RSA-2048 key pair */
    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!kctx) { LOG("doe-emu: EVP_PKEY_CTX_new_id failed"); return -1; }
    if (EVP_PKEY_keygen_init(kctx) <= 0) goto fail_kctx;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048) <= 0) goto fail_kctx;
    if (EVP_PKEY_keygen(kctx, &g_crypto.pkey) <= 0) goto fail_kctx;
    EVP_PKEY_CTX_free(kctx);

    /* Create self-signed X.509v3 certificate */
    cert = X509_new();
    if (!cert) { LOG("doe-emu: X509_new failed"); return -1; }
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 315360000L);
    X509_set_pubkey(cert, g_crypto.pkey);
    name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (unsigned char *)"doe-emu", -1, -1, 0);
    X509_set_issuer_name(cert, name);
    if (!X509_sign(cert, g_crypto.pkey, EVP_sha256())) {
        LOG("doe-emu: X509_sign failed");
        X509_free(cert);
        return -1;
    }

    /* DER-encode the certificate */
    p = cert_der;
    dlen = i2d_X509(cert, &p);
    X509_free(cert);
    if (dlen <= 0 || (size_t)(dlen + 36) > CHAIN_MAX) {
        LOG("doe-emu: cert DER too large: %d", dlen);
        return -1;
    }

    /*
     * Build SPDM CertChain:
     *   [Length(2)] [Reserved(2)] [RootHash(32)] [CertDER...]
     * RootHash = SHA-256 of the root cert DER (self-signed: same cert).
     */
    SHA256(cert_der, dlen, root_hash);
    chain_total = (uint16_t)(2 + 2 + 32 + dlen);
    p = g_crypto.chain;
    memcpy(p, &chain_total, 2);   p += 2;
    memset(p, 0, 2);               p += 2;
    memcpy(p, root_hash, 32);     p += 32;
    memcpy(p, cert_der, dlen);
    g_crypto.chain_len = chain_total;

    /* chain_hash = SHA-256 of the entire CertChain structure */
    SHA256(g_crypto.chain, g_crypto.chain_len, g_crypto.chain_hash);

    LOG("doe-emu: crypto init ok, chain=%zu bytes", g_crypto.chain_len);
    return 0;

fail_kctx:
    EVP_PKEY_CTX_free(kctx);
    LOG("doe-emu: key generation failed");
    return -1;
}

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
    doe.rsp_buf[1] = 4;

    if (index < NUM_PROTOCOLS) {
        doe.rsp_buf[2] = protocols[index].vid |
                         ((uint32_t)protocols[index].type << 16);
        doe.rsp_buf[3] = next;
        LOG("doe-emu: → VID=0x%04x Type=0x%02x next=%u",
            protocols[index].vid, protocols[index].type, next);
    } else {
        doe.rsp_buf[2] = 0;
        doe.rsp_buf[3] = 0;
    }

    doe.rsp_len = 4;
    doe.rsp_idx = 0;
    doe.status  = DOE_STATUS_DATA_OBJECT_READY;
}

/* ------------------------------------------------------------------ */
/* SPDM helpers                                                        */
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

/* ------------------------------------------------------------------ */
/* SPDM message handler                                                */
/* ------------------------------------------------------------------ */

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
    /* request length in bytes (DOE DW count minus 2 headers, times 4) */
    int req_bytes = (doe.req_len - 2) * 4;

    LOG("doe-emu: SPDM ver=0x%02x code=0x%02x", ver, code);

    switch (code) {

    /* ---- GET_VERSION -------------------------------------------- */
    case SPDM_GET_VERSION: {
        transcript_reset();
        transcript_append(req, 4);

        rsp[0] = 0x10; rsp[1] = SPDM_RSP_VERSION;
        rsp[2] = 0;    rsp[3] = 0;
        rsp[4] = 0;    rsp[5] = 0;
        rsp[6] = 2;    rsp[7] = 0;
        uint16_t *v = (uint16_t *)(rsp + 8);
        v[0] = 0x1000;  /* 1.0 */
        v[1] = 0x1200;  /* 1.2 */
        int bytes = 12;

        transcript_append(rsp, bytes);
        spdm_finish(doe_type, bytes);
        LOG("doe-emu: SPDM → VERSION (1.0, 1.2)");
        break;
    }

    /* ---- GET_CAPABILITIES --------------------------------------- */
    case SPDM_GET_CAPS: {
        transcript_append(req, req_bytes);

        uint32_t flags = SPDM_CAP_CERT | SPDM_CAP_CHAL | SPDM_CAP_MEAS_SIG;
        int bytes;

        memset(rsp, 0, 20);
        rsp[0] = ver;
        rsp[1] = SPDM_RSP_CAPS;
        rsp[5] = 12;  /* CTExponent: 2^12 µs = 4096 µs timeout */
        memcpy(rsp + 8, &flags, 4);

        if (ver >= 0x12) {
            /* SPDM 1.2: add DataTransferSize + MaxSPDMmsgSize */
            uint32_t dts = 4096, maxmsg = 4096;
            memcpy(rsp + 12, &dts,    4);
            memcpy(rsp + 16, &maxmsg, 4);
            bytes = 20;
        } else {
            bytes = 12;
        }

        transcript_append(rsp, bytes);
        spdm_finish(doe_type, bytes);
        LOG("doe-emu: SPDM → CAPABILITIES flags=0x%08x (ver=0x%02x, %d bytes)",
            flags, ver, bytes);
        break;
    }

    /* ---- NEGOTIATE_ALGORITHMS ----------------------------------- */
    case SPDM_NEG_ALGOS: {
        transcript_append(req, req_bytes);

        uint32_t asym = SPDM_ASYM_RSA2048;
        uint32_t hash = SPDM_HASH_SHA256;
        uint32_t meas_hash = SPDM_HASH_SHA256;
        uint16_t len;
        int bytes;

        memset(rsp, 0, 36);
        rsp[0] = ver;
        rsp[1] = SPDM_RSP_ALGOS;
        rsp[2] = 0;  /* NumAlgStructs */
        rsp[3] = 0;
        rsp[6] = SPDM_MEAS_DMTF;  /* MeasurementSpecificationSel */

        if (ver >= 0x11) {
            /*
             * SPDM 1.1+: byte 7 = OtherParamsSupport,
             * MeasurementHashAlgo at [8..11], BaseAsymSel at [12..15],
             * BaseHashSel at [16..19].
             */
            rsp[7] = 0;
            memcpy(rsp +  8, &meas_hash, 4);
            memcpy(rsp + 12, &asym,      4);
            memcpy(rsp + 16, &hash,      4);
            len   = 36;
            bytes = 36;
        } else {
            /* SPDM 1.0: BaseAsymSel at [8], BaseHashSel at [12] */
            memcpy(rsp +  8, &asym, 4);
            memcpy(rsp + 12, &hash, 4);
            len   = 36;
            bytes = 36;
        }
        memcpy(rsp + 4, &len, 2);

        transcript_append(rsp, bytes);
        spdm_finish(doe_type, bytes);
        LOG("doe-emu: SPDM → ALGORITHMS asym=RSA2048 hash=SHA256 (ver=0x%02x)", ver);
        break;
    }

    /* ---- GET_DIGESTS -------------------------------------------- */
    case SPDM_GET_DIGESTS: {
        transcript_append(req, 4);

        rsp[0] = ver;
        rsp[1] = SPDM_RSP_DIGESTS;
        rsp[2] = 0x01;  /* SlotMask: slot 0 */
        rsp[3] = 0;
        memcpy(rsp + 4, g_crypto.chain_hash, 32);
        int bytes = 4 + 32;

        transcript_append(rsp, bytes);
        spdm_finish(doe_type, bytes);
        LOG("doe-emu: SPDM → DIGESTS slot0");
        break;
    }

    /* ---- GET_CERTIFICATE ---------------------------------------- */
    case SPDM_GET_CERT: {
        uint16_t offset = 0, length = 0;
        if (req_bytes >= 8) {
            memcpy(&offset, req + 4, 2);
            memcpy(&length, req + 6, 2);
        }

        transcript_append(req, req_bytes);

        size_t total = g_crypto.chain_len;
        if (offset >= total) {
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }

        size_t avail   = total - offset;
        size_t portion = (length == 0 || length == 0xFFFF || length > avail)
                         ? avail : length;
        uint16_t p16 = (uint16_t)portion;
        uint16_t r16 = (uint16_t)(avail - portion);

        rsp[0] = ver;
        rsp[1] = SPDM_RSP_CERT;
        rsp[2] = req[2];  /* SlotID */
        rsp[3] = 0;
        memcpy(rsp + 4, &p16, 2);
        memcpy(rsp + 6, &r16, 2);
        memcpy(rsp + 8, g_crypto.chain + offset, portion);
        int bytes = 8 + (int)portion;

        transcript_append(rsp, bytes);
        spdm_finish(doe_type, bytes);
        LOG("doe-emu: SPDM → CERTIFICATE offset=%u portion=%zu remain=%zu",
            offset, portion, (size_t)(avail - portion));
        break;
    }

    /* ---- CHALLENGE ---------------------------------------------- */
    case SPDM_CHALLENGE: {
        if (req_bytes < 36) {
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }
        uint8_t nonce[32];
        memcpy(nonce, req + 4, 32);

        /* Append the CHALLENGE request to transcript */
        transcript_append(req, req_bytes);

        /*
         * Build CHALLENGE_AUTH body (without Signature) into rsp[].
         * Layout (SPDM 1.2):
         *   [0]   SPDMVersion
         *   [1]   0x03 (CHALLENGE_AUTH)
         *   [2]   SlotIDParam = (SlotID | SlotID<<4)
         *   [3]   SlotMask
         *   [4..35]  CertChainHash (32)
         *   [36..67] Nonce (32)
         *   [68..99] MeasurementSummaryHash (32, zeros = no meas)
         *   [100..101] OpaqueDataLength = 0
         */
        int pos = 0;
        rsp[pos++] = ver;
        rsp[pos++] = SPDM_RSP_CHAL_AUTH;
        rsp[pos++] = req[2] | (uint8_t)(req[2] << 4);
        rsp[pos++] = 0x01;                              /* SlotMask */
        memcpy(rsp + pos, g_crypto.chain_hash, 32); pos += 32;
        memcpy(rsp + pos, nonce, 32);                pos += 32;
        memset(rsp + pos, 0, 32);                    pos += 32;
        rsp[pos++] = 0; rsp[pos++] = 0;              /* OpaqueDataLength */

        /*
         * Signature = RSA-PKCS1v15-SHA256 over (transcript || rsp[0..pos-1]).
         * EVP_DigestSign hashes the data internally, so feed both.
         */
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx || EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL,
                                         g_crypto.pkey) <= 0) {
            LOG("doe-emu: CHALLENGE sign init failed");
            if (mdctx) EVP_MD_CTX_free(mdctx);
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }
        EVP_DigestSignUpdate(mdctx, g_transcript, g_transcript_len);
        EVP_DigestSignUpdate(mdctx, rsp, pos);

        size_t siglen = 256;
        uint8_t sig[256];
        if (EVP_DigestSignFinal(mdctx, sig, &siglen) <= 0) {
            LOG("doe-emu: CHALLENGE sign final failed");
            EVP_MD_CTX_free(mdctx);
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }
        EVP_MD_CTX_free(mdctx);

        memcpy(rsp + pos, sig, siglen);
        pos += (int)siglen;

        spdm_finish(doe_type, pos);
        LOG("doe-emu: SPDM → CHALLENGE_AUTH (signed, siglen=%zu, total=%d bytes)",
            siglen, pos);
        break;
    }

    default:
        LOG("doe-emu: SPDM unsupported code=0x%02x", code);
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

        if (req.control_status & 0x1) {
            LOG("doe-emu: quit received");
            break;
        }

        uint32_t offset = (uint32_t)req.physical_address;

        if (!doe.cap_detected) {
            if (req.r0w1 == 1) {
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

    if (crypto_init() < 0) {
        fprintf(stderr, "doe-emu: crypto init failed\n");
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

    EVP_PKEY_free(g_crypto.pkey);
    log_close();
    return 0;
}
