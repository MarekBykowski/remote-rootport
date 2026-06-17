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
 *               GET_DIGESTS, GET_CERTIFICATE, CHALLENGE, KEY_EXCHANGE
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
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>

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
#define SPDM_KEY_EXCHANGE   0xE4
#define SPDM_FINISH         0xE5
#define SPDM_GET_MEAS       0xE0

/* SPDM response codes */
#define SPDM_RSP_VERSION       0x04
#define SPDM_RSP_CAPS          0x61
#define SPDM_RSP_ALGOS         0x63
#define SPDM_RSP_DIGESTS       0x01
#define SPDM_RSP_CERT          0x02
#define SPDM_RSP_CHAL_AUTH     0x03
#define SPDM_RSP_KEY_EXCHANGE  0x64
#define SPDM_RSP_FINISH        0x65
#define SPDM_RSP_MEAS          0x60
#define SPDM_RSP_ERROR         0x7F
#define SPDM_ERR_UNSUP         0x07

/*
 * SPDM 1.2 Capabilities flags (DSP0274 Table 12)
 * Bit 1: CERT_CAP, Bit 2: CHAL_CAP, Bit 6: ENCRYPT_CAP, Bit 7: MAC_CAP,
 * Bit 9: KEY_EX_CAP, Bits 3-4: MEAS_CAP
 */
#define SPDM_CAP_CERT       (1u << 1)
#define SPDM_CAP_CHAL       (1u << 2)
#define SPDM_CAP_MEAS_SIG   (2u << 3)   /* measurements with signing */
#define SPDM_CAP_ENCRYPT    (1u << 6)
#define SPDM_CAP_MAC        (1u << 7)
#define SPDM_CAP_KEY_EX     (1u << 9)

/* SPDM algorithm selectors */
#define SPDM_ASYM_ECDSA_P384  (1u << 7)  /* TPM_ALG_ECDSA_ECC_NIST_P384 */
#define SPDM_HASH_SHA384      (1u << 1)
#define SPDM_DHE_SECP384R1    (1u << 4)
#define SPDM_AEAD_AES_256_GCM (1u << 1)
#define SPDM_KEY_SCHED_SPDM   (1u << 0)
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
    uint8_t   chain_hash[48];  /* SHA-384 of the CertChain structure (matches BaseHashSel) */
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

static const char *hex_str(const uint8_t *data, size_t len)
{
    static char buf[1024];
    size_t i;
    if (len > (sizeof(buf) - 1) / 2)
        len = (sizeof(buf) - 1) / 2;
    for (i = 0; i < len; i++)
        snprintf(buf + i * 2, 3, "%02x", data[i]);
    buf[i * 2] = '\0';
    return buf;
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

/* ------------------------------------------------------------------ */
/* SPDM 1.2 session key schedule (DSP0274 10.3 / spdm-rs v0.4.1)       */
/* ------------------------------------------------------------------ */

#define SESSION_MK_MAX 1024

static struct {
    int      active;
    uint32_t session_id;
    uint8_t  message_a[TRANSCRIPT_MAX]; /* snapshot of g_transcript at KEY_EXCHANGE time */
    size_t   message_a_len;
    uint8_t  message_k[SESSION_MK_MAX];
    size_t   message_k_len;
    uint8_t  handshake_secret[48];
    uint8_t  req_finished_key[48];
    uint8_t  rsp_finished_key[48];
    /* AEAD keys for handshake phase (KEY_EXCHANGE → FINISH) */
    uint8_t  req_hs_key[32];    /* requester (TPA) → responder (us) */
    uint8_t  req_hs_iv[12];
    uint8_t  rsp_hs_key[32];    /* responder (us) → requester (TPA) */
    uint8_t  rsp_hs_iv[12];
    /* AEAD keys for data phase (after FINISH) */
    uint8_t  req_data_key[32];
    uint8_t  req_data_iv[12];
    uint8_t  rsp_data_key[32];
    uint8_t  rsp_data_iv[12];
    /* per-direction sequence numbers (pcidoe: seq_count=0, but we track for nonce) */
    uint64_t req_seq_no;
    uint64_t rsp_seq_no;
    /* whether FINISH has completed (data-phase keys active) */
    int      established;
    /* message_f: FINISH req header + req hmac + FINISH rsp header */
    uint8_t  message_f[256];
    size_t   message_f_len;
} g_session;

/* HKDF-Extract(salt, ikm) = HMAC-Hash(salt, ikm) (RFC 5869) */
static int hkdf_extract_sha384(const uint8_t *salt, size_t salt_len,
                                const uint8_t *ikm, size_t ikm_len,
                                uint8_t out[48])
{
    unsigned int outlen = 0;
    return (HMAC(EVP_sha384(), salt, (int)salt_len, ikm, ikm_len, out, &outlen) &&
            outlen == 48) ? 0 : -1;
}

/*
 * HKDF-Expand(prk, info, L) for L <= 48 (SHA-384 output size): a single
 * RFC 5869 iteration T(1) = HMAC-Hash(prk, info || 0x01) suffices.
 */
static int hkdf_expand_sha384(const uint8_t prk[48],
                               const uint8_t *info, size_t info_len,
                               uint8_t *out, size_t out_len)
{
    uint8_t buf[256], t1[48];
    unsigned int outlen = 0;

    if (info_len + 1 > sizeof(buf) || out_len > 48)
        return -1;
    memcpy(buf, info, info_len);
    buf[info_len] = 0x01;
    if (!HMAC(EVP_sha384(), prk, 48, buf, info_len + 1, t1, &outlen) || outlen != 48)
        return -1;
    memcpy(out, t1, out_len);
    return 0;
}

/* AES-256-GCM encrypt/decrypt (SPDM secured messages) */
static int aes_gcm_encrypt(const uint8_t key[32], const uint8_t iv[12],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *plain, size_t plain_len,
                            uint8_t *cipher, uint8_t tag[16])
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, ok = 1;
    if (!ctx) return 0;
    ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
         EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) &&
         EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) &&
         EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) &&
         EVP_EncryptUpdate(ctx, cipher, &len, plain, (int)plain_len) &&
         EVP_EncryptFinal_ex(ctx, cipher + len, &len) &&
         EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static int aes_gcm_decrypt(const uint8_t key[32], const uint8_t iv[12],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *cipher, size_t cipher_len,
                            const uint8_t tag[16], uint8_t *plain)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0, ok;
    if (!ctx) return 0;
    ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
         EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) &&
         EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    if (ok) {
        EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len);
        EVP_DecryptUpdate(ctx, plain, &len, cipher, (int)cipher_len);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag);
        ok = EVP_DecryptFinal_ex(ctx, plain + len, &len) > 0;
    }
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

/*
 * Decode a SPDM secured message (PCIDoe, sequence_number_count=0).
 * msg = inner payload starting after DOE header (session_id + length + ct + tag).
 * Returns 0 on success, sets *plain_len to the SPDM message length.
 */
static int secured_msg_decode(const uint8_t *msg, size_t msg_len,
                               const uint8_t key[32], const uint8_t base_iv[12],
                               uint64_t seq_no,
                               uint8_t *plain_buf, size_t *plain_len_out)
{
    if (msg_len < 6 + 16)
        return -1;
    uint16_t length;
    memcpy(&length, msg + 4, 2);
    if ((size_t)(6 + length) > msg_len || length < 16)
        return -1;

    size_t cipher_len = (size_t)length - 16;
    uint8_t nonce[12];
    memcpy(nonce, base_iv, 12);
    for (int i = 0; i < 8; i++)
        nonce[i] ^= (uint8_t)(seq_no >> (8 * i));

    static uint8_t pt[1024];
    if (cipher_len > sizeof(pt))
        return -1;
    if (!aes_gcm_decrypt(key, nonce, msg, 6, msg + 6, cipher_len,
                         msg + 6 + cipher_len, pt))
        return -1;

    uint16_t app_len;
    memcpy(&app_len, pt, 2);
    if ((size_t)(app_len + 2) > cipher_len)
        return -1;
    memcpy(plain_buf, pt + 2, app_len);
    *plain_len_out = app_len;
    return 0;
}

/*
 * Encode a SPDM secured response (PCIDoe, sequence_number_count=0).
 * Writes session_id(4)+length(2)+ciphertext+tag into out[].
 * Returns total bytes written.
 */
static int secured_msg_encode(uint32_t session_id,
                               const uint8_t *app_buf, size_t app_len,
                               const uint8_t key[32], const uint8_t base_iv[12],
                               uint64_t seq_no, uint8_t *out)
{
    size_t cipher_size = app_len + 2;
    uint16_t length = (uint16_t)(cipher_size + 16);
    uint8_t aad[6];
    memcpy(aad, &session_id, 4);
    memcpy(aad + 4, &length, 2);

    static uint8_t pt[1024];
    uint16_t app_len16 = (uint16_t)app_len;
    memcpy(pt, &app_len16, 2);
    memcpy(pt + 2, app_buf, app_len);

    uint8_t nonce[12];
    memcpy(nonce, base_iv, 12);
    for (int i = 0; i < 8; i++)
        nonce[i] ^= (uint8_t)(seq_no >> (8 * i));

    memcpy(out, aad, 6);
    uint8_t tag[16];
    aes_gcm_encrypt(key, nonce, aad, 6, pt, cipher_size, out + 6, tag);
    memcpy(out + 6 + cipher_size, tag, 16);
    return (int)(6 + cipher_size + 16);
}

/*
 * SPDM HKDF-Expand-Label "binconcat": Length(2,LE) || "spdm<major>.<minor> "
 * (8 bytes) || Label || Context. This is the `info` argument to
 * HKDF-Expand, NOT the bin_str fed to signing (see spdm_signing_message).
 */
static size_t spdm_binconcat(uint16_t length, uint8_t ver,
                              const uint8_t *label, size_t label_len,
                              const uint8_t *context, size_t context_len,
                              uint8_t *out)
{
    size_t pos = 0;
    uint8_t version[8] = { 's', 'p', 'd', 'm', ' ', '.', ' ', ' ' };

    version[4] = (uint8_t)('0' + ((ver >> 4) & 0xF));
    version[6] = (uint8_t)('0' + (ver & 0xF));

    out[pos++] = (uint8_t)(length & 0xFF);
    out[pos++] = (uint8_t)(length >> 8);
    memcpy(out + pos, version, 8); pos += 8;
    memcpy(out + pos, label, label_len); pos += label_len;
    if (context) { memcpy(out + pos, context, context_len); pos += context_len; }
    return pos;
}

/*
 * SPDM 1.2 signing context prefix: 64-byte repeated "dmtf-spdm-v1.x.*"
 * (4x16 bytes) with the version digits patched at indices 11/13/27/29/...
 */
static void spdm_signing_prefix(uint8_t ver, uint8_t out[64])
{
    static const uint8_t base[16] = {
        0x64, 0x6d, 0x74, 0x66, 0x2d, 0x73, 0x70, 0x64,
        0x6d, 0x2d, 0x76, 0x31, 0x2e, 0x78, 0x2e, 0x2a,
    };
    int i;

    for (i = 0; i < 4; i++) {
        memcpy(out + i * 16, base, 16);
        out[i * 16 + 11] = (uint8_t)('0' + ((ver >> 4) & 0xF));
        out[i * 16 + 13] = (uint8_t)('0' + (ver & 0xF));
    }
}

static const uint8_t SPDM_ZEROPAD_2[2] = { 0x00, 0x00 };

/* "responder-key_exchange_rsp signing" */
static const uint8_t SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT[34] = {
    0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x64, 0x65, 0x72, 0x2d, 0x6b, 0x65,
    0x79, 0x5f, 0x65, 0x78, 0x63, 0x68, 0x61, 0x6e, 0x67, 0x65, 0x5f, 0x72,
    0x73, 0x70, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x69, 0x6e, 0x67,
};

/* ECDH P-384: shared secret is the X-coordinate only, 48 bytes */
static int ecdh_compute_shared_secret_p384(EVP_PKEY *my_pkey,
                                            const uint8_t peer_xy[96],
                                            uint8_t out[48])
{
    EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(my_pkey);
    const EC_GROUP *group;
    EC_POINT *peer_point = NULL;
    BIGNUM *x = NULL, *y = NULL;
    int rc = -1, len;

    if (!eckey)
        return -1;
    group = EC_KEY_get0_group(eckey);
    peer_point = EC_POINT_new(group);
    x = BN_bin2bn(peer_xy, 48, NULL);
    y = BN_bin2bn(peer_xy + 48, 48, NULL);
    if (!peer_point || !x || !y)
        goto out;
    if (!EC_POINT_set_affine_coordinates(group, peer_point, x, y, NULL))
        goto out;

    len = ECDH_compute_key(out, 48, peer_point, eckey, NULL);
    rc = (len == 48) ? 0 : -1;

out:
    if (peer_point) EC_POINT_free(peer_point);
    if (x) BN_free(x);
    if (y) BN_free(y);
    EC_KEY_free(eckey);
    return rc;
}

static int crypto_init(void)
{
    EVP_PKEY_CTX *kctx;
    X509 *cert;
    X509_NAME *name;
    unsigned char *p;
    int dlen;
    uint8_t cert_der[4096];
    uint8_t root_hash[48];
    uint16_t chain_total;

    /* Generate EC P-384 key pair (matches BaseAsymSel=ECDSA_P384 / DHE=secp384r1) */
    kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!kctx) { LOG("doe-emu: EVP_PKEY_CTX_new_id failed"); return -1; }
    if (EVP_PKEY_keygen_init(kctx) <= 0) goto fail_kctx;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_secp384r1) <= 0) goto fail_kctx;
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

    /*
     * webpki validates this single self-signed cert both as the trust
     * anchor (via TrustAnchor::try_from_cert_der, which doesn't check
     * BasicConstraints) and as the end-entity leaf via build_chain()'s
     * check_basic_constraints(), which explicitly REJECTS the leaf with
     * Error::CaUsedAsEndEntity if BasicConstraints CA:TRUE is set
     * (confirmed via webpki 0.22.4 source, the version this firmware's
     * spdm-rs v0.4.1 actually pins). So: no BasicConstraints extension,
     * and KeyUsage must not claim keyCertSign since this cert is never
     * used to sign another cert in this chain.
     */
    {
        X509V3_CTX ctx;
        X509_EXTENSION *ext;

        X509V3_set_ctx(&ctx, cert, cert, NULL, NULL, 0);

        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_key_usage,
                                   "digitalSignature");
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }

        /*
         * The deployed TPA firmware (spdm-rs v0.4.1, confirmed via binary
         * strings match) calls webpki's verify_cert_chain_with_eku() with
         * EKU_SPDM_RESPONDER_AUTH = OID 1.3.6.1.5.5.7.3.1 (id-kp-serverAuth).
         * That old webpki API has no "EKU absent -> pass" exception (that
         * was added later upstream) — the leaf cert MUST carry this EKU or
         * verification fails outright.
         */
        ext = X509V3_EXT_conf_nid(NULL, &ctx, NID_ext_key_usage,
                                   "serverAuth");
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
    }

    if (!X509_sign(cert, g_crypto.pkey, EVP_sha384())) {
        LOG("doe-emu: X509_sign failed");
        X509_free(cert);
        return -1;
    }

    /* DER-encode the certificate */
    p = cert_der;
    dlen = i2d_X509(cert, &p);
    X509_free(cert);
    if (dlen <= 0 || (size_t)(dlen + 52) > CHAIN_MAX) {
        LOG("doe-emu: cert DER too large: %d", dlen);
        return -1;
    }

    /*
     * Build SPDM CertChain:
     *   [Length(2)] [Reserved(2)] [RootHash(48)] [CertDER...]
     * RootHash size/algorithm must match the negotiated BaseHashAlgo
     * (SHA-384 here), not a fixed SHA-256 — the requester recomputes
     * this hash with the negotiated algorithm and compares it.
     * RootHash = SHA-384 of the root cert DER (self-signed: same cert).
     */
    SHA384(cert_der, dlen, root_hash);
    chain_total = (uint16_t)(2 + 2 + 48 + dlen);
    p = g_crypto.chain;
    memcpy(p, &chain_total, 2);   p += 2;
    memset(p, 0, 2);               p += 2;
    memcpy(p, root_hash, 48);     p += 48;
    memcpy(p, cert_der, dlen);
    g_crypto.chain_len = chain_total;

    /* chain_hash = SHA-384 of the entire CertChain structure */
    SHA384(g_crypto.chain, g_crypto.chain_len, g_crypto.chain_hash);

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

static void handle_secured_spdm(void);  /* defined after spdm_handle */

static void spdm_handle(uint8_t doe_type)
{
    if (doe.req_len < 3) {
        doe.status = DOE_STATUS_ERROR;
        return;
    }

    /* Secured messages are dispatched separately — their payload starts with
     * SessionID (4 bytes), not an SPDM header. */
    if (doe_type == DOE_TYPE_SECURED_CMA_SPDM) {
        handle_secured_spdm();
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
        rsp[4] = 0;    rsp[5] = 2;  /* Reserved, VersionNumberEntryCount */
        uint16_t *v = (uint16_t *)(rsp + 6);
        v[0] = 0x1000;  /* 1.0 */
        v[1] = 0x1200;  /* 1.2 */
        int bytes = 10;

        transcript_append(rsp, bytes);
        spdm_finish(doe_type, bytes);
        LOG("doe-emu: SPDM → VERSION (1.0, 1.2)");
        break;
    }

    /* ---- GET_CAPABILITIES --------------------------------------- */
    case SPDM_GET_CAPS: {
        transcript_append(req, req_bytes);

        uint32_t flags = SPDM_CAP_CERT | SPDM_CAP_CHAL | SPDM_CAP_MEAS_SIG |
                         SPDM_CAP_KEY_EX | SPDM_CAP_ENCRYPT | SPDM_CAP_MAC;
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

        uint32_t asym = SPDM_ASYM_ECDSA_P384;
        uint32_t hash = SPDM_HASH_SHA384;
        uint32_t meas_hash = SPDM_HASH_SHA384;
        uint8_t  num_req_structs = (req_bytes >= 3) ? req[2] : 0;
        uint16_t len;
        int bytes;

        memset(rsp, 0, 48);
        rsp[0] = ver;
        rsp[1] = SPDM_RSP_ALGOS;
        rsp[3] = 0;
        rsp[6] = SPDM_MEAS_DMTF;

        if (ver >= 0x11) {
            rsp[7] = (req_bytes >= 8) ? (req[7] & 0x02) : 0;  /* OtherParamsSel: echo OpaqueDataFmt1 bit */
            memcpy(rsp +  8, &meas_hash, 4);
            memcpy(rsp + 12, &asym,      4);
            memcpy(rsp + 16, &hash,      4);
            /* rsp[20..31] = Reserved (12 bytes, zeroed by memset) */
            /* rsp[32] = ExtAsymCount, rsp[33] = ExtHashCount, rsp[34..35] = Reserved2 (all 0) */
            len   = 36;
            bytes = 36;

            /*
             * Echo AlgStructs: responder must include one selected
             * algorithm per AlgStruct type the requester listed.
             * Format: AlgType(1) | AlgCount=0x20(1) | AlgSupported(2)
             * DHE=secp384r1(bit4), AEAD=AES-256-GCM(bit1), KeySched=SPDM(bit0)
             * AlgStruct array starts at offset 36 (after ExtAsymCount/
             * ExtHashCount/Reserved2 at 32-35), not 32.
             */
            if (num_req_structs > 0) {
                rsp[2] = 3;
                rsp[36] = 0x02; rsp[37] = 0x20;
                rsp[38] = SPDM_DHE_SECP384R1 & 0xFF; rsp[39] = SPDM_DHE_SECP384R1 >> 8;
                rsp[40] = 0x03; rsp[41] = 0x20;
                rsp[42] = SPDM_AEAD_AES_256_GCM & 0xFF; rsp[43] = SPDM_AEAD_AES_256_GCM >> 8;
                rsp[44] = 0x05; rsp[45] = 0x20;
                rsp[46] = SPDM_KEY_SCHED_SPDM & 0xFF; rsp[47] = SPDM_KEY_SCHED_SPDM >> 8;
                len   = 48;
                bytes = 48;
            } else {
                rsp[2] = 0;
            }
        } else {
            memcpy(rsp +  8, &asym, 4);
            memcpy(rsp + 12, &hash, 4);
            rsp[2] = 0;
            len   = 28;
            bytes = 28;
        }
        memcpy(rsp + 4, &len, 2);

        transcript_append(rsp, bytes);
        spdm_finish(doe_type, bytes);
        LOG("doe-emu: SPDM → ALGORITHMS asym=ECDSA_P384 hash=SHA384 dhe=secp384r1 structs=%d (ver=0x%02x, %d bytes)",
            rsp[2], ver, bytes);
        break;
    }

    /* ---- GET_DIGESTS -------------------------------------------- */
    case SPDM_GET_DIGESTS: {
        /*
         * NOT part of message_a: the real key schedule's TH1 = Hash(A ||
         * cert_chain_hash || K), where the cert chain's contribution is
         * the precomputed chain hash (g_crypto.chain_hash), not the raw
         * GET_DIGESTS/GET_CERTIFICATE wire bytes. Do not transcript_append
         * here or KEY_EXCHANGE's signature/HMAC will be computed over the
         * wrong bytes.
         */
        rsp[0] = ver;
        rsp[1] = SPDM_RSP_DIGESTS;
        rsp[2] = 0x01;  /* SlotMask: slot 0 */
        rsp[3] = 0;
        memcpy(rsp + 4, g_crypto.chain_hash, 48);
        int bytes = 4 + 48;

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

        /* See note in GET_DIGESTS: not part of message_a. */

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
         *   [4..51]  CertChainHash (48, SHA-384 since chain_hash is computed with SHA-384)
         *   [52..83] Nonce (32)
         *   [84..115] MeasurementSummaryHash (32, zeros = no meas)
         *   [116..117] OpaqueDataLength = 0
         */
        int pos = 0;
        rsp[pos++] = ver;
        rsp[pos++] = SPDM_RSP_CHAL_AUTH;
        rsp[pos++] = req[2] | (uint8_t)(req[2] << 4);
        rsp[pos++] = 0x01;                              /* SlotMask */
        memcpy(rsp + pos, g_crypto.chain_hash, 48); pos += 48;
        memcpy(rsp + pos, nonce, 32);                pos += 32;
        memset(rsp + pos, 0, 32);                    pos += 32;
        rsp[pos++] = 0; rsp[pos++] = 0;              /* OpaqueDataLength */

        /*
         * Signature = ECDSA-P384-SHA384 over (transcript || rsp[0..pos-1]).
         * EVP_DigestSign hashes the data internally, so feed both.
         */
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx || EVP_DigestSignInit(mdctx, NULL, EVP_sha384(), NULL,
                                         g_crypto.pkey) <= 0) {
            LOG("doe-emu: CHALLENGE sign init failed");
            if (mdctx) EVP_MD_CTX_free(mdctx);
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }
        EVP_DigestSignUpdate(mdctx, g_transcript, g_transcript_len);
        EVP_DigestSignUpdate(mdctx, rsp, pos);

        /* Get DER-encoded ECDSA signature, then extract raw (R || S) */
        size_t der_len = 0;
        EVP_DigestSignFinal(mdctx, NULL, &der_len);
        uint8_t *der = malloc(der_len);
        if (!der || EVP_DigestSignFinal(mdctx, der, &der_len) <= 0) {
            LOG("doe-emu: CHALLENGE sign final failed");
            free(der);
            EVP_MD_CTX_free(mdctx);
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }
        EVP_MD_CTX_free(mdctx);

        /* Convert DER ECDSA sig → raw (R || S), 48 bytes each for P-384 */
        const unsigned char *dp = der;
        ECDSA_SIG *esig = d2i_ECDSA_SIG(NULL, &dp, (long)der_len);
        free(der);
        if (!esig) {
            LOG("doe-emu: CHALLENGE d2i_ECDSA_SIG failed");
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }
        const BIGNUM *r, *s;
        ECDSA_SIG_get0(esig, &r, &s);
        BN_bn2binpad(r, rsp + pos,      48);
        BN_bn2binpad(s, rsp + pos + 48, 48);
        ECDSA_SIG_free(esig);
        pos += 96;  /* ECDSA P-384: R(48) + S(48) */

        spdm_finish(doe_type, pos);
        LOG("doe-emu: SPDM → CHALLENGE_AUTH (ECDSA P-384, total=%d bytes)", pos);
        break;
    }

    /* ---- KEY_EXCHANGE --------------------------------------------
     * Request (8-byte header + Random + Exchange + Opaque):
     *   [0] ver [1] code [2] MeasurementSummaryHashType [3] SlotID
     *   [4..5] ReqSessionID(LE) [6] SessionPolicy [7] Reserved
     *   [8..39] Random(32) [40..135] ExchangeData(96, P-384 X||Y)
     *   [136..137] OpaqueDataLength(LE) [138..] OpaqueData
     */
    case SPDM_KEY_EXCHANGE: {
        if (req_bytes < 138) {
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }

        uint16_t req_session_id;
        memcpy(&req_session_id, req + 4, 2);
        const uint8_t *peer_exchange = req + 40;

        /*
         * The requester's own message_k uses its pre-padding encoded
         * request length (8 + Random(32) + Exchange(96) + 2 +
         * OpaqueDataLength), NOT req_bytes - the latter is rounded up to a
         * DOE dword boundary and may include trailing zero padding the
         * requester never included in its own transcript. Mixing that
         * padding into message_k silently desyncs TH1 from the requester's
         * value, which manifests as a signature-verification failure with
         * no other diagnostic.
         */
        uint16_t req_opaque_len;
        memcpy(&req_opaque_len, req + 136, 2);
        int req_actual_len = 138 + req_opaque_len;
        if (req_actual_len > req_bytes)
            req_actual_len = req_bytes;

        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
        EVP_PKEY *eph_pkey = NULL;
        if (!kctx || EVP_PKEY_keygen_init(kctx) <= 0 ||
            EVP_PKEY_CTX_set_ec_paramgen_curve_nid(kctx, NID_secp384r1) <= 0 ||
            EVP_PKEY_keygen(kctx, &eph_pkey) <= 0) {
            LOG("doe-emu: KEY_EXCHANGE ephemeral keygen failed");
            if (kctx) EVP_PKEY_CTX_free(kctx);
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }
        EVP_PKEY_CTX_free(kctx);

        uint8_t shared_secret[48];
        if (ecdh_compute_shared_secret_p384(eph_pkey, peer_exchange, shared_secret) != 0) {
            LOG("doe-emu: KEY_EXCHANGE ECDH derive failed");
            EVP_PKEY_free(eph_pkey);
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }

        /* Extract our own ephemeral public key as raw X||Y (96 bytes) */
        uint8_t my_exchange[96];
        {
            EC_KEY *my_eckey = EVP_PKEY_get1_EC_KEY(eph_pkey);
            const EC_GROUP *group = EC_KEY_get0_group(my_eckey);
            const EC_POINT *pub = EC_KEY_get0_public_key(my_eckey);
            BIGNUM *x = BN_new(), *y = BN_new();
            EC_POINT_get_affine_coordinates(group, pub, x, y, NULL);
            BN_bn2binpad(x, my_exchange,      48);
            BN_bn2binpad(y, my_exchange + 48, 48);
            BN_free(x); BN_free(y);
            EC_KEY_free(my_eckey);
        }
        EVP_PKEY_free(eph_pkey);  /* shared secret + pubkey already extracted */

        /* Snapshot message_a (VERSION+CAPS+ALGORITHMS only) for this session */
        memcpy(g_session.message_a, g_transcript, g_transcript_len);
        g_session.message_a_len = g_transcript_len;
        g_session.message_k_len = 0;

        /* message_k: KEY_EXCHANGE request, exact unpadded bytes only */
        memcpy(g_session.message_k, req, req_actual_len);
        g_session.message_k_len = req_actual_len;

        /* Build response body up to (not including) Signature/VerifyData */
        int pos = 0;
        uint16_t rsp_session_id = 0xFFFF;
        rsp[pos++] = ver;
        rsp[pos++] = SPDM_RSP_KEY_EXCHANGE;
        rsp[pos++] = 0;  /* HeartbeatPeriod */
        rsp[pos++] = 0;  /* Param2/reserved */
        memcpy(rsp + pos, &rsp_session_id, 2); pos += 2;
        rsp[pos++] = 0;  /* MutAuthRequested: none */
        rsp[pos++] = 0;  /* ReqSlotID */
        if (RAND_bytes(rsp + pos, 32) != 1)
            memset(rsp + pos, 0x42, 32);  /* fallback, should not happen */
        pos += 32;
        memcpy(rsp + pos, my_exchange, 96); pos += 96;
        /* no MeasurementSummaryHash: request's HashType was None */

        /*
         * OpaqueData: requester's NEGOTIATE_ALGORITHMS set OtherParamsSel
         * OPAQUE_DATA_FMT1 (echoed back at the NEG_ALGOS handler), so the
         * requester's req_get_dmtf_secure_spdm_version_selection() requires
         * an FM1-framed SMVersionSelOpaque element here. Without it, the
         * requester's opaque decode returns None and the whole KEY_EXCHANGE
         * is rejected *silently* (no error log) right before computing
         * secure_spdm_version_sel - this is what was happening.
         * FM1OpaqueDataHeader: total_elements(1)=1, reserved(u24)=0.
         * SMVersionSelOpaque: DMTF_ID(1)=0, DMTF_VENDOR_LEN(1)=0,
         *   OpaqueElementDataLen(u16 LE)=4, SM_DATA_VERSION(1)=1,
         *   SMDataId(1)=0 (VersionSelectionSmDataId),
         *   SecuredMessageVersion(2) = {0x00, 0x11} -> v1.1 (one of the
         *   versions {1.0, 1.1} the requester offered in its own KEY_EXCHANGE
         *   request opaque data).
         */
        {
            static const uint8_t opaque_sm_version_sel[12] = {
                0x01, 0x00, 0x00, 0x00,             /* FM1OpaqueDataHeader */
                0x00, 0x00, 0x04, 0x00, 0x01, 0x00, /* SMVersionSelOpaque hdr */
                0x00, 0x11,                          /* SecuredMessageVersion 1.1 */
            };
            uint16_t opaque_len = sizeof(opaque_sm_version_sel);
            memcpy(rsp + pos, &opaque_len, 2); pos += 2;
            memcpy(rsp + pos, opaque_sm_version_sel, opaque_len); pos += opaque_len;
        }

        memcpy(g_session.message_k + g_session.message_k_len, rsp, pos);
        g_session.message_k_len += pos;

        /* TH1 (pre-signature) = SHA384(message_a || chain_hash || message_k) */
        uint8_t th[48];
        {
            EVP_MD_CTX *hctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(hctx, EVP_sha384(), NULL);
            EVP_DigestUpdate(hctx, g_session.message_a, g_session.message_a_len);
            EVP_DigestUpdate(hctx, g_crypto.chain_hash, 48);
            EVP_DigestUpdate(hctx, g_session.message_k, g_session.message_k_len);
            unsigned int th_len = 0;
            EVP_DigestFinal_ex(hctx, th, &th_len);
            EVP_MD_CTX_free(hctx);
        }

        LOG("doe-emu: KEYEX-DEBUG message_a_len=%zu message_a=%s",
            g_session.message_a_len, hex_str(g_session.message_a, g_session.message_a_len));
        LOG("doe-emu: KEYEX-DEBUG chain_hash=%s", hex_str(g_crypto.chain_hash, 48));
        LOG("doe-emu: KEYEX-DEBUG message_k_len(pre-sig)=%zu message_k=%s",
            g_session.message_k_len, hex_str(g_session.message_k, g_session.message_k_len));
        LOG("doe-emu: KEYEX-DEBUG TH1=%s", hex_str(th, 48));

        /* Signature over signing_prefix(64) || zeropad(2) || context(34) || TH1(48) */
        uint8_t sign_prefix[64];
        spdm_signing_prefix(ver, sign_prefix);
        uint8_t message_sign[64 + 2 + 34 + 48];
        size_t mpos = 0;
        memcpy(message_sign + mpos, sign_prefix, 64); mpos += 64;
        memcpy(message_sign + mpos, SPDM_ZEROPAD_2, 2); mpos += 2;
        memcpy(message_sign + mpos, SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT, 34); mpos += 34;
        memcpy(message_sign + mpos, th, 48); mpos += 48;

        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx || EVP_DigestSignInit(mdctx, NULL, EVP_sha384(), NULL,
                                         g_crypto.pkey) <= 0) {
            LOG("doe-emu: KEY_EXCHANGE sign init failed");
            if (mdctx) EVP_MD_CTX_free(mdctx);
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }
        EVP_DigestSignUpdate(mdctx, message_sign, mpos);

        size_t der_len = 0;
        EVP_DigestSignFinal(mdctx, NULL, &der_len);
        uint8_t *der = malloc(der_len);
        if (!der || EVP_DigestSignFinal(mdctx, der, &der_len) <= 0) {
            LOG("doe-emu: KEY_EXCHANGE sign final failed");
            free(der);
            EVP_MD_CTX_free(mdctx);
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }
        EVP_MD_CTX_free(mdctx);

        const unsigned char *dp = der;
        ECDSA_SIG *esig = d2i_ECDSA_SIG(NULL, &dp, (long)der_len);
        free(der);
        if (!esig) {
            LOG("doe-emu: KEY_EXCHANGE d2i_ECDSA_SIG failed");
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }
        const BIGNUM *r, *s;
        ECDSA_SIG_get0(esig, &r, &s);
        BN_bn2binpad(r, rsp + pos,      48);
        BN_bn2binpad(s, rsp + pos + 48, 48);
        ECDSA_SIG_free(esig);
        pos += 96;

        LOG("doe-emu: KEYEX-DEBUG signature=%s", hex_str(rsp + pos - 96, 96));

        memcpy(g_session.message_k + g_session.message_k_len, rsp + pos - 96, 96);
        g_session.message_k_len += 96;

        /* HKDF key schedule */
        uint8_t zero_salt[48] = {0};
        if (hkdf_extract_sha384(zero_salt, 48, shared_secret, 48,
                                 g_session.handshake_secret) != 0) {
            LOG("doe-emu: HKDF-extract(handshake_secret) failed");
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }

        /* TH1' = SHA384(message_a || chain_hash || message_k_with_signature) */
        {
            EVP_MD_CTX *hctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(hctx, EVP_sha384(), NULL);
            EVP_DigestUpdate(hctx, g_session.message_a, g_session.message_a_len);
            EVP_DigestUpdate(hctx, g_crypto.chain_hash, 48);
            EVP_DigestUpdate(hctx, g_session.message_k, g_session.message_k_len);
            unsigned int th_len = 0;
            EVP_DigestFinal_ex(hctx, th, &th_len);
            EVP_MD_CTX_free(hctx);
        }

        uint8_t info[2 + 8 + 16 + 48];
        size_t info_len;
        uint8_t rsp_hs_secret[48], req_hs_secret[48];

        info_len = spdm_binconcat(48, ver, (const uint8_t *)"rsp hs data", 11, th, 48, info);
        if (hkdf_expand_sha384(g_session.handshake_secret, info, info_len,
                                rsp_hs_secret, 48) != 0) {
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }
        info_len = spdm_binconcat(48, ver, (const uint8_t *)"req hs data", 11, th, 48, info);
        if (hkdf_expand_sha384(g_session.handshake_secret, info, info_len,
                                req_hs_secret, 48) != 0) {
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }

        info_len = spdm_binconcat(48, ver, (const uint8_t *)"finished", 8, NULL, 0, info);
        if (hkdf_expand_sha384(rsp_hs_secret, info, info_len,
                                g_session.rsp_finished_key, 48) != 0 ||
            hkdf_expand_sha384(req_hs_secret, info, info_len,
                                g_session.req_finished_key, 48) != 0) {
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }

        /* Derive handshake AEAD keys (AES-256-GCM: 32-byte key, 12-byte IV) */
        info_len = spdm_binconcat(32, ver, (const uint8_t *)"key", 3, NULL, 0, info);
        if (hkdf_expand_sha384(req_hs_secret, info, info_len, g_session.req_hs_key, 32) != 0 ||
            hkdf_expand_sha384(rsp_hs_secret, info, info_len, g_session.rsp_hs_key, 32) != 0) {
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }
        info_len = spdm_binconcat(12, ver, (const uint8_t *)"iv", 2, NULL, 0, info);
        if (hkdf_expand_sha384(req_hs_secret, info, info_len, g_session.req_hs_iv, 12) != 0 ||
            hkdf_expand_sha384(rsp_hs_secret, info, info_len, g_session.rsp_hs_iv, 12) != 0) {
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }

        /* Responder Verify Data = HMAC-SHA384(rsp_finished_key, TH1') */
        uint8_t verify_data[48];
        unsigned int vd_len = 0;
        if (!HMAC(EVP_sha384(), g_session.rsp_finished_key, 48, th, 48,
                  verify_data, &vd_len) || vd_len != 48) {
            LOG("doe-emu: KEY_EXCHANGE verify_data HMAC failed");
            spdm_error(doe_type, SPDM_ERR_UNSUP);
            break;
        }
        memcpy(rsp + pos, verify_data, 48);
        memcpy(g_session.message_k + g_session.message_k_len, verify_data, 48);
        g_session.message_k_len += 48;
        pos += 48;

        g_session.active = 1;
        g_session.established = 0;
        g_session.session_id = ((uint32_t)rsp_session_id << 16) | req_session_id;
        g_session.req_seq_no = 0;
        g_session.rsp_seq_no = 0;
        g_session.message_f_len = 0;

        spdm_finish(doe_type, pos);
        LOG("doe-emu: SPDM → KEY_EXCHANGE_RSP (session_id=0x%08x, total=%d bytes)",
            g_session.session_id, pos);
        break;
    }

    default:
        LOG("doe-emu: SPDM unsupported code=0x%02x", code);
        spdm_error(doe_type, SPDM_ERR_UNSUP);
        break;
    }
}

/* ------------------------------------------------------------------ */
/* Secured-message (DOE Type=2) handler                                */
/* ------------------------------------------------------------------ */

static void spdm_finish_rsp_secured(void);
static void spdm_meas_rsp_secured(const uint8_t *inner, size_t inner_len);

static void handle_secured_spdm(void)
{
    uint8_t *raw = (uint8_t *)&doe.req_buf[2]; /* skip 2-dword DOE header */
    size_t   raw_len = (size_t)(doe.req_len - 2) * 4;

    if (!g_session.active) {
        LOG("doe-emu: secured msg but no active session");
        doe.status = DOE_STATUS_ERROR;
        return;
    }

    /* Choose decrypt key: handshake or data phase */
    const uint8_t *key = g_session.established ? g_session.req_data_key : g_session.req_hs_key;
    const uint8_t *iv  = g_session.established ? g_session.req_data_iv  : g_session.req_hs_iv;
    uint64_t       seq = g_session.req_seq_no;

    uint8_t inner[512];
    size_t  inner_len = 0;
    if (secured_msg_decode(raw, raw_len, key, iv, seq, inner, &inner_len) != 0) {
        LOG("doe-emu: AEAD decrypt failed (seq=%llu, established=%d)",
            (unsigned long long)seq, g_session.established);
        doe.status = DOE_STATUS_ERROR;
        return;
    }
    g_session.req_seq_no++;

    if (inner_len < 2) {
        LOG("doe-emu: secured inner too short");
        doe.status = DOE_STATUS_ERROR;
        return;
    }

    uint8_t ver  = inner[0];
    uint8_t code = inner[1];
    LOG("doe-emu: secured SPDM ver=0x%02x code=0x%02x (established=%d)",
        ver, code, g_session.established);

    if (code == SPDM_FINISH) {
        /* inner[0..4] = ver, code, Param1, Param2
         * inner[4..52] = VerifyData (48 bytes, no Signature since MutAuth=0)
         */
        if (inner_len < 4 + 48) {
            LOG("doe-emu: FINISH too short (%zu)", inner_len);
            doe.status = DOE_STATUS_ERROR;
            return;
        }

        /* Append FINISH request header (4 bytes) to message_f */
        if (g_session.message_f_len + 4 > sizeof(g_session.message_f)) {
            doe.status = DOE_STATUS_ERROR;
            return;
        }
        memcpy(g_session.message_f + g_session.message_f_len, inner, 4);
        g_session.message_f_len += 4;

        /* TH2_req = SHA384(message_a || chain_hash || message_k || message_f) */
        uint8_t th2[48];
        {
            EVP_MD_CTX *hctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(hctx, EVP_sha384(), NULL);
            EVP_DigestUpdate(hctx, g_session.message_a, g_session.message_a_len);
            EVP_DigestUpdate(hctx, g_crypto.chain_hash, 48);
            EVP_DigestUpdate(hctx, g_session.message_k, g_session.message_k_len);
            EVP_DigestUpdate(hctx, g_session.message_f, g_session.message_f_len);
            unsigned int tlen = 0;
            EVP_DigestFinal_ex(hctx, th2, &tlen);
            EVP_MD_CTX_free(hctx);
        }

        /* Verify requester HMAC */
        uint8_t expected_hmac[48];
        unsigned int hlen = 0;
        HMAC(EVP_sha384(), g_session.req_finished_key, 48,
             th2, 48, expected_hmac, &hlen);
        if (hlen != 48 || memcmp(expected_hmac, inner + 4, 48) != 0) {
            LOG("doe-emu: verify_hmac_with_request_finished_key FAIL");
            doe.status = DOE_STATUS_ERROR;
            return;
        }
        LOG("doe-emu: verify_hmac_with_request_finished_key pass");

        /* Append req verify_data to message_f */
        memcpy(g_session.message_f + g_session.message_f_len, inner + 4, 48);
        g_session.message_f_len += 48;

        spdm_finish_rsp_secured();

    } else if (code == SPDM_GET_MEAS) {
        spdm_meas_rsp_secured(inner, inner_len);
    } else {
        LOG("doe-emu: unsupported secured SPDM code=0x%02x", code);
        doe.status = DOE_STATUS_ERROR;
    }
}

static void spdm_finish_rsp_secured(void)
{
    uint8_t ver = 0x12;

    /* Build FINISH_RSP (4 bytes, no verify_data: not in_clear_text) */
    uint8_t finish_rsp[4] = { ver, SPDM_RSP_FINISH, 0x00, 0x00 };

    /* Append FINISH_RSP header (4 bytes) to message_f */
    memcpy(g_session.message_f + g_session.message_f_len, finish_rsp, 4);
    g_session.message_f_len += 4;

    /* TH2 for data secrets = SHA384(message_a || chain_hash || message_k || message_f) */
    uint8_t th2[48];
    {
        EVP_MD_CTX *hctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(hctx, EVP_sha384(), NULL);
        EVP_DigestUpdate(hctx, g_session.message_a, g_session.message_a_len);
        EVP_DigestUpdate(hctx, g_crypto.chain_hash, 48);
        EVP_DigestUpdate(hctx, g_session.message_k, g_session.message_k_len);
        EVP_DigestUpdate(hctx, g_session.message_f, g_session.message_f_len);
        unsigned int tlen = 0;
        EVP_DigestFinal_ex(hctx, th2, &tlen);
        EVP_MD_CTX_free(hctx);
    }
    LOG("doe-emu: FINISH TH2=%s", hex_str(th2, 48));

    /* Derive MasterSecret: salt_1 = HKDF-Expand(HS, binconcat(48, "derived", NULL))
     *                      MS     = HKDF-Extract(salt_1, 0x00...00) */
    uint8_t info[2 + 8 + 16 + 48];
    size_t  info_len;
    uint8_t salt_1[48], master_secret[48];
    uint8_t zero48[48] = {0};

    info_len = spdm_binconcat(48, ver, (const uint8_t *)"derived", 7, NULL, 0, info);
    if (hkdf_expand_sha384(g_session.handshake_secret, info, info_len, salt_1, 48) != 0 ||
        hkdf_extract_sha384(salt_1, 48, zero48, 48, master_secret) != 0) {
        LOG("doe-emu: master_secret derivation failed");
        doe.status = DOE_STATUS_ERROR;
        return;
    }

    /* Derive data secrets */
    uint8_t req_data_secret[48], rsp_data_secret[48];
    info_len = spdm_binconcat(48, ver, (const uint8_t *)"req app data", 12, th2, 48, info);
    if (hkdf_expand_sha384(master_secret, info, info_len, req_data_secret, 48) != 0) {
        doe.status = DOE_STATUS_ERROR; return;
    }
    info_len = spdm_binconcat(48, ver, (const uint8_t *)"rsp app data", 12, th2, 48, info);
    if (hkdf_expand_sha384(master_secret, info, info_len, rsp_data_secret, 48) != 0) {
        doe.status = DOE_STATUS_ERROR; return;
    }

    /* Derive data AEAD keys */
    info_len = spdm_binconcat(32, ver, (const uint8_t *)"key", 3, NULL, 0, info);
    if (hkdf_expand_sha384(req_data_secret, info, info_len, g_session.req_data_key, 32) != 0 ||
        hkdf_expand_sha384(rsp_data_secret, info, info_len, g_session.rsp_data_key, 32) != 0) {
        doe.status = DOE_STATUS_ERROR; return;
    }
    info_len = spdm_binconcat(12, ver, (const uint8_t *)"iv", 2, NULL, 0, info);
    if (hkdf_expand_sha384(req_data_secret, info, info_len, g_session.req_data_iv, 12) != 0 ||
        hkdf_expand_sha384(rsp_data_secret, info, info_len, g_session.rsp_data_iv, 12) != 0) {
        doe.status = DOE_STATUS_ERROR; return;
    }

    g_session.established = 1;
    g_session.req_seq_no = 0;
    g_session.rsp_seq_no = 0;
    LOG("doe-emu: generate_data_secret done — session established");

    /* Encrypt and send FINISH_RSP via handshake AEAD (rsp direction) */
    uint8_t enc_buf[128];
    int enc_len = secured_msg_encode(g_session.session_id,
                                      finish_rsp, 4,
                                      g_session.rsp_hs_key, g_session.rsp_hs_iv,
                                      0 /* seq=0 for FINISH_RSP in hs phase */,
                                      enc_buf);
    if (enc_len <= 0) {
        doe.status = DOE_STATUS_ERROR;
        return;
    }

    /* Wrap in DOE header (VID=0x0001, Type=0x02) and pad to dword boundary */
    int total_bytes = enc_len;
    int dwords = (total_bytes + 3) / 4;
    doe.rsp_buf[0] = ((uint32_t)DOE_TYPE_SECURED_CMA_SPDM << 16) | DOE_VID_PCISIG;
    doe.rsp_buf[1] = (uint32_t)(dwords + 2);
    memset(doe.rsp_buf + 2, 0, (dwords + 1) * 4);
    memcpy(doe.rsp_buf + 2, enc_buf, total_bytes);
    doe.rsp_len = dwords + 2;
    doe.rsp_idx = 0;
    doe.status  = DOE_STATUS_DATA_OBJECT_READY;
    LOG("doe-emu: SPDM → FINISH_RSP (secured, %d bytes inner)", total_bytes);
}

static void spdm_meas_rsp_secured(const uint8_t *inner, size_t inner_len)
{
    uint8_t ver = (inner_len >= 1) ? inner[0] : 0x12;
    (void)inner_len;

    /* Minimal GET_MEASUREMENTS response: NumberOfBlocks=0, MeasurementRecordLength=0,
     * no Nonce, no OpaqueData, no Signature (Param1 bit 0 = 0 means no sig requested
     * is what we assume — TPA may or may not request sig). Return empty record. */
    uint8_t app[8];
    app[0] = ver;
    app[1] = SPDM_RSP_MEAS;
    app[2] = 0x00;  /* Param1 */
    app[3] = 0x00;  /* Param2: slot=0 */
    app[4] = 0x00;  /* NumberOfBlocks */
    app[5] = 0x00;  /* MeasurementRecordLength (24-bit LE) */
    app[6] = 0x00;
    app[7] = 0x00;

    const uint8_t *key = g_session.rsp_data_key;
    const uint8_t *iv  = g_session.rsp_data_iv;
    uint64_t        seq = g_session.rsp_seq_no;

    uint8_t enc_buf[128];
    int enc_len = secured_msg_encode(g_session.session_id, app, 8, key, iv, seq, enc_buf);
    if (enc_len <= 0) {
        doe.status = DOE_STATUS_ERROR;
        return;
    }
    g_session.rsp_seq_no++;

    int dwords = (enc_len + 3) / 4;
    doe.rsp_buf[0] = ((uint32_t)DOE_TYPE_SECURED_CMA_SPDM << 16) | DOE_VID_PCISIG;
    doe.rsp_buf[1] = (uint32_t)(dwords + 2);
    memset(doe.rsp_buf + 2, 0, (dwords + 1) * 4);
    memcpy(doe.rsp_buf + 2, enc_buf, enc_len);
    doe.rsp_len = dwords + 2;
    doe.rsp_idx = 0;
    doe.status  = DOE_STATUS_DATA_OBJECT_READY;
    LOG("doe-emu: SPDM → MEASUREMENTS_RSP (secured, empty)");
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
