/*
 * dpi_cosim.c
 *
 * Minimal, self-contained DPI-C bridge between the DMR-EIP RTL simulation
 * (simv) and the cosim enum named pipes. A drop-in replacement for
 * cxl_relay's libcxltlprelay.so for the pcie_txn_cosim_test / enum flow.
 *
 * simv only holds the SV-side DPI *import declarations*
 *   EipPcieTBSeqPkg.sv -> file
 *     package pi5_simics_dpi_pkg; -> package
 *       import "DPI-C" function int  -> a DPI import
 *          open_server_fifo_path(input string cxl_relay_server_path);
 *       ...
 *
 * simv, in eip_cosim_enum_seq.svh, uses them:
 *   open the pipes once, in body() (eip_cosim_enum_seq.svh)
 *      ret = pi5_simics_dpi_pkg::open_server_fifo_path(cxl_relay_server_path);
 *   relay loop, in runPort() -> request -> drive into the RTL -> response
 *      do begin
 *         automatic bit [7:0] cfg_data_temp[4];
 *         pi5_simics_dpi_pkg::simics_dpi_request(req);   // block-read one request
 *         ...
 *
 *
 * The function bodies come from the .so VCS loads at runtime via -sv_lib. This
 * file supplies exactly the four functions that package imports, plus the
 * matching simics_transaction_t layout -- nothing else from cxl_relay is
 * needed (no named_pipe.c / cxl_tlp_fifo.c / pcie_tlp_pkt_lib.c / dml_*).
 *
 *   open_server_fifo_path(path)  open request_server_pipe + reply_server_pipe
 *   simics_dpi_request(pkt)      block-read one request, program byte enables
 *   simics_dpi_response(pkt)     write one completion back
 *   print_simics_pkt_data(pkt)   optional one-line log
 *
 * Transport: two FIFOs under <path> (the +cxl_relay_server_path plusarg) --
 * the same two files thin-server-enum sits on:
 *   request_server_pipe  simv reads  (thin-server-enum writes)
 *   reply_server_pipe    simv writes (thin-server-enum reads)
 *
 * Build (on the sim host; needs VCS's svdpi.h, so VCS_HOME must be set --
 * source val/env/cxl_relay/source.me, or any env that sets VCS_HOME):
 *   gcc -shared -fPIC -I$VCS_HOME/include dpi_cosim.c -o libdpicosim.so
 *
 * Load into simv (in place of -sv_lib libcxltlprelay); point -sv_root at the
 * directory holding libdpicosim.so, and keep +cxl_relay_server_path pointing
 * at the same directory thin-server-enum uses:
 *   trex ... -sv_root <dir with libdpicosim.so> -sv_lib libdpicosim \
 *            +cxl_relay_server_path=<thin-server-enum's CXL_RELAY_SERVER_PATH> ...
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "svdpi.h"

/* simics_transaction_t + MAX_PAYLOAD -- shared definition (matches the SV
 * typedef in EipPcieTBSeqPkg.sv / cxl_relay's cxl_tlp_fifo.h). */
#include "simics_transaction.h"

/* request_server_pipe: simv reads requests. reply_server_pipe: simv writes replies. */
static int req_fd = -1;
static int rep_fd = -1;

static int full_read(int fd, void *buf, size_t len)
{
    char *p = buf;
    while (len) {
        ssize_t n = read(fd, p, len);
        if (n <= 0)
            return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int full_write(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n <= 0)
            return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

/*
 * Program the PCIe byte enables from address + size, exactly as cxl_relay's
 * byte_enable.c did. The SV data_calc_be() task consumes these fields
 * (fixed_first_size / unaligned_value / fbe / fixed_last_size / lbe) to drive
 * the config cycle, so they MUST be set on this side -- thin-server-enum does
 * not set them.
 */
static void program_byte_enables(simics_transaction_t *pkt)
{
    static const int byte_en[] = {15, 1, 3, 7, 15};
    unsigned long long adrs            = pkt->physical_address;
    int                size            = (int)pkt->data_size;
    unsigned long long adrs_dw_aligned = adrs >> 2;
    int max_first_size = 4 - (int)(adrs - (adrs_dw_aligned << 2));
    int first_size     = (size > max_first_size) ? max_first_size : size;
    int k              = (int)(adrs & 3);
    int first_byte_enable = byte_en[first_size] << (adrs & 3);

    unsigned long long last_adrs            = adrs + size - 1;
    unsigned long long last_adrs_dw_aligned = last_adrs >> 2;
    int last_size, last_byte_enable;

    if (last_adrs_dw_aligned > adrs_dw_aligned) {
        last_size        = (int)(last_adrs - (last_adrs_dw_aligned << 2) + 1);
        last_byte_enable = byte_en[last_size];
    } else {
        last_size        = 0;
        last_byte_enable = 0;
    }

    pkt->fixed_first_size = (unsigned int)first_size;
    pkt->unaligned_value  = (unsigned int)k;
    pkt->fbe              = (unsigned int)first_byte_enable;
    pkt->fixed_last_size  = (unsigned int)last_size;
    pkt->lbe              = (unsigned int)last_byte_enable;
}

int open_server_fifo_path(const char *cxl_relay_server_path)
{
    char req[1024], rep[1024];

    if (!cxl_relay_server_path) {
        printf("dpi_cosim: server path not set\n");
        return -1;
    }
    snprintf(req, sizeof(req), "%s/request_server_pipe", cxl_relay_server_path);
    snprintf(rep, sizeof(rep), "%s/reply_server_pipe",   cxl_relay_server_path);

    mkfifo(req, 0666);   /* ignore EEXIST: whoever starts first creates it */
    mkfifo(rep, 0666);

    /* O_RDWR so open() never blocks waiting for the peer end to appear. */
    req_fd = open(req, O_RDWR);
    if (req_fd < 0) {
        printf("dpi_cosim: cannot open %s\n", req);
        return -1;
    }
    rep_fd = open(rep, O_RDWR);
    if (rep_fd < 0) {
        printf("dpi_cosim: cannot open %s\n", rep);
        return -1;
    }

    printf("dpi_cosim: pipes opened under %s\n", cxl_relay_server_path);
    return 0;
}

int simics_dpi_request(simics_transaction_t *from_simics)
{
    /* Block until thin-server-enum writes one request struct. */
    if (full_read(req_fd, from_simics, sizeof(*from_simics)) < 0) {
        printf("dpi_cosim: request read failed\n");
        return -1;
    }
    program_byte_enables(from_simics);
    return 1;
}

int simics_dpi_response(simics_transaction_t *to_simics)
{
    if (full_write(rep_fd, to_simics, sizeof(*to_simics)) < 0) {
        printf("dpi_cosim: reply write failed\n");
        return -1;
    }
    return 1;
}

void print_simics_pkt_data(simics_transaction_t *pkt)
{
    if (!pkt)
        return;
    printf("dpi_cosim: pkt#=%u type=%u bus=%u dev=%u fn=%u addr=0x%llx r0w1=%u size=%u\n",
           pkt->packet_number, pkt->packet_type, pkt->bus_no, pkt->dev_no,
           pkt->fun_no, pkt->physical_address, pkt->r0w1, pkt->data_size);
}
