/*
 * thin-server.c
 *
 * Bridges daemon-doe (TCP :5555) to simv RTL (named pipes).
 * Translates avery_pci_config_op <-> simics_transaction_t.
 * No dependency on cxl_relay.
 *
 * Startup order:
 *   1. make simulate  (simv opens the named pipes)
 *   2. ./thin-server  (opens pipes, listens on TCP :5555)
 *   3. ./daemon-doe   (connects to :5555)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include <linux/avery_doe.h>

#define SERVER_PORT   5555
#define PIPE_PATH_ENV "CXL_RELAY_SERVER_PATH"
#define MAX_PAYLOAD   256

/*
 * DOE mailbox register offsets from pci_regs.h, reused as op type
 * in avery_pci_config_op.type by the kernel doe.c interception layer.
 */
#define AVERY_OP_WRITE  0x10
#define AVERY_OP_READ   0x14

/* Copied from cxl_relay/cxl_tlp_fifo.h — must match simv DPI-C struct layout */
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

static int req_fd = -1;
static int rep_fd = -1;
static uint32_t seq = 0;

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

    printf("thin-server: pipes opened: %s\n", path);
    return 0;
}

static void xrecv(int fd, void *buf, size_t len)
{
    char *p = buf;
    while (len) {
        ssize_t n = recv(fd, p, len, 0);
        if (n <= 0) { perror("recv"); exit(1); }
        p += n; len -= n;
    }
}

static void xsend(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len) {
        ssize_t n = send(fd, p, len, 0);
        if (n <= 0) { perror("send"); exit(1); }
        p += n; len -= n;
    }
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

static void serve(int client)
{
    struct avery_pci_config_op op;
    simics_transaction_t req, rsp;

    while (1) {
        xrecv(client, &op, sizeof(op));

        printf("REQ  type=%d offset=0x%x value=0x%x\n",
               op.type, op.offset, op.value);

        memset(&req, 0, sizeof(req));
        req.packet_number    = ++seq;
        req.packet_type      = 1;            /* config transaction */
        req.sim_type         = 1;
        req.physical_address = op.offset;
        req.r0w1             = (op.type == AVERY_OP_WRITE) ? 1 : 0;
        req.data_size        = 4;
        memcpy(req.data, &op.value, 4);

        xwrite(req_fd, &req, sizeof(req));
        xread (rep_fd, &rsp, sizeof(rsp));

        op.status = (int32_t)rsp.cmp_status;
        memcpy(&op.value, rsp.data, 4);

        printf("RSP  status=%d value=0x%x\n", op.status, op.value);

        xsend(client, &op, sizeof(op));
    }
}

int main(void)
{
    const char *pipe_path = getenv(PIPE_PATH_ENV);
    if (!pipe_path) {
        fprintf(stderr, "thin-server: %s not set\n", PIPE_PATH_ENV);
        return 1;
    }

    if (open_pipes(pipe_path) < 0)
        return 1;

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(SERVER_PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    listen(srv, 1);
    printf("thin-server: listening on :%d\n", SERVER_PORT);

    int client = accept(srv, NULL, NULL);
    if (client < 0) { perror("accept"); return 1; }
    printf("thin-server: daemon-doe connected\n");

    serve(client);

    close(client);
    close(srv);
    close(req_fd);
    close(rep_fd);
    return 0;
}
