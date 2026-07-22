/*
 * thin-server-enum.c
 *
 * Bridges daemon-enum (TCP :5556) to cosim/Simics RTL (named pipes).
 * Translates cosim_pci_enum_op <-> simics_transaction_t.
 *
 * Startup order:
 *   1. make simulate   (simv opens the named pipes)
 *   2. ./thin-server-enum
 *   3. ./daemon-enum
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

#include <linux/cosim_enum.h>
#include "log.h"

#define SERVER_PORT   5556
#define PIPE_PATH_ENV "CXL_RELAY_SERVER_PATH"

/* simics_transaction_t + MAX_PAYLOAD -- shared definition. */
#include "simics_transaction.h"

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

    LOG("thin-server-enum: pipes opened: %s", path);
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
    struct cosim_pci_enum_op op;
    simics_transaction_t req, rsp;

    while (1) {
        xrecv(client, &op, sizeof(op));

        LOG("REQ  bus=%u dev=%u fn=%u offset=0x%x size=%u type=%s",
            op.bus, op.devfn >> 3, op.devfn & 7,
            op.offset, op.size,
            op.type == COSIM_ENUM_READ ? "R" : "W");

        memset(&req, 0, sizeof(req));
        req.packet_number    = ++seq;
        req.packet_type      = 1;           /* config transaction */
        req.sim_type         = 1;
        req.bus_no           = op.bus;
        req.dev_no           = op.devfn >> 3;
        req.fun_no           = op.devfn & 7;
        req.physical_address = op.offset;
        req.r0w1             = (op.type == COSIM_ENUM_WRITE) ? 1 : 0;
        req.data_size        = op.size;
        memcpy(req.data, &op.value, op.size);

        xwrite(req_fd, &req, sizeof(req));
        xread (rep_fd, &rsp, sizeof(rsp));

        op.status = (int32_t)rsp.cmp_status;
        memcpy(&op.value, rsp.data, op.size);

        LOG("RSP  status=%d value=0x%x", op.status, op.value);

        xsend(client, &op, sizeof(op));
    }
}

int main(void)
{
    log_init(getenv("CXL_LOG_FILE"));

    const char *pipe_path = getenv(PIPE_PATH_ENV);
    if (!pipe_path) {
        fprintf(stderr, "thin-server-enum: %s not set\n", PIPE_PATH_ENV);
        log_close();
        return 1;
    }

    if (open_pipes(pipe_path) < 0) {
        log_close();
        return 1;
    }

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
    LOG("thin-server-enum: listening on :%d", SERVER_PORT);

    int client = accept(srv, NULL, NULL);
    if (client < 0) { perror("accept"); return 1; }
    LOG("thin-server-enum: daemon-enum connected");

    serve(client);

    close(client);
    close(srv);
    close(req_fd);
    close(rep_fd);
    log_close();
    return 0;
}
