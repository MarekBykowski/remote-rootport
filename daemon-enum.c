/*
 * daemon-enum.c
 *
 * Bridges /dev/cosim_enum_chardev0 (kernel) to thin-server-enum (TCP :5556).
 * Mirrors daemon-doe.c but for PCI config-space enumeration ops.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <linux/cosim_wire.h>
#include "log.h"

#define MINOR 0

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define DEV_PATH        "/dev/cosim_enum_chardev" STR(MINOR)
#define SERVER_IP_ENV   "CXL_RELAY_SERVER_IP"
#define SERVER_IP_DEFAULT "127.0.0.1"
#define SERVER_PORT     5556

static int connect_remote(void)
{
    int sock;
    struct sockaddr_in addr;
    const char *server_ip = getenv(SERVER_IP_ENV);
    if (!server_ip)
        server_ip = SERVER_IP_DEFAULT;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); exit(1); }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(SERVER_PORT);

    if (inet_pton(AF_INET, server_ip, &addr.sin_addr) <= 0) {
        perror("inet_pton"); exit(1);
    }
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect"); exit(1);
    }

    LOG("Connected to thin-server-enum %s:%d", server_ip, SERVER_PORT);
    return sock;
}

static void send_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len) {
        ssize_t n = send(fd, p, len, 0);
        if (n <= 0) { perror("send"); exit(1); }
        p += n; len -= n;
    }
}

static void recv_all(int fd, void *buf, size_t len)
{
    char *p = buf;
    while (len) {
        ssize_t n = recv(fd, p, len, 0);
        if (n <= 0) { perror("recv"); exit(1); }
        p += n; len -= n;
    }
}

int main(void)
{
    int devfd, sockfd;
    struct pollfd pfd;
    struct cosim_wire_op op;

    log_init(getenv("CXL_LOG_FILE"));

    devfd = open(DEV_PATH, O_RDWR);
    if (devfd < 0) {
        perror("open cosim_enum_chardev");
        log_close();
        return 1;
    }

    sockfd = connect_remote();
    LOG("daemon-enum started");

    pfd.fd     = devfd;
    pfd.events = POLLIN;

    while (1) {
        int ret = poll(&pfd, 1, -1);
        if (ret < 0) { perror("poll"); break; }

        if (pfd.revents & POLLIN) {
            ssize_t n = read(devfd, &op, sizeof(op));
            if (n <= 0) { perror("read"); break; }

            if (op.kind == COSIM_OP_MMIO)
                LOG("REQ: MMIO bus=%u devfn=%u addr=0x%llx size=%u type=%s",
                    op.mmio.bus, op.mmio.devfn,
                    (unsigned long long)op.mmio.addr, op.mmio.size,
                    op.mmio.type == COSIM_MMIO_READ ? "R" : "W");
            else
                LOG("REQ: CFG bus=%u devfn=%u offset=0x%x size=%u type=%s",
                    op.enum_op.bus, op.enum_op.devfn, op.enum_op.offset,
                    op.enum_op.size,
                    op.enum_op.type == COSIM_ENUM_READ ? "R" : "W");

            send_all(sockfd, &op, sizeof(op));
            recv_all(sockfd, &op, sizeof(op));

            if (op.kind == COSIM_OP_MMIO)
                LOG("RSP: status=%d value=0x%llx",
                    op.mmio.status, (unsigned long long)op.mmio.value);
            else
                LOG("RSP: status=%d value=0x%x",
                    op.enum_op.status, op.enum_op.value);

            if (write(devfd, &op, sizeof(op)) < 0) {
                perror("write"); break;
            }
        }
    }

    close(sockfd);
    close(devfd);
    log_close();
    return 0;
}
