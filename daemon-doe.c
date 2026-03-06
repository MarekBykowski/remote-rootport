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

#include <linux/pci-doe.h>

#define DEV_PATH "/dev/avery_doe_chardev"
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 5555

static int connect_remote(void)
{
    int sock;
    struct sockaddr_in addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);

    if (inet_pton(AF_INET, SERVER_IP, &addr.sin_addr) <= 0) {
        perror("inet_pton");
        exit(1);
    }

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect");
        exit(1);
    }

    printf("Connected to remote RC %s:%d\n", SERVER_IP, SERVER_PORT);
    return sock;
}

static void send_all(int fd, const void *buf, size_t len)
{
    const char *p = buf;
    while (len) {
        ssize_t n = send(fd, p, len, 0);
        if (n <= 0) {
            perror("send");
            exit(1);
        }
        p += n;
        len -= n;
    }
}

static void recv_all(int fd, void *buf, size_t len)
{
    char *p = buf;
    while (len) {
        ssize_t n = recv(fd, p, len, 0);
        if (n <= 0) {
            perror("recv");
            exit(1);
        }
        p += n;
        len -= n;
    }
}

int main(void)
{
    int devfd;
    int sockfd;
    struct pollfd pfd;
    struct avery_pci_config_op op;

    devfd = open(DEV_PATH, O_RDWR);
    if (devfd < 0) {
        perror("open char dev");
        return 1;
    }

    sockfd = connect_remote();

    printf("Daemon started\n");

    pfd.fd = devfd;
    pfd.events = POLLIN;

    while (1) {

        int ret = poll(&pfd, 1, -1);
        if (ret < 0) {
            perror("poll");
            break;
        }

        if (pfd.revents & POLLIN) {

            ssize_t n = read(devfd, &op, sizeof(op));
            if (n <= 0) {
                perror("read");
                break;
            }

            printf("REQ: type=%d offset=0x%x value=0x%x\n",
                   op.type, op.offset, op.value);

            /* send request to remote emulator */
            send_all(sockfd, &op, sizeof(op));

            /* receive response */
            recv_all(sockfd, &op, sizeof(op));

            printf("RESP: status=%d value=0x%x\n",
                   op.status, op.value);

            if (write(devfd, &op, sizeof(op)) < 0) {
                perror("write");
                break;
            }
        }
    }

    close(sockfd);
    close(devfd);
    return 0;
}

