/* remote_rc.c */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/pci_regs.h>

#include <linux/avery_doe.h>

#define PORT 5555

int main(void)
{
    int s, c;
    struct sockaddr_in addr;
    struct avery_pci_config_op op;

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket");
        return 1;
    }

    int opt = 1;
    if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(s, 1) < 0) {
        perror("listen");
        return 1;
    }

    printf("Remote RC waiting on port %d...\n", PORT);

    c = accept(s, NULL, NULL);
    if (c < 0) {
        perror("accept");
        return 1;
    }

    printf("Daemon connected\n");

    while (1) {

        ssize_t n = recv(c, &op, sizeof(op), MSG_WAITALL);
        if (n <= 0) {
            perror("recv");
            break;
        }

        printf("Remote got req: type=%u offset=0x%x value=0x%x\n",
               op.type, op.offset, op.value);

        /* emulate behavior */
        if (op.type == PCI_DOE_READ) {
            op.value = 0xCAFEBABE;
        }

        op.status = 0;

        if (send(c, &op, sizeof(op), 0) != sizeof(op)) {
            perror("send");
            break;
        }

        printf("Remote sent resp: status=%d value=0x%x\n",
               op.status, op.value);
    }

    close(c);
    close(s);

    return 0;
}
