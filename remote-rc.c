/* remote_rc.c */
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <linux/pci-doe.h>
#include <linux/pci_regs.h>

#define PORT 5555

int main()
{
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {0};

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    bind(s, (struct sockaddr *)&addr, sizeof(addr));
    listen(s, 1);

    printf("Remote RC waiting...\n");

    int c = accept(s, NULL, NULL);

    struct avery_pci_config_op op;

    while (1) {

        if (recv(c, &op, sizeof(op), MSG_WAITALL) <= 0)
            break;

        printf("Remote got req type=%d off=0x%x\n",
               op.type, op.offset);

        if (op.type == PCI_DOE_READ)
            op.value = 0xCAFEBABE;

        op.status = 0;

        send(c, &op, sizeof(op), 0);
    }
}
