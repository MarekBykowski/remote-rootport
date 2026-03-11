/* daemon_doe_netlink_fixed.c */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>

#include <linux/avery_doe.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 5555

#define AVERY_FAMILY_NAME "AVERY_DOE"

enum {
	AVERY_CMD_UNSPEC,
	AVERY_CMD_REQUEST,
	AVERY_CMD_RESPONSE,
	AVERY_CMD_REGISTER,
};

enum {
	AVERY_ATTR_UNSPEC,
	AVERY_ATTR_OP,
};

static int nl_sock;
static int family_id;

struct pending_req {
	uint32_t portid;
	uint32_t seq;
};

static void nl_register_daemon(void)
{
	char buffer[256];

	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
	struct genlmsghdr *genl;
	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };

	memset(buffer, 0, sizeof(buffer));

	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_seq = 1;

	genl = NLMSG_DATA(nlh);
	genl->cmd = AVERY_CMD_REGISTER;
	genl->version = 1;

	sendto(nl_sock, buffer, nlh->nlmsg_len, 0,
	   (struct sockaddr *)&addr, sizeof(addr));

	printf("REGISTER sent to kernel\n");
}

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

static int nl_get_family_id(void)
{
	struct {
		struct nlmsghdr nlh;
		struct genlmsghdr genl;
		char buf[256];
	}req;

	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	struct nlattr *na;

	memset(&req, 0, sizeof(req));

	req.nlh.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	req.nlh.nlmsg_type = GENL_ID_CTRL;
	req.nlh.nlmsg_flags = NLM_F_REQUEST;
	req.nlh.nlmsg_pid = getpid();
	req.nlh.nlmsg_seq = 1;

	req.genl.cmd = CTRL_CMD_GETFAMILY;
	req.genl.version = 1;

	na = (struct nlattr *)((char *)&req + req.nlh.nlmsg_len);
	na->nla_type = CTRL_ATTR_FAMILY_NAME;

	int len = strlen(AVERY_FAMILY_NAME) + 1;
	na->nla_len = NLA_HDRLEN + len;

	strcpy((char *)na + NLA_HDRLEN, AVERY_FAMILY_NAME);

	req.nlh.nlmsg_len += NLA_ALIGN(na->nla_len);

	if (sendto(nl_sock, &req, req.nlh.nlmsg_len, 0,
		   (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
	    perror("sendto");
	    exit(1);
	}

	char buffer[8192];
	int r = recv(nl_sock, buffer, sizeof(buffer), 0);
	if (r < 0) {
	    perror("recv");
	    exit(1);
	}

	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
	struct genlmsghdr *genl = NLMSG_DATA(nlh);

	struct nlattr *attr = (struct nlattr *)(genl + 1);
	int attrlen = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

	while (attrlen > 0) {

	    if (attr->nla_type == CTRL_ATTR_FAMILY_ID)
		return *(__u16 *)((char *)attr + NLA_HDRLEN);

	    attrlen -= NLA_ALIGN(attr->nla_len);
	    attr = (struct nlattr *)((char *)attr + NLA_ALIGN(attr->nla_len));
	}

	fprintf(stderr, "family id not found\n");
	exit(1);
}

static void nl_send_response(struct pending_req *req,
			     struct avery_pci_config_op *op)
{
	char buffer[256];

	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
	struct genlmsghdr *genl;
	struct nlattr *na;

	struct sockaddr_nl addr = { .nl_family = AF_NETLINK };

	memset(buffer, 0, sizeof(buffer));

	nlh->nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
	nlh->nlmsg_type = family_id;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_seq = req->seq;

	genl = NLMSG_DATA(nlh);
	genl->cmd = AVERY_CMD_RESPONSE;
	genl->version = 1;

	na = (struct nlattr *)((char *)nlh + nlh->nlmsg_len);
	na->nla_type = AVERY_ATTR_OP;
	na->nla_len = NLA_HDRLEN + sizeof(*op);

	memcpy((char *)na + NLA_HDRLEN, op, sizeof(*op));

	nlh->nlmsg_len += NLA_ALIGN(na->nla_len);

	sendto(nl_sock, buffer, nlh->nlmsg_len, 0,
	       (struct sockaddr *)&addr, sizeof(addr));
}

/* ------------------------------------------------------------- */

static int nl_recv_request(struct pending_req *req,
			   struct avery_pci_config_op *op)
{
	char buffer[4096];

	int len = recv(nl_sock, buffer, sizeof(buffer), 0);
	if (len <= 0)
	    return -1;

	struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
	struct genlmsghdr *genl = NLMSG_DATA(nlh);

	if (genl->cmd != AVERY_CMD_REQUEST)
	    return -1;

	req->portid = nlh->nlmsg_pid;
	req->seq = nlh->nlmsg_seq;

	struct nlattr *attr = (struct nlattr *)(genl + 1);
	int attrlen = nlh->nlmsg_len - NLMSG_LENGTH(GENL_HDRLEN);

	while (attrlen > 0) {

	    if (attr->nla_type == AVERY_ATTR_OP) {
		memcpy(op, (char *)attr + NLA_HDRLEN, sizeof(*op));
		return 0;
	    }

	    attrlen -= NLA_ALIGN(attr->nla_len);
	    attr = (struct nlattr *)((char *)attr + NLA_ALIGN(attr->nla_len));
}

return -1;

}

/* ------------------------------------------------------------- */

int main(void)
{
	int sockfd;
	struct sockaddr_nl addr;

	struct pending_req req;
	struct avery_pci_config_op op;

	sockfd = connect_remote();

	nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);

	memset(&addr, 0, sizeof(addr));
	addr.nl_family = AF_NETLINK;
	addr.nl_pid = getpid();

	bind(nl_sock, (struct sockaddr *)&addr, sizeof(addr));

	family_id = nl_get_family_id();

	printf("Netlink family id = %d\n", family_id);

	nl_register_daemon();   // <-- ADD THIS

	printf("Daemon started\n");

	while (1) {

	    if (nl_recv_request(&req, &op))
		continue;

	    printf("REQ: type=%d offset=0x%x value=0x%x\n",
		   op.type, op.offset, op.value);

	    send(sockfd, &op, sizeof(op), 0);
	    recv(sockfd, &op, sizeof(op), MSG_WAITALL);

	    printf("RESP: status=%d value=0x%x\n",
		   op.status, op.value);

	    nl_send_response(&req, &op);
	}

	return 0;
}
