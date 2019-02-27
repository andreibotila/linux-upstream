/*
 * stp.c - Transport protocol
 *
 * Author : Andrei Botila <andreibotila95@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/sock.h>

#include "stp.h"

/* /proc/net/stp_stats entry */
struct proc_dir_entry *proc_stp;

static unsigned long RxPkts;
static unsigned long HdrErr;
static unsigned long CsumErr;
static unsigned long NoSock;
static unsigned long NoBuffs;
static unsigned long TxPkts;

struct stp_sock {
	struct sock sk;
};

/* Statistics formatting. */
static int stp_proc_show(struct seq_file *m, void *v)
{
	seq_puts(m, "RxPkts HdrErr CsumErr NoSock NoBuffs TxPkts");
	seq_printf(m, "%lu %lu %lu %lu %lu %lu", RxPkts, HdrErr, CsumErr,
			NoSock, NoBuffs, TxPkts);

	return 0;
}

static int stp_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, stp_proc_show, NULL);
}

/* Operations on the /proc/net/ file */
static const struct file_operations stp_proc_fops = {
	.owner		= THIS_MODULE,
	.open		= stp_proc_open,
	.read		= seq_read,
	.release	= single_release,
};

/* Interface between socket layer and transport layer. */
static struct proto stp_proto = {
	.name		= STP_PROTO_NAME,
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct stp_sock),
};

static int stp_release(struct socket *sock)
{
	return 0;
}

static int stp_bind(struct socket *sock, struct sockaddr *myaddr,
	int sockaddr_len)
{
	return 0;
}

static int stp_connect(struct socket *sock, struct sockaddr *vaddr,
	int sockaddr_len, int flags)
{
	return 0;
}

static int stp_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
	return 0;
}

static int stp_recvmsg(struct socket *sock, struct msghdr *m, size_t total_len,
	int flags)
{
	return 0;
}

/* Operations which represent the interface between
 * BSD socket and AF interface.
 */
static const struct proto_ops stp_ops = {
	.family		= PF_STP,
	.owner		= THIS_MODULE,
	.release	= stp_release,
	.bind		= stp_bind,
	.connect	= stp_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= sock_no_getname,
	.poll		= datagram_poll,
	.ioctl		= sock_no_ioctl,
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.setsockopt	= sock_no_setsockopt,
	.getsockopt	= sock_no_getsockopt,
	.sendmsg	= stp_sendmsg,
	.recvmsg	= stp_recvmsg,
	.mmap		= sock_no_mmap,
	.sendpage	= sock_no_sendpage,
};

/* Callback for creating a INET socket and attaching it to the BSD socket. */
static int create_stp_socket(struct net *net, struct socket *sock,
	int protocol, int kern)
{
	struct sock *sk;
	int err;

	/* Protocol supports only datagrams. */
	if (sock->type != SOCK_DGRAM) {
		pr_err("Wrong socket type.");
		err = -ESOCKTNOSUPPORT;
		goto out;
	}

	/* Protocol STP is not a standard IP protocol. */
	if (protocol != 0) {
		pr_err("Wrong protocol.");
		err = -ESOCKTNOSUPPORT;
		goto out;
	}

	/* stp_proto means the protocol asociated with this new socket */
	sk = sk_alloc(net, PF_STP, GFP_KERNEL, &stp_proto, kern);
	if (!sk) {
		pr_err("Failed to allocate a INET socket.");
		err = -ENOMEM;
		goto out;
	}

	sock_init_data(sock, sk);
	sk->sk_protocol = protocol;
	sock->ops = &stp_ops;
	return 0;

out:
	return err;
}

/* Socket creation for this type of family.
 * This family will be added to net_families table for the
 * sock_create() function to find it when it is called with family AF_STP
 * and execute create_stp_socket function
 */
static const struct net_proto_family stp_family = {
	.family		= AF_STP,
	.create		= create_stp_socket,
	.owner		= THIS_MODULE,
};

/* Function handling a received package from the network layer. */
static int stp_packet_handler(struct sk_buff *skb, struct net_device *dev,
	struct packet_type *pt, struct net_device *orig_dev)
{
	struct stp_hdr *header;
	int err;

	header = (struct stp_hdr *)skb->data;

	/* Package too short. At least the header should have. */
	if (skb->len < sizeof(struct stp_hdr)) {
		pr_err("Invalid header size.");
		HdrErr++;
		err = -EINVAL;
		goto out;
	}

	/* Invalid destination or source port. */
	if (header->dst == 0 || header->src == 0) {
		pr_err("Invalid destination/source port.");
		HdrErr++;
		err = -EINVAL;
		goto out;
	}

	return 0;

out:
	return err;
}

static struct packet_type stp_packet = {
	.type		= htons(ETH_P_STP),
	.func		= stp_packet_handler,
};

int __init stp_init(void)
{
	int err;

	err = proto_register(&stp_proto, 0);
	if (err < 0) {
		pr_err("Failed to register protocol");
		goto out;
	}

	/* Register the protocol family in net_family table. */
	err = sock_register(&stp_family);
	if (err < 0) {
		pr_err("Failed to register the stp_family");
		goto out_sock_register;
	}

	/* Handler for packages received from network layer. */
	dev_add_pack(&stp_packet);

	proc_stp = proc_create(STP_PROC_NET_FILENAME, 0000,
			init_net.proc_net, &stp_proc_fops);
	if (!proc_stp) {
		pr_err("Can't create an entry under /proc/net/");
		err = -ENOMEM;
		goto out_proc_create;
	}

	return 0;

out_proc_create:
	dev_remove_pack(&stp_packet);
out_sock_register:
	proto_unregister(&stp_proto);
out:
	return err;
}

void __exit stp_exit(void)
{
	proc_remove(proc_stp);
	dev_remove_pack(&stp_packet);
	sock_unregister(AF_STP);
	proto_unregister(&stp_proto);
}

module_init(stp_init);
module_exit(stp_exit);

MODULE_DESCRIPTION("SO2 Transport Protocol");
MODULE_AUTHOR("Andrei Botila <andreibotila95@gmail.com>");
MODULE_LICENSE("GPL v2");
