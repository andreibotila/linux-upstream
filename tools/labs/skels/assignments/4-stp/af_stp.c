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
#include <linux/hashtable.h>
#include <net/sock.h>

#include "stp.h"

/* Linked list head. */
struct list_head head;

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
	struct sockaddr_stp *sstp;
	__be16 remote_port;
	__u8 remote_mac[6];
	struct list_head list;
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

/* Interface between socket layer(kernel-side socket) and transport layer.
 * Defines callbacks when opening a STP socket in userspace
 * and using the socket API.
 */
static struct proto stp_proto = {
	.name		= STP_PROTO_NAME,
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct stp_sock),
};

static int stp_release(struct socket *sock)
{
	struct stp_sock *ssock, *tmp;

	list_for_each_entry_safe(ssock, tmp, &head, list) {
		if (sock == ssock->sk.sk_socket) {
			list_del(&ssock->list);
			kfree(ssock->sstp);
			sock_put(&ssock->sk);
			break;
		}
	}

	return 0;
}

static int stp_bind(struct socket *sock, struct sockaddr *myaddr,
	int sockaddr_len)
{
	struct sockaddr_stp *sstp;
	struct stp_sock *ssock;
	struct stp_sock *stp_sock, *tmp;
	unsigned int same_port;

	sstp = (struct sockaddr_stp *)myaddr;

	/* Allocate stp_sock structure. */
	ssock = kzalloc(sizeof(struct stp_sock), GFP_KERNEL);
	if (ssock == NULL)
		return -ENOMEM;
	memcpy(&ssock->sk, sock->sk, sizeof(struct stp_sock));

	if (sockaddr_len < sizeof(struct sockaddr_stp))
		return -EINVAL;
	if (sstp->sas_family != AF_STP)
		return -EINVAL;

	list_for_each_entry_safe(stp_sock, tmp, &head, list) {
		same_port =
			(stp_sock->sstp->sas_port == sstp->sas_port) ? 1 : 0;

		if (same_port && stp_sock->sstp->sas_ifindex == 0)
			return -ENOMEM;
		if (same_port && (sstp->sas_ifindex == 0 ||
			stp_sock->sstp->sas_ifindex == sstp->sas_ifindex))
			return -ENOMEM;
	}

	/* Allocate address field inside stp_sock structure
	 * if informations are valid.
	 */
	ssock->sstp = kzalloc(sizeof(struct sockaddr_stp), GFP_KERNEL);
	if (ssock->sstp == NULL)
		return -ENOMEM;
	memcpy(ssock->sstp, sstp, sizeof(struct sockaddr_stp));

	/* Add the socket to the linked list. */
	list_add(&ssock->list, &head);

	return 0;
}

static int stp_connect(struct socket *sock, struct sockaddr *vaddr,
	int sockaddr_len, int flags)
{

	struct stp_sock *ssock, *tmp;
	struct sockaddr_stp *sstp;

	sstp = (struct sockaddr_stp *)vaddr;

	list_for_each_entry_safe(ssock, tmp, &head, list) {
		if (sock == ssock->sk.sk_socket) {
			ssock->remote_port = ntohs(sstp->sas_port);
			memcpy(ssock->remote_mac, sstp->sas_addr, 6);
			break;
		}
	}

	return 0;
}

static int stp_sendmsg(struct socket *sock, struct msghdr *m, size_t total_len)
{
	return 0;
}

static int stp_recvmsg(struct socket *sock, struct msghdr *m, size_t total_len,
	int flags)
{
	struct sk_buff *skb;
	int csum, err, i;

	/* Receive the datagram. */
	skb = skb_recv_datagram(sock->sk, flags, flags & MSG_DONTWAIT, &err);
	if (skb == NULL) {
		pr_err("Failed to receive the datagram.");
		goto out;
	}

	/* Check the message has not been modified, checksum. */
	for (i = 0; i < skb->len; i++)
		csum = csum ^ *(skb->data + i);
	if (csum != skb->csum) {
		pr_err("Wrong checksum.");
		CsumErr++;
		err = -EINVAL;
		goto out;
	}

	/* Copy message from buffer to msghdr. Wrapper over iovec. */
	err = skb_copy_datagram_msg(skb, 0, m, skb->len);
	if (err) {
		pr_err("Failed to copy a datagram to msghdr.");
		goto out_free;
	}

	/* Send message to user space. */
	sock_recv_ts_and_drops(m, sock->sk, skb);
	RxPkts++;
	skb_free_datagram(sock->sk, skb);

	return total_len;

out_free:
	skb_free_datagram(sock->sk, skb);
out:
	return err;
}

/* Operations providing the interface between BSD socket and AF interface.
 * Basically operations between user-side and kernel-side sockets.
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

/* Protocol function handling, processing a received package
 * from the network layer. Called by netif_receive_skb().
 */
static int stp_packet_handler(struct sk_buff *skb, struct net_device *dev,
	struct packet_type *pt, struct net_device *orig_dev)
{
	struct stp_hdr *header;
	struct stp_sock *ssock, *tmp;
	int err, found;

	/* skb->data has been incremented by the lower layer so now
	 * it points to the header for the transport protocol.
	 */
	header = (struct stp_hdr *)skb->data;

	/* Package too short. sk_buff contains data and layers header.
	 * If it doesn't have a header for the layer to process it then fails.
	 */
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

	/* Check if socket listening on the specific port exists. */
	found = 0;
	list_for_each_entry_safe(ssock, tmp, &head, list) {
		if (ssock->sstp->sas_port == header->dst)
			found = 1;
	}
	if (!found) {
		pr_err("Socket listening of destination port doesn't exists.");
		NoSock++;
		err = -EINVAL;
		goto out;
	}

	/* If adding the skb to the socket receive queue fails
	 * then we know that the queue is full.
	 */
	err = sock_queue_rcv_skb(skb->sk, skb);
	if (err) {
		pr_err("Socket receive queue is full.");
		NoBuffs++;
		goto out;
	}

	return 0;

out:
	/* Decrement the users count(number of entities using the buffer). */
	kfree_skb(skb);
	return err;
}

/* Checked by netif_receive_skb() to determine which function handler
 * to execute in order to process the packet at L3.(checks skb->protocol)
 * Describes a protocol.
 */
static struct packet_type stp_packet = {
	.type		= htons(ETH_P_STP),
	.func		= stp_packet_handler,
};

int __init stp_init(void)
{
	int err;

	/* Initialize the linked list head. */
	INIT_LIST_HEAD(&head);

	/* Register the interface between socket layer and transport layer. */
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

	/* Creating entry under /proc/net/ for statistics. */
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
	sock_unregister(AF_STP);
out_sock_register:
	proto_unregister(&stp_proto);
out:
	return err;
}

void __exit stp_exit(void)
{
	struct stp_sock *ssock, *tmp;

	dev_remove_pack(&stp_packet);
	proc_remove(proc_stp);
	sock_unregister(AF_STP);
	proto_unregister(&stp_proto);

	list_for_each_entry_safe(ssock, tmp, &head, list) {
		list_del(&ssock->list);
		kfree(ssock->sstp);
		sock_put(&ssock->sk);
		kfree(ssock);
	}
	list_del(&head);
}

module_init(stp_init);
module_exit(stp_exit);

MODULE_DESCRIPTION("SO2 Transport Protocol");
MODULE_AUTHOR("Andrei Botila <andreibotila95@gmail.com>");
MODULE_LICENSE("GPL v2");
