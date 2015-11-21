/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the protocol dispatcher.
 *
 * Version:	@(#)protocol.h	1.0.2	05/07/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 *	Changes:
 *		Alan Cox	:	Added a name field and a frag handler
 *					field for later.
 *		Alan Cox	:	Cleaned up, and sorted types.
 *		Pedro Roque	:	inet6 protocols
 */

#ifndef _PROTOCOL_H
#define _PROTOCOL_H

#include <linux/in6.h>
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
#include <linux/ipv6.h>
#endif

#define MAX_INET_PROTOS	256		/* Must be a power of 2		*/

// 该结构定义了协议族中支持的传输层协议已经传输层的报文接收例程，是网络层和传输层的桥梁
/* This is used to register protocols. */
struct net_protocol {
	int			(*handler)(struct sk_buff *skb);		// 传输层数据报文接收处理函数指针  tcp_v4_rcv() udp_rcv() igmp_rcv()
	void			(*err_handler)(struct sk_buff *skb, u32 info);	// 在ICMP收到差错报文之后，调用的上层错误处理函数 tcp_v4_err() udp_err()
	int			(*gso_send_check)(struct sk_buff *skb);
	struct sk_buff	       *(*gso_segment)(struct sk_buff *skb,
					       int features);
	int			no_policy;								// 标识在路由时是否进行策略路由
};

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
struct inet6_protocol
{
	int	(*handler)(struct sk_buff **skb);

	void	(*err_handler)(struct sk_buff *skb,
			       struct inet6_skb_parm *opt,
			       int type, int code, int offset,
			       __be32 info);

	int	(*gso_send_check)(struct sk_buff *skb);
	struct sk_buff *(*gso_segment)(struct sk_buff *skb,
				       int features);

	unsigned int	flags;	/* INET6_PROTO_xxx */
};

#define INET6_PROTO_NOPOLICY	0x1
#define INET6_PROTO_FINAL	0x2
/* This should be set for any extension header which is compatible with GSO. */
#define INET6_PROTO_GSO_EXTHDR	0x4
#endif

/* This is used to register socket interfaces for IP protocols.  */
struct inet_protosw {
	struct list_head list;	// 用于将type类型相同的inet_protosw结构组成链表

        /* These two fields form the lookup key.  */
	unsigned short	 type;	   /* This is the 2nd argument to socket(2). */ // SOCK_STREAM SOCK_DGRAM
	unsigned short	 protocol; /* This is the L4 protocol number.  */		// IPPROTO_TCP IPPROTO_UDP

	struct proto	 *prot;			// 传输层接口。TCP tcp_prot UDP udp_prot  RAW raw_prot
	const struct proto_ops *ops;	// 套接口层操作集。TCP inet_stream_ops UDP inet_dgram_ops RAW inet_sockraw_ops

	int              capability; /* Which (if any) capability do	当大于0时候，需要检查当前创建套接口进程是否有能力
				      * we need to use this socket					TCP UDP 均为-1， RAW为 CAP_NET_RAW
				      * interface?
                                      */
	char             no_check;   /* checksum on rcv/xmit/none? */	// TCP 协议一定要进行校验，值固定0，标识要校验。RAW和UDP值见 UDP_CSUM_NOXMIT
	unsigned char	 flags;      /* See INET_PROTOSW_* below.  */	// 辅助标志，用于初始化传输控制块的is_icsk成员，见下面
};
#define INET_PROTOSW_REUSE 0x01	     /* Are ports automatically reusable? */		// 标识端口是否能被重用
#define INET_PROTOSW_PERMANENT 0x02  /* Permanent protocols are unremovable. */		// 标识此协议不能被替换、卸载
#define INET_PROTOSW_ICSK      0x04  /* Is this an inet_connection_sock? */			// 标识是不是连接类型的套接口

extern struct net_protocol *inet_protocol_base;
extern struct net_protocol *inet_protos[MAX_INET_PROTOS];

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
extern struct inet6_protocol *inet6_protos[MAX_INET_PROTOS];
#endif

extern int	inet_add_protocol(struct net_protocol *prot, unsigned char num);
extern int	inet_del_protocol(struct net_protocol *prot, unsigned char num);
extern void	inet_register_protosw(struct inet_protosw *p);
extern void	inet_unregister_protosw(struct inet_protosw *p);

#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
extern int	inet6_add_protocol(struct inet6_protocol *prot, unsigned char num);
extern int	inet6_del_protocol(struct inet6_protocol *prot, unsigned char num);
extern void	inet6_register_protosw(struct inet_protosw *p);
extern void	inet6_unregister_protosw(struct inet_protosw *p);
#endif

#endif	/* _PROTOCOL_H */
