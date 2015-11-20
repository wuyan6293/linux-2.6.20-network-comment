/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for inet_sock
 *
 * Authors:	Many, reorganised here by
 * 		Arnaldo Carvalho de Melo <acme@mandriva.com>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _INET_SOCK_H
#define _INET_SOCK_H


#include <linux/string.h>
#include <linux/types.h>

#include <net/flow.h>
#include <net/sock.h>
#include <net/request_sock.h>

/** struct ip_options - IP Options
 *
 * @faddr - Saved first hop address
 * @is_data - Options in __data, rather than skb
 * @is_strictroute - Strict source route
 * @srr_is_hit - Packet destination addr was our one
 * @is_changed - IP checksum more not valid
 * @rr_needaddr - Need to record addr of outgoing dev
 * @ts_needtime - Need to record timestamp
 * @ts_needaddr - Need to record addr of outgoing dev
 */
struct ip_options {
	__be32		faddr;
	unsigned char	optlen;
	unsigned char	srr;
	unsigned char	rr;
	unsigned char	ts;
	unsigned char	is_data:1,
			is_strictroute:1,
			srr_is_hit:1,
			is_changed:1,
			rr_needaddr:1,
			ts_needtime:1,
			ts_needaddr:1;
	unsigned char	router_alert;
	unsigned char	cipso;
	unsigned char	__pad2;
	unsigned char	__data[0];
};

#define optlength(opt) (sizeof(struct ip_options) + opt->optlen)

struct inet_request_sock {
	struct request_sock	req;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	u16			inet6_rsk_offset;
	/* 2 bytes hole, try to pack */
#endif
	__be32			loc_addr;
	__be32			rmt_addr;
	__be16			rmt_port;
	u16			snd_wscale : 4, 
				rcv_wscale : 4, 
				tstamp_ok  : 1,
				sack_ok	   : 1,
				wscale_ok  : 1,
				ecn_ok	   : 1,
				acked	   : 1;
	struct ip_options	*opt;
};

static inline struct inet_request_sock *inet_rsk(const struct request_sock *sk)
{
	return (struct inet_request_sock *)sk;
}

struct ip_mc_socklist;
struct ipv6_pinfo;
struct rtable;

/** struct inet_sock - representation of INET sockets
 *
 * @sk - ancestor class
 * @pinet6 - pointer to IPv6 control block
 * @daddr - Foreign IPv4 addr
 * @rcv_saddr - Bound local IPv4 addr
 * @dport - Destination port
 * @num - Local port
 * @saddr - Sending source
 * @uc_ttl - Unicast TTL
 * @sport - Source port
 * @id - ID counter for DF pkts
 * @tos - TOS
 * @mc_ttl - Multicasting TTL
 * @is_icsk - is this an inet_connection_sock?
 * @mc_index - Multicast device index
 * @mc_list - Group array
 * @cork - info to build ip hdr on each ip frag while socket is corked
 */
struct inet_sock {
	/* sk and pinet6 has to be the first two members of inet_sock */
	struct sock		sk;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	struct ipv6_pinfo	*pinet6;	// IPv6控制块指针
#endif
	/* Socket demultiplex comparisons on incoming packets. */
	__be32			daddr;			// 目的IP地址
	__be32			rcv_saddr;		// 已绑定的本地IP地址
	__be16			dport;			// 目的端口
	__u16			num;			// 主机字节序的本地端口
	__be32			saddr;			// 本地IP地址，在发送时候使用。和rcv_saddr都描述本地IP地址，但是功能不同
	__s16			uc_ttl;			// 单播报文TTL,默认值为-1，表示使用默认的TTL值。在输出报文时，TTL值先从这里获取，若没有设置，则从路由表项的metric中获取
	__u16			cmsg_flags;		// 存放IPPROTO_IP级别的选项，例如: IP_CMSG_PKTINFO
	struct ip_options	*opt;		// 指向IP数据包选项部分的指针
	__be16			sport;			// 由num转换过来的网络字节序的源端口
	__u16			id;				// 一个单调递增的值，用来赋给IP首部的id域
	__u8			tos;			// 用于设置IP首部的TOS域
	__u8			mc_ttl;			// 用于设置多播数据包的TTL
	__u8			pmtudisc;		// 标识是否启用路径MTU发现功能，例如: IP_PMTUDISC_DO    见: IP_MTU_DISCOVER
	__u8			recverr:1,		// 标识是否允许接收扩展的可靠错误信息，见: IP_RECVERR
				is_icsk:1,			// 标志是否为基于连接的传输控制块，即是否为基于inet_connection_sock结构的传输控制块
				freebind:1,			// 标识是否允许绑定非主机地址，见: IP_FREEBIND
				hdrincl:1,			// 标识IP首部是否由用户构建
				mc_loop:1;			// 标识组播是否发向回路
	int			mc_index;			// 发送组播报文的网络设备索引号
	__be32			mc_addr;		// 发送组播报文的源地址
	struct ip_mc_socklist	*mc_list;	// 所在套接口加入的组播地址列表
	struct {
		unsigned int		flags;		// 相关标志，见 IPCORK_OPT
		unsigned int		fragsize;	// UDP数据包或原始IP数据包的分片大小
		struct ip_options	*opt;		// 此次发送数据包的IP选项
		struct rtable		*rt;		// 发送数据包使用的输出路由缓存项
		int			length;				// 当前发送的数据包的数据长度 /* Total length of all frames */	
		__be32			addr;			// 输出IP数据包的目的地址
		struct flowi		fl;			// 用flowi结构来缓存目的地址、目的端口、源地址和源端口
	} cork;								// UDP或原始IP在每次发送时缓存的一些临时信息
};

#define IPCORK_OPT	1	/* ip-options has been held in ipcork.opt */			// 标识IP选项信息是否已经在cork的opt成员中
#define IPCORK_ALLFRAG	2	/* always fragment (for ipv6 for now) */			// 总是分片(只用于IPv6)

static inline struct inet_sock *inet_sk(const struct sock *sk)
{
	return (struct inet_sock *)sk;
}

static inline void __inet_sk_copy_descendant(struct sock *sk_to,
					     const struct sock *sk_from,
					     const int ancestor_size)
{
	memcpy(inet_sk(sk_to) + 1, inet_sk(sk_from) + 1,
	       sk_from->sk_prot->obj_size - ancestor_size);
}
#if !(defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE))
static inline void inet_sk_copy_descendant(struct sock *sk_to,
					   const struct sock *sk_from)
{
	__inet_sk_copy_descendant(sk_to, sk_from, sizeof(struct inet_sock));
}
#endif

extern int inet_sk_rebuild_header(struct sock *sk);

static inline unsigned int inet_ehashfn(const __be32 laddr, const __u16 lport,
					const __be32 faddr, const __be16 fport)
{
	unsigned int h = ((__force __u32)laddr ^ lport) ^ ((__force __u32)faddr ^ (__force __u32)fport);
	h ^= h >> 16;
	h ^= h >> 8;
	return h;
}

static inline int inet_sk_ehashfn(const struct sock *sk)
{
	const struct inet_sock *inet = inet_sk(sk);
	const __be32 laddr = inet->rcv_saddr;
	const __u16 lport = inet->num;
	const __be32 faddr = inet->daddr;
	const __be16 fport = inet->dport;

	return inet_ehashfn(laddr, lport, faddr, fport);
}

#endif	/* _INET_SOCK_H */
