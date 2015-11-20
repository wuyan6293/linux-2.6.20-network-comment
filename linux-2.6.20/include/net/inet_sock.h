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
	struct ipv6_pinfo	*pinet6;	// IPv6���ƿ�ָ��
#endif
	/* Socket demultiplex comparisons on incoming packets. */
	__be32			daddr;			// Ŀ��IP��ַ
	__be32			rcv_saddr;		// �Ѱ󶨵ı���IP��ַ
	__be16			dport;			// Ŀ�Ķ˿�
	__u16			num;			// �����ֽ���ı��ض˿�
	__be32			saddr;			// ����IP��ַ���ڷ���ʱ��ʹ�á���rcv_saddr����������IP��ַ�����ǹ��ܲ�ͬ
	__s16			uc_ttl;			// ��������TTL,Ĭ��ֵΪ-1����ʾʹ��Ĭ�ϵ�TTLֵ�����������ʱ��TTLֵ�ȴ������ȡ����û�����ã����·�ɱ����metric�л�ȡ
	__u16			cmsg_flags;		// ���IPPROTO_IP�����ѡ�����: IP_CMSG_PKTINFO
	struct ip_options	*opt;		// ָ��IP���ݰ�ѡ��ֵ�ָ��
	__be16			sport;			// ��numת�������������ֽ����Դ�˿�
	__u16			id;				// һ������������ֵ����������IP�ײ���id��
	__u8			tos;			// ��������IP�ײ���TOS��
	__u8			mc_ttl;			// �������öಥ���ݰ���TTL
	__u8			pmtudisc;		// ��ʶ�Ƿ�����·��MTU���ֹ��ܣ�����: IP_PMTUDISC_DO    ��: IP_MTU_DISCOVER
	__u8			recverr:1,		// ��ʶ�Ƿ����������չ�Ŀɿ�������Ϣ����: IP_RECVERR
				is_icsk:1,			// ��־�Ƿ�Ϊ�������ӵĴ�����ƿ飬���Ƿ�Ϊ����inet_connection_sock�ṹ�Ĵ�����ƿ�
				freebind:1,			// ��ʶ�Ƿ�����󶨷�������ַ����: IP_FREEBIND
				hdrincl:1,			// ��ʶIP�ײ��Ƿ����û�����
				mc_loop:1;			// ��ʶ�鲥�Ƿ����·
	int			mc_index;			// �����鲥���ĵ������豸������
	__be32			mc_addr;		// �����鲥���ĵ�Դ��ַ
	struct ip_mc_socklist	*mc_list;	// �����׽ӿڼ�����鲥��ַ�б�
	struct {
		unsigned int		flags;		// ��ر�־���� IPCORK_OPT
		unsigned int		fragsize;	// UDP���ݰ���ԭʼIP���ݰ��ķ�Ƭ��С
		struct ip_options	*opt;		// �˴η������ݰ���IPѡ��
		struct rtable		*rt;		// �������ݰ�ʹ�õ����·�ɻ�����
		int			length;				// ��ǰ���͵����ݰ������ݳ��� /* Total length of all frames */	
		__be32			addr;			// ���IP���ݰ���Ŀ�ĵ�ַ
		struct flowi		fl;			// ��flowi�ṹ������Ŀ�ĵ�ַ��Ŀ�Ķ˿ڡ�Դ��ַ��Դ�˿�
	} cork;								// UDP��ԭʼIP��ÿ�η���ʱ�����һЩ��ʱ��Ϣ
};

#define IPCORK_OPT	1	/* ip-options has been held in ipcork.opt */			// ��ʶIPѡ����Ϣ�Ƿ��Ѿ���cork��opt��Ա��
#define IPCORK_ALLFRAG	2	/* always fragment (for ipv6 for now) */			// ���Ƿ�Ƭ(ֻ����IPv6)

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
