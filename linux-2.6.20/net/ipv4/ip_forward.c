/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		The IP forwarding functionality.
 *		
 * Version:	$Id: ip_forward.c,v 1.48 2000/12/13 18:31:48 davem Exp $
 *
 * Authors:	see ip.c
 *
 * Fixes:
 *		Many		:	Split from ip.c , see ip_input.c for 
 *					history.
 *		Dave Gregorich	:	NULL ip_rt_put fix for multicast 
 *					routing.
 *		Jos Vos		:	Add call_out_firewall before sending,
 *					use output device for accounting.
 *		Jos Vos		:	Call forward firewall after routing
 *					(always use output device).
 *		Mike McLagan	:	Routing by source
 */

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter_ipv4.h>
#include <net/checksum.h>
#include <linux/route.h>
#include <net/route.h>
#include <net/xfrm.h>

static inline int ip_forward_finish(struct sk_buff *skb)
{
	struct ip_options * opt	= &(IPCB(skb)->opt);

	IP_INC_STATS_BH(IPSTATS_MIB_OUTFORWDATAGRAMS);

	if (unlikely(opt->optlen))
		ip_forward_options(skb);	// 处理转发IP数据包中的选项，包括记录路由选项和时间戳选项

	return dst_output(skb);			// 输出报文，最终调用单播输出函数ip_output()或组播输出函数ip_mc_output()
}

int ip_forward(struct sk_buff *skb)
{
	struct iphdr *iph;	/* Our header */
	struct rtable *rt;	/* Route we use */
	struct ip_options * opt	= &(IPCB(skb)->opt);

	if (!xfrm4_policy_check(NULL, XFRM_POLICY_FWD, skb))	// IPsec策略数据块查找，如果失败，则丢弃
		goto drop;
	// 如果数据包中存在路由警告信息，则调用ip_call_ra_chain(skb)将警告信息传递给感兴趣的用户进程。成功则返回
	if (IPCB(skb)->opt.router_alert && ip_call_ra_chain(skb))
		return NET_RX_SUCCESS;
	// 发给接收数据包的主机的数据包才能被接收。数据包中的目的MAC地址必须为网络设备的MAC地址。
	if (skb->pkt_type != PACKET_HOST)	
		goto drop;
	// 由于转发过程中会修改IP首部，所以需要标识校验和标志位，让后续模块计算校验和
	skb->ip_summed = CHECKSUM_NONE;
	
	/*
	 *	According to the RFC, we must first decrease the TTL field. If
	 *	that reaches zero, we must reply an ICMP control message telling
	 *	that the packet's lifetime expired.
	 */	// TTL减到0，则丢弃该报文，发送超时ICMP报文
	if (skb->nh.iph->ttl <= 1)
                goto too_many_hops;
	// 进行IPsec路由选路和转发处理，如果失败，则丢弃报文
	if (!xfrm4_route_forward(skb))	
		goto drop;

	rt = (struct rtable*)skb->dst;
	// 如果数据包启用了严格路由选项，则当数据包的下一跳不是网关，则发送超时ICMP报文，丢弃该报文
	if (opt->is_strictroute && rt->rt_dst != rt->rt_gateway)
		goto sr_failed;
	// 确保SKB有指定长度的headroom空间，当SKB的headroom空间小于指定长度或者克隆SKB时，会创建SKB缓冲并释放对原包引用
	/* We are about to mangle packet. Copy it! */
	if (skb_cow(skb, LL_RESERVED_SPACE(rt->u.dst.dev)+rt->u.dst.header_len))
		goto drop;
	iph = skb->nh.iph;

	/* Decrease ttl after skb cow done */
	ip_decrease_ttl(iph);			// 经过路由，IP数据包的TTL减1

	/*
	 *	We now generate an ICMP HOST REDIRECT giving the route
	 *	we calculated.
	 */	// 如果该数据报的输出路由存在重定向，且数据包中不存在源路由选项，则发送重定向ICMP报文
	if (rt->rt_flags&RTCF_DOREDIRECT && !opt->srr)
		ip_rt_send_redirect(skb);

	skb->priority = rt_tos2priority(iph->tos);
	// 经过netfilter处理之后，调用ip_forward_finish()，完成IP层的转发操作。
	return NF_HOOK(PF_INET, NF_IP_FORWARD, skb, skb->dev, rt->u.dst.dev,
		       ip_forward_finish);

sr_failed:
        /*
	 *	Strict routing permits no gatewaying
	 */		// 发送不可达ICMP报文
         icmp_send(skb, ICMP_DEST_UNREACH, ICMP_SR_FAILED, 0);
         goto drop;

too_many_hops:
        /* Tell the sender its packet died... */
        IP_INC_STATS_BH(IPSTATS_MIB_INHDRERRORS);
        icmp_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);	// 发送超时ICMP报文
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}
