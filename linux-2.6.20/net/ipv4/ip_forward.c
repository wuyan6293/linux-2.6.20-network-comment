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
		ip_forward_options(skb);	// ����ת��IP���ݰ��е�ѡ�������¼·��ѡ���ʱ���ѡ��

	return dst_output(skb);			// ������ģ����յ��õ����������ip_output()���鲥�������ip_mc_output()
}

int ip_forward(struct sk_buff *skb)
{
	struct iphdr *iph;	/* Our header */
	struct rtable *rt;	/* Route we use */
	struct ip_options * opt	= &(IPCB(skb)->opt);

	if (!xfrm4_policy_check(NULL, XFRM_POLICY_FWD, skb))	// IPsec�������ݿ���ң����ʧ�ܣ�����
		goto drop;
	// ������ݰ��д���·�ɾ�����Ϣ�������ip_call_ra_chain(skb)��������Ϣ���ݸ�����Ȥ���û����̡��ɹ��򷵻�
	if (IPCB(skb)->opt.router_alert && ip_call_ra_chain(skb))
		return NET_RX_SUCCESS;
	// �����������ݰ������������ݰ����ܱ����ա����ݰ��е�Ŀ��MAC��ַ����Ϊ�����豸��MAC��ַ��
	if (skb->pkt_type != PACKET_HOST)	
		goto drop;
	// ����ת�������л��޸�IP�ײ���������Ҫ��ʶУ��ͱ�־λ���ú���ģ�����У���
	skb->ip_summed = CHECKSUM_NONE;
	
	/*
	 *	According to the RFC, we must first decrease the TTL field. If
	 *	that reaches zero, we must reply an ICMP control message telling
	 *	that the packet's lifetime expired.
	 */	// TTL����0�������ñ��ģ����ͳ�ʱICMP����
	if (skb->nh.iph->ttl <= 1)
                goto too_many_hops;
	// ����IPsec·��ѡ·��ת���������ʧ�ܣ���������
	if (!xfrm4_route_forward(skb))	
		goto drop;

	rt = (struct rtable*)skb->dst;
	// ������ݰ��������ϸ�·��ѡ������ݰ�����һ���������أ����ͳ�ʱICMP���ģ������ñ���
	if (opt->is_strictroute && rt->rt_dst != rt->rt_gateway)
		goto sr_failed;
	// ȷ��SKB��ָ�����ȵ�headroom�ռ䣬��SKB��headroom�ռ�С��ָ�����Ȼ��߿�¡SKBʱ���ᴴ��SKB���岢�ͷŶ�ԭ������
	/* We are about to mangle packet. Copy it! */
	if (skb_cow(skb, LL_RESERVED_SPACE(rt->u.dst.dev)+rt->u.dst.header_len))
		goto drop;
	iph = skb->nh.iph;

	/* Decrease ttl after skb cow done */
	ip_decrease_ttl(iph);			// ����·�ɣ�IP���ݰ���TTL��1

	/*
	 *	We now generate an ICMP HOST REDIRECT giving the route
	 *	we calculated.
	 */	// ��������ݱ������·�ɴ����ض��������ݰ��в�����Դ·��ѡ������ض���ICMP����
	if (rt->rt_flags&RTCF_DOREDIRECT && !opt->srr)
		ip_rt_send_redirect(skb);

	skb->priority = rt_tos2priority(iph->tos);
	// ����netfilter����֮�󣬵���ip_forward_finish()�����IP���ת��������
	return NF_HOOK(PF_INET, NF_IP_FORWARD, skb, skb->dev, rt->u.dst.dev,
		       ip_forward_finish);

sr_failed:
        /*
	 *	Strict routing permits no gatewaying
	 */		// ���Ͳ��ɴ�ICMP����
         icmp_send(skb, ICMP_DEST_UNREACH, ICMP_SR_FAILED, 0);
         goto drop;

too_many_hops:
        /* Tell the sender its packet died... */
        IP_INC_STATS_BH(IPSTATS_MIB_INHDRERRORS);
        icmp_send(skb, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL, 0);	// ���ͳ�ʱICMP����
drop:
	kfree_skb(skb);
	return NET_RX_DROP;
}
