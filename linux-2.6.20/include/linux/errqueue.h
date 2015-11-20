#ifndef _LINUX_ERRQUEUE_H
#define _LINUX_ERRQUEUE_H 1

struct sock_extended_err
{
	__u32	ee_errno;			// 出错信息的错误码
	__u8	ee_origin;			// 标识出出错信息的来源: SO_EE_ORIGIN_LOCAL
	__u8	ee_type;			// 在出错信息来自ICMP消息的情况下，标识ICMP差错消息的类型，其他来源均为0
	__u8	ee_code;			// 在出错信息来自ICMP消息的情况下，标识ICMP差错消息的编码，其他来源均为0
	__u8	ee_pad;				// 未使用，填充0
	__u32   ee_info;			// 出错信息的扩展信息，具体意义随出错信息的错误码而定。例如在收到目的不可达的差错报文时，为下一跳的MTU
	__u32   ee_data;			// 未使用，填充0
};

#define SO_EE_ORIGIN_NONE	0
#define SO_EE_ORIGIN_LOCAL	1
#define SO_EE_ORIGIN_ICMP	2
#define SO_EE_ORIGIN_ICMP6	3

#define SO_EE_OFFENDER(ee)	((struct sockaddr*)((ee)+1))

#ifdef __KERNEL__

#include <net/ip.h>
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
#include <linux/ipv6.h>
#endif

#define SKB_EXT_ERR(skb) ((struct sock_exterr_skb *) ((skb)->cb))

struct sock_exterr_skb
{
	union {
		struct inet_skb_parm	h4;
#if defined(CONFIG_IPV6) || defined (CONFIG_IPV6_MODULE)
		struct inet6_skb_parm	h6;
#endif
	} header;	// 与IP控制块兼容，可以存储IP选项信息
	struct sock_extended_err	ee;		// 记录出错信息
	u16				addr_offset;		// 导致出错的原始数据报的目的地址在负载ICMP报文的IP数据包中的偏移量
	__be16				port;			// 对于UDP是出错报文的目的端口，对于其他情况都为0
};

#endif

#endif
