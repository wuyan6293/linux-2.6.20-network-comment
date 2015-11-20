/*
 * NET		Generic infrastructure for INET connection oriented protocols.
 *
 *		Definitions for inet_connection_sock 
 *
 * Authors:	Many people, see the TCP sources
 *
 * 		From code originally in TCP
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _INET_CONNECTION_SOCK_H
#define _INET_CONNECTION_SOCK_H

#include <linux/compiler.h>
#include <linux/string.h>
#include <linux/timer.h>
#include <linux/poll.h>

#include <net/inet_sock.h>
#include <net/request_sock.h>

#define INET_CSK_DEBUG 1

/* Cancel timers, when they are not required. */
#undef INET_CSK_CLEAR_TIMERS

struct inet_bind_bucket;
struct inet_hashinfo;
struct tcp_congestion_ops;

/*
 * Pointers to address related TCP functions
 * (i.e. things that depend on the address family)
 */	// 封装了一组与传输层相关的操作集，包括向网络层发送的接口、传输层的setsockopt接口等。TCP的实例为ipv4_specific
struct inet_connection_sock_af_ops {
	int	    (*queue_xmit)(struct sk_buff *skb, int ipfragok);				// 从传输层向网络层传递的接口
	void	    (*send_check)(struct sock *sk, int len,						// 计算传输层首部校验和函数
				  struct sk_buff *skb);
	int	    (*rebuild_header)(struct sock *sk);								// 如果此传输控制块还没有路由缓存项，为传输控制块选择路由缓存项
	int	    (*conn_request)(struct sock *sk, struct sk_buff *skb);			// 处理连接请求接口
	struct sock *(*syn_recv_sock)(struct sock *sk, struct sk_buff *skb,		// 在完成三次握手后，调用此接口来创建一个新的套接口
				      struct request_sock *req,
				      struct dst_entry *dst);
	int	    (*remember_stamp)(struct sock *sk);								// 在启用tw_recycle情况下，关闭套接口时，记录相关时间戳信息到对端信息管理块中
	u16	    net_header_len;													// 在IPv4中为IP首部长度，即iphdr结构的大小
	u16	    sockaddr_len;
	int	    (*setsockopt)(struct sock *sk, int level, int optname, 			// 传输层系统调用接口
				  char __user *optval, int optlen);
	int	    (*getsockopt)(struct sock *sk, int level, int optname, 
				  char __user *optval, int __user *optlen);
	int	    (*compat_setsockopt)(struct sock *sk,
				int level, int optname,
				char __user *optval, int optlen);
	int	    (*compat_getsockopt)(struct sock *sk,
				int level, int optname,
				char __user *optval, int __user *optlen);
	void	    (*addr2sockaddr)(struct sock *sk, struct sockaddr *);		// 将IP套接口地址结构中的地址信息复制到传输控制块中
};

/** inet_connection_sock - INET connection oriented sock
 *
 * @icsk_accept_queue:	   FIFO of established children 
 * @icsk_bind_hash:	   Bind node
 * @icsk_timeout:	   Timeout
 * @icsk_retransmit_timer: Resend (no ack)
 * @icsk_rto:		   Retransmit timeout
 * @icsk_pmtu_cookie	   Last pmtu seen by socket
 * @icsk_ca_ops		   Pluggable congestion control hook
 * @icsk_af_ops		   Operations which are AF_INET{4,6} specific
 * @icsk_ca_state:	   Congestion control state
 * @icsk_retransmits:	   Number of unrecovered [RTO] timeouts
 * @icsk_pending:	   Scheduled timer event
 * @icsk_backoff:	   Backoff
 * @icsk_syn_retries:      Number of allowed SYN (or equivalent) retries
 * @icsk_probes_out:	   unanswered 0 window probes
 * @icsk_ext_hdr_len:	   Network protocol overhead (IP/IPv6 options)
 * @icsk_ack:		   Delayed ACK control data
 * @icsk_mtup;		   MTU probing control data
 */
struct inet_connection_sock {
	/* inet_sock has to be the first member! */
	struct inet_sock	  icsk_inet;
	struct request_sock_queue icsk_accept_queue;	// 当TCP传输层接收到客户端的连接请求后，会创建一个客户端套接口存放到icsk_accept_queue容器中，等待应用程序调用accept()
	struct inet_bind_bucket	  *icsk_bind_hash;		// 指向与之绑定的本地端口信息，在绑定过程中被设置
	unsigned long		  icsk_timeout;				// 进行重传的超时时间，通常为jiffies+icsk_rto
 	struct timer_list	  icsk_retransmit_timer;	// 通过icsk_pending来区分重传定时器和持续定时器。
 	struct timer_list	  icsk_delack_timer;		// 延迟发送ACK段的定时器
	__u32			  icsk_rto;						// 超时重传的时间，初始值为TCP_TIMEOUT_INIT。与icsk_timeout的区别?
	__u32			  icsk_pmtu_cookie;				// 最后一次更新的路径MTU(PMTU)
	const struct tcp_congestion_ops *icsk_ca_ops;	// 指向实现某个拥塞控制算法的指针。见: TCP_CONGESTION
	const struct inet_connection_sock_af_ops *icsk_af_ops;	// TCP的一个操作接口集，包括向IP层发送的接口、TCP层setsockopt接口等。在tcp_v4_init_sock()中被初始化为inet_connection_sock_af_ops类型常量ipv4_specific
	unsigned int		  (*icsk_sync_mss)(struct sock *sk, u32 pmtu);// 根据PMTU同步本地MSS函数指针，在tcp_v4_init_sock()中被初始化为tcp_sync_mss()
	__u8			  icsk_ca_state;				// 拥塞控制状态
	__u8			  icsk_retransmits;				// 记录超时重传的次数
	__u8			  icsk_pending;					// 标识预定的定时器事件  见: ICSK_TIME_RETRANS。一般取值为 ICSK_TIME_RETRANS ICSK_TIME_PROBE0
	__u8			  icsk_backoff;					// 用来计算持续定时器的下一个设定值的指数退避算法指数，在传送超时时会增加
	__u8			  icsk_syn_retries;				// 建立TCP连接时最多允许重试发送SYN或SYN+ACK段的次数， 见: TCP_SYNCNT选项和tcp_synack_retries系统参数
	__u8			  icsk_probes_out;				// 持续定时器或保活定时器周期性发送出去但未被确认的TCP段数目，在收到ACK之后清理
	__u16			  icsk_ext_hdr_len;				// IP首部选项部分长度
	struct {
		__u8		  pending;	 /* ACK is pending			   */				// 标识当前需要发送确认的紧急程度和状态  见 inet_csk_ack_state_t结构
		__u8		  quick;	 /* Scheduled number of quick acks	   */		// 标识在快速发送确认模式中，可以快递发送ACK段的数量，与pingpong一同作为判断是否在快速发送确认模式下的条件，如果要延时发送确认，则必须在延时发送确认模式下
		__u8		  pingpong;	 /* The session is interactive		   */		// 标识启用或禁用快速确认模式。通过TCP_QUICKACK选项可以设置。  0: 快速发送  1: 延时确认
		__u8		  blocked;	 /* Delayed ACK was blocked by socket lock */	// 标识ACK被延时，因为用户进程拿了传输控制块的锁，而导致延时确认定时器拿不到锁
		__u32		  ato;		 /* Predicted tick of soft clock	   */		// 用来计算延时确认的估值，在接收到TCP段时会根据与上次接收的时间间隔来调整该值
		unsigned long	  timeout;	 /* Currently scheduled timeout		   */	// 当前的延时确认时间，超时后会发送ACK
		__u32		  lrcvtime;	 /* timestamp of last received data packet */	// 标识最近一次接收到数据包的时间
		__u16		  last_seg_size; /* Size of last incoming segment	   */	// 最后一个接收的段的长度，用来计算rcv_mss
		__u16		  rcv_mss;	 /* MSS used for delayed ACK decisions	   */ 	// 由最近接收到段计算出MSS，主要用来确定是否执行延时确认
	} icsk_ack;			// 延时确认控制数据块
	struct {
		int		  enabled;								// 标识是否启用路径MTU发现

		/* Range of MTUs to search */
		int		  search_high;							// 标识路径MTU发现的区间的上下限
		int		  search_low;

		/* Information on the current probe. */
		int		  probe_size;							// 当前路径MTU探测段的长度，也用于判断路径MTU探测是否完成。无论成功还是失败，路径MTU探测完成后都被初始化为0
	} icsk_mtup;		// 有关路径MTU发送的控制数据块，在tcp_mtup_init()中被初始化
	u32			  icsk_ca_priv[16];						// 存储各种有关TCP拥塞控制算法的私有参数
#define ICSK_CA_PRIV_SIZE	(16 * sizeof(u32))
};
// isck_pending的取值
#define ICSK_TIME_RETRANS	1	/* Retransmit timer */				// 重传定时器
#define ICSK_TIME_DACK		2	/* Delayed ack timer */				// 延时确认定时器
#define ICSK_TIME_PROBE0	3	/* Zero window probe timer */		// 坚持定时器(零窗口探测定时器)
#define ICSK_TIME_KEEPOPEN	4	/* Keepalive timer */				// 保活定时器

static inline struct inet_connection_sock *inet_csk(const struct sock *sk)
{
	return (struct inet_connection_sock *)sk;
}

static inline void *inet_csk_ca(const struct sock *sk)
{
	return (void *)inet_csk(sk)->icsk_ca_priv;
}

extern struct sock *inet_csk_clone(struct sock *sk,
				   const struct request_sock *req,
				   const gfp_t priority);
// pending的取值
enum inet_csk_ack_state_t {
	ICSK_ACK_SCHED	= 1,				// 有ACK需要发送，是立即发送还是延时发送，还需要看其他标志，也是能否发送确认的前提。在接收到有负荷的TCP段后，会设置该标志
	ICSK_ACK_TIMER  = 2,				// 延时发送ACK定时器已经启动
	ICSK_ACK_PUSHED = 4,				// 只要有ACK需要发送，并且pingpong为0时，ACK可以立即发送
	ICSK_ACK_PUSHED2 = 8				// 只要有ACK需要发送，都可以立即发送，无论是否处于快速发送模式
};

extern void inet_csk_init_xmit_timers(struct sock *sk,
				      void (*retransmit_handler)(unsigned long),
				      void (*delack_handler)(unsigned long),
				      void (*keepalive_handler)(unsigned long));
extern void inet_csk_clear_xmit_timers(struct sock *sk);

static inline void inet_csk_schedule_ack(struct sock *sk)
{
	inet_csk(sk)->icsk_ack.pending |= ICSK_ACK_SCHED;
}

static inline int inet_csk_ack_scheduled(const struct sock *sk)
{
	return inet_csk(sk)->icsk_ack.pending & ICSK_ACK_SCHED;
}

static inline void inet_csk_delack_init(struct sock *sk)
{
	memset(&inet_csk(sk)->icsk_ack, 0, sizeof(inet_csk(sk)->icsk_ack));
}

extern void inet_csk_delete_keepalive_timer(struct sock *sk);
extern void inet_csk_reset_keepalive_timer(struct sock *sk, unsigned long timeout);

#ifdef INET_CSK_DEBUG
extern const char inet_csk_timer_bug_msg[];
#endif

static inline void inet_csk_clear_xmit_timer(struct sock *sk, const int what)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	
	if (what == ICSK_TIME_RETRANS || what == ICSK_TIME_PROBE0) {
		icsk->icsk_pending = 0;
#ifdef INET_CSK_CLEAR_TIMERS
		sk_stop_timer(sk, &icsk->icsk_retransmit_timer);
#endif
	} else if (what == ICSK_TIME_DACK) {
		icsk->icsk_ack.blocked = icsk->icsk_ack.pending = 0;
#ifdef INET_CSK_CLEAR_TIMERS
		sk_stop_timer(sk, &icsk->icsk_delack_timer);
#endif
	}
#ifdef INET_CSK_DEBUG
	else {
		pr_debug("%s", inet_csk_timer_bug_msg);
	}
#endif
}

/*
 *	Reset the retransmission timer
 */
static inline void inet_csk_reset_xmit_timer(struct sock *sk, const int what,
					     unsigned long when,
					     const unsigned long max_when)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (when > max_when) {
#ifdef INET_CSK_DEBUG
		pr_debug("reset_xmit_timer: sk=%p %d when=0x%lx, caller=%p\n",
			 sk, what, when, current_text_addr());
#endif
		when = max_when;
	}

	if (what == ICSK_TIME_RETRANS || what == ICSK_TIME_PROBE0) {
		icsk->icsk_pending = what;
		icsk->icsk_timeout = jiffies + when;
		sk_reset_timer(sk, &icsk->icsk_retransmit_timer, icsk->icsk_timeout);
	} else if (what == ICSK_TIME_DACK) {
		icsk->icsk_ack.pending |= ICSK_ACK_TIMER;
		icsk->icsk_ack.timeout = jiffies + when;
		sk_reset_timer(sk, &icsk->icsk_delack_timer, icsk->icsk_ack.timeout);
	}
#ifdef INET_CSK_DEBUG
	else {
		pr_debug("%s", inet_csk_timer_bug_msg);
	}
#endif
}

extern struct sock *inet_csk_accept(struct sock *sk, int flags, int *err);

extern struct request_sock *inet_csk_search_req(const struct sock *sk,
						struct request_sock ***prevp,
						const __be16 rport,
						const __be32 raddr,
						const __be32 laddr);
extern int inet_csk_bind_conflict(const struct sock *sk,
				  const struct inet_bind_bucket *tb);
extern int inet_csk_get_port(struct inet_hashinfo *hashinfo,
			     struct sock *sk, unsigned short snum,
			     int (*bind_conflict)(const struct sock *sk,
						  const struct inet_bind_bucket *tb));

extern struct dst_entry* inet_csk_route_req(struct sock *sk,
					    const struct request_sock *req);

static inline void inet_csk_reqsk_queue_add(struct sock *sk,
					    struct request_sock *req,
					    struct sock *child)
{
	reqsk_queue_add(&inet_csk(sk)->icsk_accept_queue, req, sk, child);
}

extern void inet_csk_reqsk_queue_hash_add(struct sock *sk,
					  struct request_sock *req,
					  unsigned long timeout);

static inline void inet_csk_reqsk_queue_removed(struct sock *sk,
						struct request_sock *req)
{
	if (reqsk_queue_removed(&inet_csk(sk)->icsk_accept_queue, req) == 0)
		inet_csk_delete_keepalive_timer(sk);
}

static inline void inet_csk_reqsk_queue_added(struct sock *sk,
					      const unsigned long timeout)
{
	if (reqsk_queue_added(&inet_csk(sk)->icsk_accept_queue) == 0)
		inet_csk_reset_keepalive_timer(sk, timeout);
}

static inline int inet_csk_reqsk_queue_len(const struct sock *sk)
{
	return reqsk_queue_len(&inet_csk(sk)->icsk_accept_queue);
}

static inline int inet_csk_reqsk_queue_young(const struct sock *sk)
{
	return reqsk_queue_len_young(&inet_csk(sk)->icsk_accept_queue);
}

static inline int inet_csk_reqsk_queue_is_full(const struct sock *sk)
{
	return reqsk_queue_is_full(&inet_csk(sk)->icsk_accept_queue);
}

static inline void inet_csk_reqsk_queue_unlink(struct sock *sk,
					       struct request_sock *req,
					       struct request_sock **prev)
{
	reqsk_queue_unlink(&inet_csk(sk)->icsk_accept_queue, req, prev);
}

static inline void inet_csk_reqsk_queue_drop(struct sock *sk,
					     struct request_sock *req,
					     struct request_sock **prev)
{
	inet_csk_reqsk_queue_unlink(sk, req, prev);
	inet_csk_reqsk_queue_removed(sk, req);
	reqsk_free(req);
}

extern void inet_csk_reqsk_queue_prune(struct sock *parent,
				       const unsigned long interval,
				       const unsigned long timeout,
				       const unsigned long max_rto);

extern void inet_csk_destroy_sock(struct sock *sk);

/*
 * LISTEN is a special case for poll..
 */
static inline unsigned int inet_csk_listen_poll(const struct sock *sk)
{
	return !reqsk_queue_empty(&inet_csk(sk)->icsk_accept_queue) ?
			(POLLIN | POLLRDNORM) : 0;
}

extern int  inet_csk_listen_start(struct sock *sk, const int nr_table_entries);
extern void inet_csk_listen_stop(struct sock *sk);

extern void inet_csk_addr2sockaddr(struct sock *sk, struct sockaddr *uaddr);

extern int inet_csk_ctl_sock_create(struct socket **sock,
				    unsigned short family,
				    unsigned short type,
				    unsigned char protocol);

extern int inet_csk_compat_getsockopt(struct sock *sk, int level, int optname,
				      char __user *optval, int __user *optlen);
extern int inet_csk_compat_setsockopt(struct sock *sk, int level, int optname,
				      char __user *optval, int optlen);
#endif /* _INET_CONNECTION_SOCK_H */
