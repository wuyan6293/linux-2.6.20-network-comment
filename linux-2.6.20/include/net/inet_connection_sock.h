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
 */	// ��װ��һ���봫�����صĲ�����������������㷢�͵Ľӿڡ�������setsockopt�ӿڵȡ�TCP��ʵ��Ϊipv4_specific
struct inet_connection_sock_af_ops {
	int	    (*queue_xmit)(struct sk_buff *skb, int ipfragok);				// �Ӵ����������㴫�ݵĽӿ�
	void	    (*send_check)(struct sock *sk, int len,						// ���㴫����ײ�У��ͺ���
				  struct sk_buff *skb);
	int	    (*rebuild_header)(struct sock *sk);								// ����˴�����ƿ黹û��·�ɻ����Ϊ������ƿ�ѡ��·�ɻ�����
	int	    (*conn_request)(struct sock *sk, struct sk_buff *skb);			// ������������ӿ�
	struct sock *(*syn_recv_sock)(struct sock *sk, struct sk_buff *skb,		// ������������ֺ󣬵��ô˽ӿ�������һ���µ��׽ӿ�
				      struct request_sock *req,
				      struct dst_entry *dst);
	int	    (*remember_stamp)(struct sock *sk);								// ������tw_recycle����£��ر��׽ӿ�ʱ����¼���ʱ�����Ϣ���Զ���Ϣ�������
	u16	    net_header_len;													// ��IPv4��ΪIP�ײ����ȣ���iphdr�ṹ�Ĵ�С
	u16	    sockaddr_len;
	int	    (*setsockopt)(struct sock *sk, int level, int optname, 			// �����ϵͳ���ýӿ�
				  char __user *optval, int optlen);
	int	    (*getsockopt)(struct sock *sk, int level, int optname, 
				  char __user *optval, int __user *optlen);
	int	    (*compat_setsockopt)(struct sock *sk,
				int level, int optname,
				char __user *optval, int optlen);
	int	    (*compat_getsockopt)(struct sock *sk,
				int level, int optname,
				char __user *optval, int __user *optlen);
	void	    (*addr2sockaddr)(struct sock *sk, struct sockaddr *);		// ��IP�׽ӿڵ�ַ�ṹ�еĵ�ַ��Ϣ���Ƶ�������ƿ���
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
	struct request_sock_queue icsk_accept_queue;	// ��TCP�������յ��ͻ��˵���������󣬻ᴴ��һ���ͻ����׽ӿڴ�ŵ�icsk_accept_queue�����У��ȴ�Ӧ�ó������accept()
	struct inet_bind_bucket	  *icsk_bind_hash;		// ָ����֮�󶨵ı��ض˿���Ϣ���ڰ󶨹����б�����
	unsigned long		  icsk_timeout;				// �����ش��ĳ�ʱʱ�䣬ͨ��Ϊjiffies+icsk_rto
 	struct timer_list	  icsk_retransmit_timer;	// ͨ��icsk_pending�������ش���ʱ���ͳ�����ʱ����
 	struct timer_list	  icsk_delack_timer;		// �ӳٷ���ACK�εĶ�ʱ��
	__u32			  icsk_rto;						// ��ʱ�ش���ʱ�䣬��ʼֵΪTCP_TIMEOUT_INIT����icsk_timeout������?
	__u32			  icsk_pmtu_cookie;				// ���һ�θ��µ�·��MTU(PMTU)
	const struct tcp_congestion_ops *icsk_ca_ops;	// ָ��ʵ��ĳ��ӵ�������㷨��ָ�롣��: TCP_CONGESTION
	const struct inet_connection_sock_af_ops *icsk_af_ops;	// TCP��һ�������ӿڼ���������IP�㷢�͵Ľӿڡ�TCP��setsockopt�ӿڵȡ���tcp_v4_init_sock()�б���ʼ��Ϊinet_connection_sock_af_ops���ͳ���ipv4_specific
	unsigned int		  (*icsk_sync_mss)(struct sock *sk, u32 pmtu);// ����PMTUͬ������MSS����ָ�룬��tcp_v4_init_sock()�б���ʼ��Ϊtcp_sync_mss()
	__u8			  icsk_ca_state;				// ӵ������״̬
	__u8			  icsk_retransmits;				// ��¼��ʱ�ش��Ĵ���
	__u8			  icsk_pending;					// ��ʶԤ���Ķ�ʱ���¼�  ��: ICSK_TIME_RETRANS��һ��ȡֵΪ ICSK_TIME_RETRANS ICSK_TIME_PROBE0
	__u8			  icsk_backoff;					// �������������ʱ������һ���趨ֵ��ָ���˱��㷨ָ�����ڴ��ͳ�ʱʱ������
	__u8			  icsk_syn_retries;				// ����TCP����ʱ����������Է���SYN��SYN+ACK�εĴ����� ��: TCP_SYNCNTѡ���tcp_synack_retriesϵͳ����
	__u8			  icsk_probes_out;				// ������ʱ���򱣻ʱ�������Է��ͳ�ȥ��δ��ȷ�ϵ�TCP����Ŀ�����յ�ACK֮������
	__u16			  icsk_ext_hdr_len;				// IP�ײ�ѡ��ֳ���
	struct {
		__u8		  pending;	 /* ACK is pending			   */				// ��ʶ��ǰ��Ҫ����ȷ�ϵĽ����̶Ⱥ�״̬  �� inet_csk_ack_state_t�ṹ
		__u8		  quick;	 /* Scheduled number of quick acks	   */		// ��ʶ�ڿ��ٷ���ȷ��ģʽ�У����Կ�ݷ���ACK�ε���������pingpongһͬ��Ϊ�ж��Ƿ��ڿ��ٷ���ȷ��ģʽ�µ����������Ҫ��ʱ����ȷ�ϣ����������ʱ����ȷ��ģʽ��
		__u8		  pingpong;	 /* The session is interactive		   */		// ��ʶ���û���ÿ���ȷ��ģʽ��ͨ��TCP_QUICKACKѡ��������á�  0: ���ٷ���  1: ��ʱȷ��
		__u8		  blocked;	 /* Delayed ACK was blocked by socket lock */	// ��ʶACK����ʱ����Ϊ�û��������˴�����ƿ��������������ʱȷ�϶�ʱ���ò�����
		__u32		  ato;		 /* Predicted tick of soft clock	   */		// ����������ʱȷ�ϵĹ�ֵ���ڽ��յ�TCP��ʱ��������ϴν��յ�ʱ������������ֵ
		unsigned long	  timeout;	 /* Currently scheduled timeout		   */	// ��ǰ����ʱȷ��ʱ�䣬��ʱ��ᷢ��ACK
		__u32		  lrcvtime;	 /* timestamp of last received data packet */	// ��ʶ���һ�ν��յ����ݰ���ʱ��
		__u16		  last_seg_size; /* Size of last incoming segment	   */	// ���һ�����յĶεĳ��ȣ���������rcv_mss
		__u16		  rcv_mss;	 /* MSS used for delayed ACK decisions	   */ 	// ��������յ��μ����MSS����Ҫ����ȷ���Ƿ�ִ����ʱȷ��
	} icsk_ack;			// ��ʱȷ�Ͽ������ݿ�
	struct {
		int		  enabled;								// ��ʶ�Ƿ�����·��MTU����

		/* Range of MTUs to search */
		int		  search_high;							// ��ʶ·��MTU���ֵ������������
		int		  search_low;

		/* Information on the current probe. */
		int		  probe_size;							// ��ǰ·��MTU̽��εĳ��ȣ�Ҳ�����ж�·��MTU̽���Ƿ���ɡ����۳ɹ�����ʧ�ܣ�·��MTU̽����ɺ󶼱���ʼ��Ϊ0
	} icsk_mtup;		// �й�·��MTU���͵Ŀ������ݿ飬��tcp_mtup_init()�б���ʼ��
	u32			  icsk_ca_priv[16];						// �洢�����й�TCPӵ�������㷨��˽�в���
#define ICSK_CA_PRIV_SIZE	(16 * sizeof(u32))
};
// isck_pending��ȡֵ
#define ICSK_TIME_RETRANS	1	/* Retransmit timer */				// �ش���ʱ��
#define ICSK_TIME_DACK		2	/* Delayed ack timer */				// ��ʱȷ�϶�ʱ��
#define ICSK_TIME_PROBE0	3	/* Zero window probe timer */		// ��ֶ�ʱ��(�㴰��̽�ⶨʱ��)
#define ICSK_TIME_KEEPOPEN	4	/* Keepalive timer */				// ���ʱ��

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
// pending��ȡֵ
enum inet_csk_ack_state_t {
	ICSK_ACK_SCHED	= 1,				// ��ACK��Ҫ���ͣ����������ͻ�����ʱ���ͣ�����Ҫ��������־��Ҳ���ܷ���ȷ�ϵ�ǰ�ᡣ�ڽ��յ��и��ɵ�TCP�κ󣬻����øñ�־
	ICSK_ACK_TIMER  = 2,				// ��ʱ����ACK��ʱ���Ѿ�����
	ICSK_ACK_PUSHED = 4,				// ֻҪ��ACK��Ҫ���ͣ�����pingpongΪ0ʱ��ACK������������
	ICSK_ACK_PUSHED2 = 8				// ֻҪ��ACK��Ҫ���ͣ��������������ͣ������Ƿ��ڿ��ٷ���ģʽ
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
