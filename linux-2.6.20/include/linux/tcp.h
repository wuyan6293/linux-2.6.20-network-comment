/*
 * INET		An implementation of the TCP/IP protocol suite for the LINUX
 *		operating system.  INET is implemented using the  BSD Socket
 *		interface as the means of communication with the user level.
 *
 *		Definitions for the TCP protocol.
 *
 * Version:	@(#)tcp.h	1.0.2	04/28/93
 *
 * Author:	Fred N. van Kempen, <waltje@uWalt.NL.Mugnet.ORG>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */
#ifndef _LINUX_TCP_H
#define _LINUX_TCP_H

#include <linux/types.h>
#include <asm/byteorder.h>
#include <linux/socket.h>

struct tcphdr {
	__be16	source;
	__be16	dest;
	__be32	seq;
	__be32	ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif	
	__be16	window;
	__sum16	check;
	__be16	urg_ptr;
};

/*
 *	The union cast uses a gcc extension to avoid aliasing problems
 *  (union is compatible to any of its members)
 *  This means this part of the code is -fstrict-aliasing safe now.
 */
union tcp_word_hdr { 
	struct tcphdr hdr;
	__be32 		  words[5];
}; 

#define tcp_flag_word(tp) ( ((union tcp_word_hdr *)(tp))->words [3]) 

enum { 
	TCP_FLAG_CWR = __constant_htonl(0x00800000), 
	TCP_FLAG_ECE = __constant_htonl(0x00400000), 
	TCP_FLAG_URG = __constant_htonl(0x00200000), 
	TCP_FLAG_ACK = __constant_htonl(0x00100000), 
	TCP_FLAG_PSH = __constant_htonl(0x00080000), 
	TCP_FLAG_RST = __constant_htonl(0x00040000), 
	TCP_FLAG_SYN = __constant_htonl(0x00020000), 
	TCP_FLAG_FIN = __constant_htonl(0x00010000),
	TCP_RESERVED_BITS = __constant_htonl(0x0F000000),
	TCP_DATA_OFFSET = __constant_htonl(0xF0000000)
}; 

/* TCP socket options */
#define TCP_NODELAY		1	/* Turn off Nagle's algorithm. */
#define TCP_MAXSEG		2	/* Limit MSS */
#define TCP_CORK		3	/* Never send partially complete segments */
#define TCP_KEEPIDLE		4	/* Start keeplives after this period */
#define TCP_KEEPINTVL		5	/* Interval between keepalives */
#define TCP_KEEPCNT		6	/* Number of keepalives before death */
#define TCP_SYNCNT		7	/* Number of SYN retransmits */
#define TCP_LINGER2		8	/* Life time of orphaned FIN-WAIT-2 state */
#define TCP_DEFER_ACCEPT	9	/* Wake up listener only when data arrive */
#define TCP_WINDOW_CLAMP	10	/* Bound advertised window */
#define TCP_INFO		11	/* Information about this connection. */
#define TCP_QUICKACK		12	/* Block/reenable quick acks */
#define TCP_CONGESTION		13	/* Congestion control algorithm */
#define TCP_MD5SIG		14	/* TCP MD5 Signature (RFC2385) */

#define TCPI_OPT_TIMESTAMPS	1
#define TCPI_OPT_SACK		2
#define TCPI_OPT_WSCALE		4
#define TCPI_OPT_ECN		8

enum tcp_ca_state
{
	TCP_CA_Open = 0,
#define TCPF_CA_Open	(1<<TCP_CA_Open)
	TCP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
	TCP_CA_CWR = 2,
#define TCPF_CA_CWR	(1<<TCP_CA_CWR)
	TCP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)
	TCP_CA_Loss = 4
#define TCPF_CA_Loss	(1<<TCP_CA_Loss)
};

struct tcp_info
{
	__u8	tcpi_state;
	__u8	tcpi_ca_state;
	__u8	tcpi_retransmits;
	__u8	tcpi_probes;
	__u8	tcpi_backoff;
	__u8	tcpi_options;
	__u8	tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

	__u32	tcpi_rto;
	__u32	tcpi_ato;
	__u32	tcpi_snd_mss;
	__u32	tcpi_rcv_mss;

	__u32	tcpi_unacked;
	__u32	tcpi_sacked;
	__u32	tcpi_lost;
	__u32	tcpi_retrans;
	__u32	tcpi_fackets;

	/* Times. */
	__u32	tcpi_last_data_sent;
	__u32	tcpi_last_ack_sent;     /* Not remembered, sorry. */
	__u32	tcpi_last_data_recv;
	__u32	tcpi_last_ack_recv;

	/* Metrics. */
	__u32	tcpi_pmtu;
	__u32	tcpi_rcv_ssthresh;
	__u32	tcpi_rtt;
	__u32	tcpi_rttvar;
	__u32	tcpi_snd_ssthresh;
	__u32	tcpi_snd_cwnd;
	__u32	tcpi_advmss;
	__u32	tcpi_reordering;

	__u32	tcpi_rcv_rtt;
	__u32	tcpi_rcv_space;

	__u32	tcpi_total_retrans;
};

/* for TCP_MD5SIG socket option */
#define TCP_MD5SIG_MAXKEYLEN	80

struct tcp_md5sig {
	struct __kernel_sockaddr_storage tcpm_addr;	/* address associated */
	__u16	__tcpm_pad1;				/* zero */
	__u16	tcpm_keylen;				/* key length */
	__u32	__tcpm_pad2;				/* zero */
	__u8	tcpm_key[TCP_MD5SIG_MAXKEYLEN];		/* key (binary) */
};

#ifdef __KERNEL__

#include <linux/skbuff.h>
#include <linux/dmaengine.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <net/inet_timewait_sock.h>

/* This defines a selective acknowledgement block. */
struct tcp_sack_block_wire {
	__be32	start_seq;
	__be32	end_seq;
};

struct tcp_sack_block {
	u32	start_seq;
	u32	end_seq;
};

struct tcp_options_received {
/*	PAWS/RTTM data	*/
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */		// ��¼�ӽ��յ��Ķ���ȡ��ʱ������õ�ts_recent��ʱ�䣬���ڼ��ts_recent����Ч��
	u32	ts_recent;	/* Time stamp to echo next		*/						// ��һ�������͵�TCP���е�ʱ�������ֵ
	u32	rcv_tsval;	/* Time stamp value             	*/					// �������һ�ν��յ��Զ˵�TCP�ε�ʱ���ѡ���е�ʱ���
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/					// �������һ�ν��յ��Զ˵�TCP�ε�ʱ���ѡ���е�ʱ�������Ӧ��
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/			// ��ʶ���һ�ν��յ���TCP���Ƿ����TCPʱ���ѡ�1Ϊ�У�0Ϊû��
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/				// ��ʶTCP�����Ƿ�����ʱ���ѡ��
		dsack : 1,	/* D-SACK is scheduled			*/						// ��ʶ�´η��͵Ķ���SACKѡ���Ƿ����D-SACK
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/				// ��ʶ���շ��Ƿ�֧�ִ����������ӣ�ֻ�ܳ�����SYN����
		sack_ok : 4,	/* SACK seen on SYN packet		*/					// ��ʶ���շ��Ƿ�֧��SACK 0: ��֧��  ��0: ֧��
		snd_wscale : 4,	/* Window scaling received from sender	*/			// ���ʹ����������ӣ���Ҫ��TCP�ײ��л������ڴ�С����snd_wscaleλ�󣬲��������Ļ������ڴ�С
		rcv_wscale : 4;	/* Window scaling to send to receiver	*/			// ���մ�����������
/*	SACKs data	*/
	u8	eff_sacks;	/* Size of SACK array to send with next packet */		// ��һ�������͵Ķ���SACKѡ���SACK�����С�����Ϊ0�������Ϊû��SACK
	u8	num_sacks;	/* Number of SACK blocks		*/						// ��һ�������͵Ķ���SACKѡ���SACK������ͬʱ��������eff_sacks
	u16	user_mss;  	/* mss requested by user in ioctl */					// Ϊ�û����õ�MSS���ޣ��뽨������ʱSYN���е�MSS������֮�����Сֵ��Ϊ�����ӵ�MSS���ޣ��洢��mss_clamp�С�
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */		// �����ӵĶԶ�MSS����
};

struct tcp_request_sock {
	struct inet_request_sock 	req;
#ifdef CONFIG_TCP_MD5SIG
	/* Only used by TCP MD5 Signature so far. */
	struct tcp_request_sock_ops	*af_specific;
#endif
	u32			 	rcv_isn;
	u32			 	snt_isn;
};

static inline struct tcp_request_sock *tcp_rsk(const struct request_sock *req)
{
	return (struct tcp_request_sock *)req;
}

struct tcp_sock {
	/* inet_connection_sock has to be the first member of tcp_sock */
	struct inet_connection_sock	inet_conn;
	u16	tcp_header_len;	/* Bytes of tcp header to send		*/			// TCP�ײ����ȣ�����TCPѡ��
	u16	xmit_size_goal;	/* Goal for segmenting output packets	*/		 
	// xmit_size_goal: ��¼���׽ӿڷ��͵������豸�εĳ��ȣ��ڲ�֧��TSO������£�ֵΪMSS���������֧��TSO�������¼���
/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */	// �ײ�Ԥ���־�����ڷ��ͺͽ���SYN�����´��ڻ�����ǡ����ʱ�����øñ�־���ñ�־��ʱ����Լ����кŵ�����һ�����ж�ָ�����·����������·��������֮һ
	__be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */	// �ȴ����յ���һ��TCP�ε���ţ�ÿ���յ�һ��TCP��֮�󶼻���¸�ֵ
 	u32	rcv_nxt;	/* What we want to receive next 	*/
 	u32	snd_nxt;	/* Next sequence we send		*/		// �ȴ����͵���һ��TCP�ε����

 	u32	snd_una;	/* First byte we want an ack for	*/	// ������Ķ��У�����һ��δȷ�϶ε����
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */	// ������͵�С�������һ���ֽ���ţ��ڳɹ����Ͷκ��������С��MSS�������¸��ֶΣ���Ҫ�����ж��Ƿ������Nagle�㷨
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */			// ���һ���յ�ACK�ε�ʱ�䣬����TCP����
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */	// ���һ�η������ݰ���ʱ�䣬��Ҫ����ӵ�����ڵ�����
	// ����ṹ���������Ƹ������ݵ��û����̵Ŀ��ƿ飬���������û��ռ仺�漰���ȣ�perqueue���м�ռ���ڴ��
	/* Data for direct copy to user */
	struct {
		struct sk_buff_head	prequeue;	// ���δ����tcp_low_latency��TCP�ν����Ȼ��浽�˶��У�֪������������ȡʱ�������ӿڵ����ն����д���
		struct task_struct	*task;		// ��δ����tcp_low_latency����£���ǰ���ڶ�ȡTCP���Ľ��̣����ΪNULL���ʾ��ʱû�н��̶�����ж�ȡ
		struct iovec		*iov;		// ��δ����tcp_low_latency����£�����������ݵ��û��ռ��ַ���ڽ��մ���TCP��ʱֱ�Ӹ��Ƶ��û��ռ�
		int			memory;				// prequeue���е�ǰ���ĵ��ڴ�
		int			len;				// �û������е�ǰ����ʹ�õĻ����С����recv��ϵͳ���õ�len������ʼ��
#ifdef CONFIG_NET_DMA
		/* members for async copy */
		struct dma_chan		*dma_chan;
		int			wakeup;
		struct dma_pinned_list	*pinned_list;
		dma_cookie_t		dma_cookie;
#endif
	} ucopy;

	u32	snd_wl1;	/* Sequence for window update		*/				// ��¼���·��ʹ��ڵ��Ǹ�ACK�ε���ţ������ж��Ƿ���Ҫ���´��ڡ���������յ���ACK�ε���Ŵ���snd_wl1����˵����Ҫ���´��ڣ������������
	u32	snd_wnd;	/* The window we expect to receive	*/				// ���շ��ṩ�Ľ��մ��ڴ�С�������ͷ����ʹ��ڴ�С
	u32	max_window;	/* Maximal window ever seen from peer	*/			// ���շ�ͨ����������մ���ֵ
	u32	mss_cache;	/* Cached effective mss, not including SACKS */		// ���ͷ���ǰ��ЧMSS

	u32	window_clamp;	/* Maximal window to advertise		*/			// �����������ֵ���������ڴ�С�ڱ仯������ʼ�ղ��ܳ�����ֵ��
	u32	rcv_ssthresh;	/* Current window clamp			*/				// ��ǰ���մ��ڵ���ֵ��

	u32	frto_highmark;	/* snd_nxt when RTO occurred */					// ���ش���ʱ����ʱ��������F-RTO����£�������������͵���һ��TCP�ε����
	u8	reordering;	/* Packet reordering metric.		*/				// �ڲ�֧��SACKʱ��Ϊ�������ӽ��յ��ظ�ȷ�϶�������ٻظ��׶ε��ظ�ȷ����ֵ
	u8	frto_counter;	/* Number of new acks after RTO */				// �ڴ��䳬ʱ�󣬼�¼������F-RTO�㷨ʱ���յ�ACK�ε���Ŀ��
	u8	nonagle;	/* Disable Nagle algorithm?             */			// ��ʶ�Ƿ�����Nagle�㷨    ȡֵ��: TCP_NAGLE_OFF
	u8	keepalive_probes; /* num of allowed keep alive probes	*/		// ����̽����������ֵΪ127����TCP_KEEPCNT

/* RTT measurement */
	u32	srtt;		/* smoothed round trip time << 3	*/				// ƽ����RTT��Ϊ���⸡�����㣬�ǽ���Ŵ�8����洢��
	u32	mdev;		/* medium deviation			*/						// RTTƽ��ƫ���RTT��RTT��ֵƫ�����ֵ��Ȩƽ�����õ���ֵԽ��˵��RTT����Խ����
	u32	mdev_max;	/* maximal mdev for the last rtt period	*/			// ����ÿ�η��ʹ����ڵĶα�ȫ��ȷ�Ϲ����У�RTTƽ��ƫ�����ֵ
	u32	rttvar;		/* smoothed mdev_max			*/					// ƽ����RTTƽ��ƫ���mdev����õ�����������RTO
	u32	rtt_seq;	/* sequence number to update rttvar	*/				// ��¼SND.UNA�������ڼ���RTOʱ�Ƚ�SND.UNA�Ƿ��Ѿ��������ˣ���������£�����Ҫͬʱ����rttvar

	u32	packets_out;	/* Packets which are "in flight"	*/			// �ӷ��Ͷ��з�����δ�õ�ȷ��TCP�ε���Ŀ(SND.NXT-SND.UNA)
	u32	left_out;	/* Packets which leaved network	*/					// ���뿪��������������δȷ�ϵ�TCP�����������������: һ��ͨ��SACKȷ�ϵĶΣ������Ѷ�ʧ�ĶΣ���left_out=sacked_out+lost_out
	u32	retrans_out;	/* Retransmitted packets out		*/			// �ش���δ�õ�ȷ�ϵ�TCP����Ŀ
/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
	struct tcp_options_received rx_opt;									// �洢���յ���TCPѡ��

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
 	u32	snd_ssthresh;	/* Slow start size threshold		*/			// ӵ������ʱ����������ֵ
 	u32	snd_cwnd;	/* Sending congestion window		*/				// ��ǰӵ�����ڴ�С
 	u16	snd_cwnd_cnt;	/* Linear increase counter		*/				// �Դ��ϴε���ӵ�����ڵ�ĿǰΪֹ���յ�����ACK����
	u16	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */	// �������ӵ������ֵ����ʼ��Ϊ65535��֮���ڽ���SYN��ACK��ʱ�����������ȷ���Ƿ��·���������ȡ��Ϣ���¸��ֶ�
	u32	snd_cwnd_used;	// ��Ӧ�ó�������ʱ����¼��ǰ�ӷ��Ͷ��з�����δ�õ�ȷ�ϵĶ����������ڼ���ӵ������ʱ����ӵ�����ڣ�����ӵ������ʧЧ
	u32	snd_cwnd_stamp;	// ��¼���һ�μ���ӵ�����ڵ�ʱ�䡣��ӵ���ڼ䣬���յ�ACK������ӵ�����ڵļ���

	struct sk_buff_head	out_of_order_queue; /* Out of order segments go here */	// ���򻺴���У������ݴ���յ��������TCP��

 	u32	rcv_wnd;	/* Current receiver window		*/					// ��ǰ���մ��ڴ�С
	u32	rcv_wup;	/* rcv_nxt on last window update sent	*/			// ��ʶ������յ�δȷ�ϵĶε���ţ�����ǰ���մ��ڵ���ˡ�
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */		// �Ѽ��뵽���Ͷ����е����һ���ֽ����
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */	// ͨ������±�ʾ�Ѿ��������ͳ�ȥ�����һ���ֽ���ţ�����ʱҲ���ܱ�ʾ�������ͳ�ȥ�����һ���ֽ����
	u32	copied_seq;	/* Head of yet unread data		*/					// ��δ���ں˿ռ临�Ƶ��û��ռ�Ķ���ǰ��һ���ֽڵ����

/*	SACKs data	*/
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */			// �洢D-SACK��Ϣ
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/	// �洢SACK��Ϣ

	struct tcp_sack_block recv_sack_cache[4];							// �洢���յ���SACK��Ϣ

	/* from STCP, retrans queue hinting */
	struct sk_buff* lost_skb_hint;				// һ����ӵ��״̬û�г�����û�н���Loss״̬ʱ�����ش������У�������һ�α�ǼǷ���δ��ʧ�����һ���Σ���ҪΪ�˼��ٶ��ش����еı�ǲ���

	struct sk_buff *scoreboard_skb_hint;		// һ����ӵ��״̬û�г�����û�н���Loss״̬ʱ�����ش������У���¼��һ�θ��¼Ƿ��Ƶ����һ��SKB
	struct sk_buff *retransmit_skb_hint;		// ���ڼ�¼��ǰ�ش���λ��
	struct sk_buff *forward_skb_hint;			// ��֧��SACK��FACKʱ�����ش�����SACK���еĿ�϶�еĶ�ʱ�����ڼ�¼������������������δ���ش���λ��
	struct sk_buff *fastpath_skb_hint;			// ��¼��һ�δ���SACKѡ��������Ŷε�SDK

	int     fastpath_cnt_hint;					// ��¼��һ�μ���õ���fackets_out
	int     lost_cnt_hint;
	int     retransmit_cnt_hint;				// ���ڼ�¼��ǰ�ش���λ��
	int     forward_cnt_hint;

	u16	advmss;		/* Advertised MSS			*/						// �����ܽ��ܵ�MSS���ޣ��ڽ�������ʱ����ͨ��Զ�
	u16	prior_ssthresh; /* ssthresh saved at recovery start	*/			// ������FRTO�㷨������£�·��MTU̽��ɹ�������ӵ������Disorder��Recovery��Loss״̬ʱ�����ssthreshֵ
	u32	lost_out;	/* Lost packets			*/							// ���ͺ�ʧ�ڴ�������ж�������ĿǰTCPЭ�黹û������"�ζ�ʧ֪ͨ"����
	u32	sacked_out;	/* SACK'd packets			*/						// ����SACKʱ��ͨ��SACK��TCPѡ���ʶ�ѽ��յ��ε�����
	u32	fackets_out;	/* FACK'd packets			*/					// ��¼SND.UNA��SACKѡ����Ŀǰ���շ��յ��Ķ��������Ŷ�֮��Ķ���
	u32	high_seq;	/* snd_nxt at onset of congestion	*/				// ��¼����ӵ��ʱ��SND.NXT����ʶ�ش����е�β��

	u32	retrans_stamp;	/* Timestamp of the last retransmit,			// ��������ʱ����¼��һ��SYN�εķ���ʱ�䣬�������ACK����Ƿ����
				 * also used in SYN-SENT to remember stamp of			// �����ݴ���׶Σ���������ʱ�ش�ʱ����¼�ϴ��ش��׶ε�һ���ش��η���ʱ�䣬�����ж��Ƿ���Խ���ӵ������
				 * the first SYN. */
	u32	undo_marker;	/* tracking retrans started here. */			// ��ʹ��F-RTO�㷨���з��ͳ�ʱ���������Recovery�����ش��������Loss��ʼ����������¼��ʱSND.UNA������ش���ʼ�㡣
	int	undo_retrans;	/* number of undoable retransmissions. */		// �ڻָ�ӵ������֮ǰ�ɽ��г������ش�������
	u32	urg_seq;	/* Seq of received urgent pointer */				// �������ݵ���ţ������ڶε���źͽ���ָ����Ӷ��õ�
	u16	urg_data;	/* Saved octet of OOB data and control flags */		// ��8λ���ڴ�Ž��յ��Ľ������ݣ���8λ���ڱ�ʶ����������ص�״̬��ȡֵ: TCP_URG_NOTYET
	u8	urg_mode;	/* In urgent mode		*/							// ��ʶ���ڽ���ģʽ�����߽��շ�"��������"�Ѿ���������ͨ��������
	u8	ecn_flags;	/* ECN status bits.			*/						// ��ʾӵ��֪ͨ״̬λ��ȡֵ: TCP_ECN_OK
	u32	snd_up;		/* Urgent pointer		*/							// ��������ָ�룬���������ݵ���ţ���������TCP�ײ��еĽ���ָ��

	u32	total_retrans;	/* Total retransmits for entire connection */	// �������������ش�����
	u32	bytes_acked;	/* Appropriate Byte Counting - RFC3465 */		// ����tcp_abc֮����ӵ���رܽ׶Σ�������ȷ�ϵ��ֽ���

	unsigned int		keepalive_time;	  /* time before keep alive takes place */		// TCP���ͱ���̽��ǰ��TCP���ӵĿ���ʱ�䣬�����ʱ��������ʱ����ֵ��
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */	// ���ͱ���̽���ʱ����
	int			linger2;												// ��ʶTCPǨ�Ƶ��ر�CLOSED״̬֮ǰ������FIN_WAIT_2״̬��ʱ��

	unsigned long last_synq_overflow; 		// ������tcp_syncookies������£���������ʱ��¼����SYN�ε�ʱ�䣬������⽨�������Ƿ�ʱ

	u32	tso_deferred;						// ��ʶ����TSO�ֶεĶ��Ƿ���Ҫ��ʱ���ͣ�����ʹ��ʱ���ͣ�Ҳ���ܳ�������ʱ�ӵδ�

/* Receiver side RTT estimation */
	struct {
		u32	rtt;							// ���շ������RTT�����㷽������յ��Ķ����Ƿ���ʱ���ѡ�����ͬ
		u32	seq;							// �ڽ��յ��Ķ�û��ʱ���������£����½��շ�RTTʱ�Ľ��մ����Ҷ���ţ�ÿ���һ�����մ��ڵĽ��ո���һ�ν��շ�RTT
		u32	time;							// �ڽ��յ��Ķ�û��ʱ���������£���¼ÿ�θ��½��շ�RTT��ʱ�䣬��������
	} rcv_rtt_est;							// �洢���շ���RTT����ֵ������ʵ��ͨ�����ڽ��մ����������������ƵĹ���

/* Receiver queue space */
	struct {
		int	space;							// ���ڵ������ջ���Ĵ�С
		u32	seq;							// �Ѹ��Ƶ��û��ռ��TCP�����
		u32	time;							// ��¼���һ�ν��е�����ʱ��
	} rcvq_space;							// ��������TCP���ջ���ռ�ͽ��մ��ڴ�С��Ҳ����ʵ��ͨ�����ڽ��մ����������������ƹ���

/* TCP-specific MTU probe information. */
	struct {
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;							// �洢�ѷ���MTU���ֶε���ʼ��źͽ�����ţ��뷢��MTU���ֶε�SKB��tcp_skb_cb�ṹ��seq��end_seq�ֶ����Ӧ�������ж�·��MTU�����Ƿ�ɹ�

#ifdef CONFIG_TCP_MD5SIG
/* TCP AF-Specific parts; only used by MD5 Signature support so far */
	struct tcp_sock_af_ops	*af_specific;

/* TCP MD5 Signagure Option information */
	struct tcp_md5sig_info	*md5sig_info;
#endif
};

static inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
	return (struct tcp_sock *)sk;
}

struct tcp_timewait_sock {
	struct inet_timewait_sock tw_sk;
	u32			  tw_rcv_nxt;
	u32			  tw_snd_nxt;
	u32			  tw_rcv_wnd;
	u32			  tw_ts_recent;
	long			  tw_ts_recent_stamp;
#ifdef CONFIG_TCP_MD5SIG
	u16			  tw_md5_keylen;
	u8			  tw_md5_key[TCP_MD5SIG_MAXKEYLEN];
#endif
};

static inline struct tcp_timewait_sock *tcp_twsk(const struct sock *sk)
{
	return (struct tcp_timewait_sock *)sk;
}

#endif

#endif	/* _LINUX_TCP_H */
