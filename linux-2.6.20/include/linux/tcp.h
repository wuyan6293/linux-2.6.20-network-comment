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
	long	ts_recent_stamp;/* Time we stored ts_recent (for aging) */		// 记录从接收到的段中取出时间戳设置到ts_recent的时间，用于检测ts_recent的有效性
	u32	ts_recent;	/* Time stamp to echo next		*/						// 下一个待发送的TCP段中的时间戳回显值
	u32	rcv_tsval;	/* Time stamp value             	*/					// 保存最近一次接收到对端的TCP段的时间戳选项中的时间戳
	u32	rcv_tsecr;	/* Time stamp echo reply        	*/					// 保存最近一次接收到对端的TCP段的时间戳选项中的时间戳回显应答
	u16 	saw_tstamp : 1,	/* Saw TIMESTAMP on last packet		*/			// 标识最近一次接收到的TCP段是否存在TCP时间戳选项，1为有，0为没有
		tstamp_ok : 1,	/* TIMESTAMP seen on SYN packet		*/				// 标识TCP连接是否启用时间戳选项
		dsack : 1,	/* D-SACK is scheduled			*/						// 标识下次发送的段中SACK选项是否存在D-SACK
		wscale_ok : 1,	/* Wscale seen on SYN packet		*/				// 标识接收方是否支持窗口扩大因子，只能出现在SYN段中
		sack_ok : 4,	/* SACK seen on SYN packet		*/					// 标识接收方是否支持SACK 0: 不支持  非0: 支持
		snd_wscale : 4,	/* Window scaling received from sender	*/			// 发送窗口扩大因子，即要把TCP首部中滑动窗口大小左移snd_wscale位后，才是真正的滑动窗口大小
		rcv_wscale : 4;	/* Window scaling to send to receiver	*/			// 接收窗口扩大因子
/*	SACKs data	*/
	u8	eff_sacks;	/* Size of SACK array to send with next packet */		// 下一个待发送的段中SACK选项的SACK数组大小，如果为0则可以认为没有SACK
	u8	num_sacks;	/* Number of SACK blocks		*/						// 下一个待发送的段中SACK选项的SACK块数，同时用来计算eff_sacks
	u16	user_mss;  	/* mss requested by user in ioctl */					// 为用户设置的MSS上限，与建立连接时SYN段中的MSS，两者之间的最小值作为该连接的MSS上限，存储在mss_clamp中。
	u16	mss_clamp;	/* Maximal mss, negotiated at connection setup */		// 该连接的对端MSS上限
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
	u16	tcp_header_len;	/* Bytes of tcp header to send		*/			// TCP首部长度，包括TCP选项
	u16	xmit_size_goal;	/* Goal for segmenting output packets	*/		 
	// xmit_size_goal: 记录该套接口发送到网络设备段的长度，在不支持TSO的情况下，值为MSS。如果网卡支持TSO，则重新计算
/*
 *	Header prediction flags
 *	0x5?10 << 16 + snd_wnd in net byte order
 */	// 首部预测标志，会在发送和接收SYN、更新窗口或其他恰当的时候，设置该标志，该标志和时间戳以及序列号等因素一样是判断指向快速路径还是慢速路径的条件之一
	__be32	pred_flags;

/*
 *	RFC793 variables by their proper names. This means you can
 *	read the code and the spec side by side (and laugh ...)
 *	See RFC793 and RFC1122. The RFC writes these in capitals.
 */	// 等待接收的下一个TCP段的序号，每次收到一个TCP段之后都会更新该值
 	u32	rcv_nxt;	/* What we want to receive next 	*/
 	u32	snd_nxt;	/* Next sequence we send		*/		// 等待发送的下一个TCP段的序号

 	u32	snd_una;	/* First byte we want an ack for	*/	// 在输出的段中，最早一个未确认段的序号
 	u32	snd_sml;	/* Last byte of the most recently transmitted small packet */	// 最近发送的小包的最后一个字节序号，在成功发送段后，如果报文小于MSS，即更新该字段，主要用来判断是否启用錘agle算法
	u32	rcv_tstamp;	/* timestamp of last received ACK (for keepalives) */			// 最近一次收到ACK段的时间，用于TCP保活
	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */	// 最近一次发送数据包的时间，主要用于拥塞窗口的设置
	// 下面结构，用来控制复制数据到用户进程的控制块，包括描述用户空间缓存及长度，perqueue队列及占用内存等
	/* Data for direct copy to user */
	struct {
		struct sk_buff_head	prequeue;	// 如果未启用tcp_low_latency，TCP段将首先缓存到此队列，知道进程主动读取时才真正接口到接收队列中处理
		struct task_struct	*task;		// 在未启用tcp_low_latency情况下，当前正在读取TCP流的进程，如果为NULL则表示暂时没有进程对其进行读取
		struct iovec		*iov;		// 在未启用tcp_low_latency情况下，用来存放数据的用户空间地址，在接收处理TCP段时直接复制到用户空间
		int			memory;				// prequeue队列当前消耗的内存
		int			len;				// 用户缓存中当前可以使用的缓存大小，由recv等系统调用的len参数初始化
#ifdef CONFIG_NET_DMA
		/* members for async copy */
		struct dma_chan		*dma_chan;
		int			wakeup;
		struct dma_pinned_list	*pinned_list;
		dma_cookie_t		dma_cookie;
#endif
	} ucopy;

	u32	snd_wl1;	/* Sequence for window update		*/				// 记录更新发送窗口的那个ACK段的序号，用来判断是否需要更新窗口。如果后续收到的ACK段的序号大于snd_wl1，则说明需要更新窗口，否则无需更新
	u32	snd_wnd;	/* The window we expect to receive	*/				// 接收方提供的接收窗口大小，即发送方发送窗口大小
	u32	max_window;	/* Maximal window ever seen from peer	*/			// 接收方通告过的最大接收窗口值
	u32	mss_cache;	/* Cached effective mss, not including SACKS */		// 发送方当前有效MSS

	u32	window_clamp;	/* Maximal window to advertise		*/			// 滑动窗口最大值，滑动窗口大小在变化过程中始终不能超出该值。
	u32	rcv_ssthresh;	/* Current window clamp			*/				// 当前接收窗口的阈值。

	u32	frto_highmark;	/* snd_nxt when RTO occurred */					// 当重传超时发生时，在启用F-RTO情况下，用来保存待发送的下一个TCP段的序号
	u8	reordering;	/* Packet reordering metric.		*/				// 在不支持SACK时，为由于连接接收到重复确认而进入快速回复阶段的重复确认阈值
	u8	frto_counter;	/* Number of new acks after RTO */				// 在传输超时后，记录在启用F-RTO算法时接收到ACK段的数目。
	u8	nonagle;	/* Disable Nagle algorithm?             */			// 标识是否允许Nagle算法    取值见: TCP_NAGLE_OFF
	u8	keepalive_probes; /* num of allowed keep alive probes	*/		// 保活探测次数，最大值为127，见TCP_KEEPCNT

/* RTT measurement */
	u32	srtt;		/* smoothed round trip time << 3	*/				// 平滑的RTT，为避免浮点运算，是将其放大8倍后存储的
	u32	mdev;		/* medium deviation			*/						// RTT平均偏差，由RTT与RTT均值偏差绝对值加权平均而得到，值越大说明RTT抖动越厉害
	u32	mdev_max;	/* maximal mdev for the last rtt period	*/			// 跟踪每次发送窗口内的段被全部确认过程中，RTT平均偏差最大值
	u32	rttvar;		/* smoothed mdev_max			*/					// 平滑的RTT平均偏差，有mdev计算得到，用来计算RTO
	u32	rtt_seq;	/* sequence number to update rttvar	*/				// 记录SND.UNA。用来在计算RTO时比较SND.UNA是否已经被更新了，如果被更新，则需要同时更新rttvar

	u32	packets_out;	/* Packets which are "in flight"	*/			// 从发送队列发出而未得到确认TCP段的数目(SND.NXT-SND.UNA)
	u32	left_out;	/* Packets which leaved network	*/					// 已离开主机在网络中且未确认的TCP段数，包含两种情况: 一是通过SACK确认的段，二是已丢失的段，即left_out=sacked_out+lost_out
	u32	retrans_out;	/* Retransmitted packets out		*/			// 重传还未得到确认的TCP段数目
/*
 *      Options received (usually on last packet, some only on SYN packets).
 */
	struct tcp_options_received rx_opt;									// 存储接收到的TCP选项

/*
 *	Slow start and congestion control (see also Nagle, and Karn & Partridge)
 */
 	u32	snd_ssthresh;	/* Slow start size threshold		*/			// 拥塞控制时慢启动的阈值
 	u32	snd_cwnd;	/* Sending congestion window		*/				// 当前拥塞窗口大小
 	u16	snd_cwnd_cnt;	/* Linear increase counter		*/				// 自从上次调整拥塞窗口到目前为止接收到的总ACK段数
	u16	snd_cwnd_clamp; /* Do not allow snd_cwnd to grow above this */	// 允许最大拥塞窗口值。初始化为65535，之后在接收SYN和ACK段时，会根据条件确定是否从路由配置项读取信息更新该字段
	u32	snd_cwnd_used;	// 当应用程序限制时，记录当前从发送队列发出而未得到确认的段数，用于在检验拥塞窗口时调节拥塞窗口，避免拥塞窗口失效
	u32	snd_cwnd_stamp;	// 记录最近一次检验拥塞窗口的时间。在拥塞期间，接收到ACK后会进行拥塞窗口的检验

	struct sk_buff_head	out_of_order_queue; /* Out of order segments go here */	// 乱序缓存队列，用来暂存接收到的乱序的TCP段

 	u32	rcv_wnd;	/* Current receiver window		*/					// 当前接收窗口大小
	u32	rcv_wup;	/* rcv_nxt on last window update sent	*/			// 标识最早接收但未确认的段的序号，即当前接收窗口的左端。
	u32	write_seq;	/* Tail(+1) of data held in tcp send buffer */		// 已加入到发送队列中的最后一个字节序号
	u32	pushed_seq;	/* Last pushed seq, required to talk to windows */	// 通常情况下表示已经真正发送出去的最后一个字节序号，但有时也可能表示期望发送出去的最后一个字节序号
	u32	copied_seq;	/* Head of yet unread data		*/					// 尚未从内核空间复制到用户空间的段最前面一个字节的序号

/*	SACKs data	*/
	struct tcp_sack_block duplicate_sack[1]; /* D-SACK block */			// 存储D-SACK信息
	struct tcp_sack_block selective_acks[4]; /* The SACKS themselves*/	// 存储SACK信息

	struct tcp_sack_block recv_sack_cache[4];							// 存储接收到的SACK信息

	/* from STCP, retrans queue hinting */
	struct sk_buff* lost_skb_hint;				// 一般在拥塞状态没有撤销或没有进入Loss状态时，在重传队列中，缓存上一次标记记分牌未丢失的最后一个段，主要为了加速对重传队列的标记操作

	struct sk_buff *scoreboard_skb_hint;		// 一般在拥塞状态没有撤销或没有进入Loss状态时，在重传队列中，记录上一次更新记分牌的最后一个SKB
	struct sk_buff *retransmit_skb_hint;		// 用于记录当前重传的位置
	struct sk_buff *forward_skb_hint;			// 当支持SACK或FACK时，在重传处于SACK块中的空隙中的段时，用于记录由于满足其他条件而未能重传的位置
	struct sk_buff *fastpath_skb_hint;			// 记录上一次处理SACK选项的最高序号段的SDK

	int     fastpath_cnt_hint;					// 记录上一次计算得到的fackets_out
	int     lost_cnt_hint;
	int     retransmit_cnt_hint;				// 用于记录当前重传的位置
	int     forward_cnt_hint;

	u16	advmss;		/* Advertised MSS			*/						// 本端能接受的MSS上限，在建立连接时用来通告对端
	u16	prior_ssthresh; /* ssthresh saved at recovery start	*/			// 在启用FRTO算法的情况下，路径MTU探测成功，进入拥塞控制Disorder、Recovery、Loss状态时保存的ssthresh值
	u32	lost_out;	/* Lost packets			*/							// 发送后丢失在传输过程中段数量。目前TCP协议还没有类似"段丢失通知"机制
	u32	sacked_out;	/* SACK'd packets			*/						// 启用SACK时，通过SACK的TCP选项标识已接收到段的数量
	u32	fackets_out;	/* FACK'd packets			*/					// 记录SND.UNA与SACK选项中目前接收方收到的段中最高序号段之间的段数
	u32	high_seq;	/* snd_nxt at onset of congestion	*/				// 记录发生拥塞时的SND.NXT，标识重传队列的尾部

	u32	retrans_stamp;	/* Timestamp of the last retransmit,			// 主动连接时，记录第一个SYN段的发送时间，用来检测ACK序号是否回绕
				 * also used in SYN-SENT to remember stamp of			// 在数据传输阶段，当发生超时重传时，记录上次重传阶段第一个重传段发送时间，用来判断是否可以进行拥塞撤销
				 * the first SYN. */
	u32	undo_marker;	/* tracking retrans started here. */			// 在使用F-RTO算法进行发送超时处理，或进入Recovery进行重传，或进入Loss开始慢启动，记录当时SND.UNA，标记重传起始点。
	int	undo_retrans;	/* number of undoable retransmissions. */		// 在恢复拥塞控制之前可进行撤销的重传段数。
	u32	urg_seq;	/* Seq of received urgent pointer */				// 紧急数据的序号，由所在段的序号和紧急指针相加而得到
	u16	urg_data;	/* Saved octet of OOB data and control flags */		// 低8位用于存放接收到的紧急数据，高8位用于标识紧急数据相关的状态。取值: TCP_URG_NOTYET
	u8	urg_mode;	/* In urgent mode		*/							// 标识处于紧急模式，告诉接收方"紧急数据"已经放置在普通数据流中
	u8	ecn_flags;	/* ECN status bits.			*/						// 显示拥塞通知状态位，取值: TCP_ECN_OK
	u32	snd_up;		/* Urgent pointer		*/							// 紧急数据指针，即带外数据的序号，用来计算TCP首部中的紧急指针

	u32	total_retrans;	/* Total retransmits for entire connection */	// 整个连接中总重传次数
	u32	bytes_acked;	/* Appropriate Byte Counting - RFC3465 */		// 启用tcp_abc之后，在拥塞回避阶段，保存已确认的字节数

	unsigned int		keepalive_time;	  /* time before keep alive takes place */		// TCP发送保活探测前，TCP连接的空闲时间，即保活定时器启动的时间阈值。
	unsigned int		keepalive_intvl;  /* time interval between keep alive probes */	// 发送保活探测的时间间隔
	int			linger2;												// 标识TCP迁移到关闭CLOSED状态之前保持在FIN_WAIT_2状态的时间

	unsigned long last_synq_overflow; 		// 在启用tcp_syncookies的情况下，简历连接时记录接收SYN段的时间，用来检测建立连接是否超时

	u32	tso_deferred;						// 标识经过TSO分段的段是否需要延时发送，但即使延时发送，也不能超过两个时钟滴答

/* Receiver side RTT estimation */
	struct {
		u32	rtt;							// 接收方估算的RTT，计算方法因接收到的段中是否有时间戳选项而不同
		u32	seq;							// 在接收到的段没有时间戳的情况下，更新接收方RTT时的接收窗口右端序号，每完成一个接收窗口的接收更新一次接收方RTT
		u32	time;							// 在接收到的段没有时间戳的情况下，记录每次更新接收方RTT的时间，用来计算
	} rcv_rtt_est;							// 存储接收方的RTT估算值，用于实现通过调节接收窗口来进行流量控制的功能

/* Receiver queue space */
	struct {
		int	space;							// 用于调整接收缓存的大小
		u32	seq;							// 已复制到用户空间的TCP段序号
		u32	time;							// 记录最近一次进行调整的时间
	} rcvq_space;							// 用来调整TCP接收缓冲空间和接收窗口大小，也用于实现通过调节接收窗口来进行流量控制功能

/* TCP-specific MTU probe information. */
	struct {
		u32		  probe_seq_start;
		u32		  probe_seq_end;
	} mtu_probe;							// 存储已发送MTU发现段的起始序号和结束序号，与发送MTU发现段的SKB中tcp_skb_cb结构的seq和end_seq字段相对应，用来判读路径MTU发现是否成功

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
