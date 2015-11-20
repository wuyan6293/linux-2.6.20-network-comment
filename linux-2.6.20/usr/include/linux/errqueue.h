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


#endif
