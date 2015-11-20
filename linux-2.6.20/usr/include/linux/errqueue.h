#ifndef _LINUX_ERRQUEUE_H
#define _LINUX_ERRQUEUE_H 1

struct sock_extended_err
{
	__u32	ee_errno;			// ������Ϣ�Ĵ�����
	__u8	ee_origin;			// ��ʶ��������Ϣ����Դ: SO_EE_ORIGIN_LOCAL
	__u8	ee_type;			// �ڳ�����Ϣ����ICMP��Ϣ������£���ʶICMP�����Ϣ�����ͣ�������Դ��Ϊ0
	__u8	ee_code;			// �ڳ�����Ϣ����ICMP��Ϣ������£���ʶICMP�����Ϣ�ı��룬������Դ��Ϊ0
	__u8	ee_pad;				// δʹ�ã����0
	__u32   ee_info;			// ������Ϣ����չ��Ϣ�����������������Ϣ�Ĵ�����������������յ�Ŀ�Ĳ��ɴ�Ĳ����ʱ��Ϊ��һ����MTU
	__u32   ee_data;			// δʹ�ã����0
};

#define SO_EE_ORIGIN_NONE	0
#define SO_EE_ORIGIN_LOCAL	1
#define SO_EE_ORIGIN_ICMP	2
#define SO_EE_ORIGIN_ICMP6	3

#define SO_EE_OFFENDER(ee)	((struct sockaddr*)((ee)+1))


#endif
