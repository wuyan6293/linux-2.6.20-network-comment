/*
 *		INETPEER - A storage for permanent information about peers
 *
 *  Version:	$Id: inetpeer.h,v 1.2 2002/01/12 07:54:56 davem Exp $
 *
 *  Authors:	Andrey V. Savochkin <saw@msu.ru>
 */

#ifndef _NET_INETPEER_H
#define _NET_INETPEER_H

#include <linux/types.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <asm/atomic.h>
// �Զ���Ϣ�飬��֯��AVL��. peer_root��Ϊ������v4daddrΪkeyֵ
struct inet_peer
{
	/* group together avl_left,avl_right,v4daddr to speedup lookups */
	struct inet_peer	*avl_left, *avl_right;				// avl_left��avl_right��avl_rightΪAVL������ɲ���
	__be32			v4daddr;	/* peer's address */		// �Զ�IP��ַ
	__u16			avl_height;
	__u16			ip_id_count;	/* IP ID for the next packet */	// һ������ֵ����������IP��Ƭ�ײ��е�id��
	struct inet_peer	*unused_next, **unused_prevp;		// �������ӵ�inet_peer_unused_head�����ϡ��������ϵĶԶ���Ϣ�鶼�ǿ��еģ��ɻ��ա�
	__u32			dtime;		/* the time of last use of not	// ��¼���ü���Ϊ0��ʱ�䣬�����ó���ָ��ʱ�䣬�ͻᱻ����
						 * referenced entries */
	atomic_t		refcnt;		// ���ü���
	atomic_t		rid;		/* Frag reception counter */	// ����ID���Զ˷��ͷ�Ƭ�ļ�����
	__u32			tcp_ts;										// ��¼TCP���һ��ACK�����ʱ��
	unsigned long		tcp_ts_stamp;							// ��¼TCP�У��յ����е�ʱ���
};

void			inet_initpeers(void) __init;

/* can be called with or without local BH being disabled */
struct inet_peer	*inet_getpeer(__be32 daddr, int create);

/* can be called from BH context or outside */
extern void inet_putpeer(struct inet_peer *p);

extern spinlock_t inet_peer_idlock;
/* can be called with or without local BH being disabled */
static inline __u16	inet_getid(struct inet_peer *p, int more)
{
	__u16 id;

	spin_lock_bh(&inet_peer_idlock);
	id = p->ip_id_count;
	p->ip_id_count += 1 + more;
	spin_unlock_bh(&inet_peer_idlock);
	return id;
}

#endif /* _NET_INETPEER_H */
