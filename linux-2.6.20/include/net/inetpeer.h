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
// 对端信息块，组织成AVL树. peer_root作为树根，v4daddr为key值
struct inet_peer
{
	/* group together avl_left,avl_right,v4daddr to speedup lookups */
	struct inet_peer	*avl_left, *avl_right;				// avl_left、avl_right、avl_right为AVL树的组成部分
	__be32			v4daddr;	/* peer's address */		// 对端IP地址
	__u16			avl_height;
	__u16			ip_id_count;	/* IP ID for the next packet */	// 一个递增值，用来设置IP分片首部中的id域
	struct inet_peer	*unused_next, **unused_prevp;		// 用来链接到inet_peer_unused_head链表上。该链表上的对端信息块都是空闲的，可回收。
	__u32			dtime;		/* the time of last use of not	// 记录引用计数为0的时间，当闲置超出指定时间，就会被回收
						 * referenced entries */
	atomic_t		refcnt;		// 引用计数
	atomic_t		rid;		/* Frag reception counter */	// 递增ID，对端发送分片的计数器
	__u32			tcp_ts;										// 记录TCP最后一个ACK到达的时间
	unsigned long		tcp_ts_stamp;							// 记录TCP中，收到段中的时间戳
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
