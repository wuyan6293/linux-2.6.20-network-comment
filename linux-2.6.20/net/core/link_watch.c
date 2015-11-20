/*
 * Linux network device link state notification
 *
 * Author:
 *     Stefan Rompf <sux@loplof.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 *
 */

#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/if.h>
#include <net/sock.h>
#include <net/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/jiffies.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/workqueue.h>
#include <linux/bitops.h>
#include <asm/types.h>


enum lw_bits {
	LW_RUNNING = 0,		// 当linkwatch_work工作队列调度时，该标志位被设置。当工作队列被激活后，该标志位被清除
	LW_SE_USED			// 标识静态分配的singleevent是否被使用
};

static unsigned long linkwatch_flags;
static unsigned long linkwatch_nextevent;

static void linkwatch_event(struct work_struct *dummy);
static DECLARE_DELAYED_WORK(linkwatch_work, linkwatch_event);

static LIST_HEAD(lweventlist);
static DEFINE_SPINLOCK(lweventlist_lock);

struct lw_event {
	struct list_head list;
	struct net_device *dev;
};

/* Avoid kmalloc() for most systems */
static struct lw_event singleevent;

static unsigned char default_operstate(const struct net_device *dev)
{
	if (!netif_carrier_ok(dev))
		return (dev->ifindex != dev->iflink ?
			IF_OPER_LOWERLAYERDOWN : IF_OPER_DOWN);

	if (netif_dormant(dev))
		return IF_OPER_DORMANT;

	return IF_OPER_UP;
}


static void rfc2863_policy(struct net_device *dev)
{
	unsigned char operstate = default_operstate(dev);

	if (operstate == dev->operstate)
		return;

	write_lock_bh(&dev_base_lock);

	switch(dev->link_mode) {
	case IF_LINK_MODE_DORMANT:
		if (operstate == IF_OPER_UP)
			operstate = IF_OPER_DORMANT;
		break;

	case IF_LINK_MODE_DEFAULT:
	default:
		break;
	};

	dev->operstate = operstate;

	write_unlock_bh(&dev_base_lock);
}


/* Must be called with the rtnl semaphore held */
void linkwatch_run_queue(void)
{
	struct list_head head, *n, *next;
	// 取出lweventlist链表中的未处理事件，放入临时链表中
	spin_lock_irq(&lweventlist_lock);
	list_replace_init(&lweventlist, &head);
	spin_unlock_irq(&lweventlist_lock);
	// 遍历所有的未处理事件
	list_for_each_safe(n, next, &head) {
		struct lw_event *event = list_entry(n, struct lw_event, list);
		struct net_device *dev = event->dev;

		if (event == &singleevent) {
			clear_bit(LW_SE_USED, &linkwatch_flags);
		} else {
			kfree(event);
		}

		/* We are about to handle this device,
		 * so new events can be accepted
		 */
		clear_bit(__LINK_STATE_LINKWATCH_PENDING, &dev->state);

		rfc2863_policy(dev);
		if (dev->flags & IFF_UP) {
			if (netif_carrier_ok(dev)) {
				WARN_ON(dev->qdisc_sleeping == &noop_qdisc);
				dev_activate(dev);
			} else
				dev_deactivate(dev);

			netdev_state_change(dev);
		}

		dev_put(dev);
	}
}       

// 该函数为linkwatch_work工作队列的例程，一旦linkwatch_work工作队列被激活，就会调用该函数
static void linkwatch_event(struct work_struct *dummy)
{
	/* Limit the number of linkwatch events to one
	 * per second so that a runaway driver does not
	 * cause a storm of messages on the netlink
	 * socket
	 */	
	linkwatch_nextevent = jiffies + HZ;
	clear_bit(LW_RUNNING, &linkwatch_flags);		// 清楚标志

	rtnl_lock();
	linkwatch_run_queue();
	rtnl_unlock();
}


void linkwatch_fire_event(struct net_device *dev)
{
	if (!test_and_set_bit(__LINK_STATE_LINKWATCH_PENDING, &dev->state)) {
		unsigned long flags;
		struct lw_event *event;

		// 如果静态分配的lw_event没有被使用，则优先使用。使用后会设置linkwatch_flags的LW_SE_USED标志
		if (test_and_set_bit(LW_SE_USED, &linkwatch_flags)) {
			event = kmalloc(sizeof(struct lw_event), GFP_ATOMIC);

			if (unlikely(event == NULL)) {
				clear_bit(__LINK_STATE_LINKWATCH_PENDING, &dev->state);
				return;
			}
		} else {
			event = &singleevent;
		}
		// 将dev增加到lw_event上，并增加引用计数
		dev_hold(dev);
		event->dev = dev;
		// 添加到事件队列里
		spin_lock_irqsave(&lweventlist_lock, flags);
		list_add_tail(&event->list, &lweventlist);
		spin_unlock_irqrestore(&lweventlist_lock, flags);
		// 设置状态为LW_RUNNING
		if (!test_and_set_bit(LW_RUNNING, &linkwatch_flags)) {
			unsigned long delay = linkwatch_nextevent - jiffies;

			/* If we wrap around we'll delay it by at most HZ. */
			if (delay > HZ)
				delay = 0;
			schedule_delayed_work(&linkwatch_work, delay);	// 每秒调用一次
		}
	}
}

EXPORT_SYMBOL(linkwatch_fire_event);
