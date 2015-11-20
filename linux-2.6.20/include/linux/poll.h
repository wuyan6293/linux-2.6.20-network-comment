#ifndef _LINUX_POLL_H
#define _LINUX_POLL_H

#include <asm/poll.h>

#ifdef __KERNEL__

#include <linux/compiler.h>
#include <linux/wait.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>

/* ~832 bytes of stack space used max in sys_select/sys_poll before allocating
   additional memory. */
#define MAX_STACK_ALLOC 832
#define FRONTEND_STACK_ALLOC	256
#define SELECT_STACK_ALLOC	FRONTEND_STACK_ALLOC
#define POLL_STACK_ALLOC	FRONTEND_STACK_ALLOC
#define WQUEUES_STACK_ALLOC	(MAX_STACK_ALLOC - FRONTEND_STACK_ALLOC)
#define N_INLINE_POLL_ENTRIES	(WQUEUES_STACK_ALLOC / sizeof(struct poll_table_entry))

struct poll_table_struct;

/* 
 * structures and helpers for f_op->poll implementations
 */
typedef void (*poll_queue_proc)(struct file *, wait_queue_head_t *, struct poll_table_struct *);

typedef struct poll_table_struct {
	// 向wait_queue_head 添加回调节点(wait_queue_t)的接口函数
	poll_queue_proc qproc;
} poll_table;

// 通用的poll_wait 函数, 文件的f_ops->poll 通常会调用此函数
static inline void poll_wait(struct file * filp, wait_queue_head_t * wait_address, poll_table *p)
{
	// 调用 qproc 在wait_address 上添加节点和回调函数   
    // 调用 poll_table 上的函数指针向wait_address添加节点, 并设置节点的func   
    // qproc (如果是select或poll 则是 __pollwait, 如果是 epoll 则是 ep_ptable_queue_proc),
	if (p && wait_address)
		p->qproc(filp, wait_address, p);
}

static inline void init_poll_funcptr(poll_table *pt, poll_queue_proc qproc)
{
	pt->qproc = qproc;
}
// 与一个正在poll /select 的文件相关联,
struct poll_table_entry {
	struct file * filp;							// 在poll/select中的文件
	wait_queue_t wait;							// 插入到wait_queue_head_t 的节点
	wait_queue_head_t * wait_address;			// 文件上的wait_queue_head_t 地址
};

/*
 * Structures and helpers for sys_poll/sys_poll
 */
// select/poll 对poll_table的具体化实现
struct poll_wqueues {
	poll_table pt;
	struct poll_table_page * table;		// 如果inline_entries 空间不足, 从poll_table_page 中分配
	int error;
	int inline_index;					// 下一个要分配的inline_entrie 索引
	struct poll_table_entry inline_entries[N_INLINE_POLL_ENTRIES];
};

extern void poll_initwait(struct poll_wqueues *pwq);
extern void poll_freewait(struct poll_wqueues *pwq);

/*
 * Scaleable version of the fd_set.
 */

typedef struct {
	unsigned long *in, *out, *ex;
	unsigned long *res_in, *res_out, *res_ex;
} fd_set_bits;

/*
 * How many longwords for "nr" bits?
 */
#define FDS_BITPERLONG	(8*sizeof(long))
#define FDS_LONGS(nr)	(((nr)+FDS_BITPERLONG-1)/FDS_BITPERLONG)
#define FDS_BYTES(nr)	(FDS_LONGS(nr)*sizeof(long))

/*
 * We do a VERIFY_WRITE here even though we are only reading this time:
 * we'll write to it eventually..
 *
 * Use "unsigned long" accesses to let user-mode fd_set's be long-aligned.
 */
static inline
int get_fd_set(unsigned long nr, void __user *ufdset, unsigned long *fdset)
{
	nr = FDS_BYTES(nr);
	if (ufdset)
		return copy_from_user(fdset, ufdset, nr) ? -EFAULT : 0;

	memset(fdset, 0, nr);
	return 0;
}

static inline unsigned long __must_check
set_fd_set(unsigned long nr, void __user *ufdset, unsigned long *fdset)
{
	if (ufdset)
		return __copy_to_user(ufdset, fdset, FDS_BYTES(nr));
	return 0;
}

static inline
void zero_fd_set(unsigned long nr, unsigned long *fdset)
{
	memset(fdset, 0, FDS_BYTES(nr));
}

#define MAX_INT64_SECONDS (((s64)(~((u64)0)>>1)/HZ)-1)

extern int do_select(int n, fd_set_bits *fds, s64 *timeout);
extern int do_sys_poll(struct pollfd __user * ufds, unsigned int nfds,
		       s64 *timeout);

#endif /* KERNEL */

#endif /* _LINUX_POLL_H */
