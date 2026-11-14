// SPDX-License-Identifier: GPL-2.0
/*
 * susfs <-> KernelSU Next bridge.
 *
 * susfs4ksu's userspace tool (ksu_susfs) talks to the kernel with
 *   prctl(KERNEL_SU_OPTION = 0xDEADBEEF, CMD_SUSFS_*, arg3, arg4, arg5)
 * which is the weishu KernelSU convention. KernelSU Next dropped the prctl
 * handler in favour of an ioctl supercall, so there is nothing to route the
 * susfs commands. We install a dedicated kprobe on the prctl syscall and
 * route only the susfs commands, leaving every other prctl untouched.
 *
 * Only root or the KernelSU manager may configure susfs.
 */

#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/printk.h>
#include <linux/susfs.h>
#include <linux/susfs_def.h>

#include "feature/susfs_bridge.h"
#include "selinux/selinux.h"
#include "manager/manager_identity.h"
#include "compat/kernel_compat.h"

#define KSU_SUSFS_PRCTL_MAGIC 0xDEADBEEFu

/* Used by fs/susfs.c to avoid hiding things from the ksu domain itself. */
bool susfs_is_current_ksu_domain(void)
{
	return is_ksu_domain();
}

static bool susfs_caller_is_privileged(void)
{
	return current_uid().val == 0 || is_manager();
}

/* Returns true when the prctl was a susfs command and was consumed here. */
static bool ksu_handle_susfs_prctl(unsigned int option, unsigned long cmd,
				   unsigned long arg3, unsigned long arg4,
				   unsigned long arg5)
{
	int error = 0;

	if (option != KSU_SUSFS_PRCTL_MAGIC)
		return false;

	switch (cmd) {
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
	case CMD_SUSFS_ADD_SUS_PATH:
		if (!susfs_caller_is_privileged())
			return false;
		if (!ksu_access_ok((void __user *)arg3,
				   sizeof(struct st_susfs_sus_path))) {
			pr_err("susfs_bridge: ADD_SUS_PATH arg3 not accessible\n");
			return true;
		}
		error = susfs_add_sus_path((struct st_susfs_sus_path __user *)arg3);
		if (arg5 && ksu_access_ok((void __user *)arg5, sizeof(error))) {
			if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
				pr_info("susfs_bridge: copy_to_user failed\n");
		}
		return true;
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
	case CMD_SUSFS_ENABLE_LOG:
		if (!susfs_caller_is_privileged())
			return false;
		susfs_set_log(arg3 == 1);
		return true;
#endif
	default:
		return false;
	}
}

static int susfs_prctl_pre(struct kprobe *p, struct pt_regs *regs)
{
	/*
	 * arm64 pt_regs-based syscall ABI: __arm64_sys_prctl(const struct
	 * pt_regs *regs) receives the pointer to the syscall pt_regs in x0.
	 */
	struct pt_regs *sys = (struct pt_regs *)regs->regs[0];
	unsigned int option;

	if (!sys)
		return 0;

	option = (unsigned int)sys->regs[0];
	if (likely(option != KSU_SUSFS_PRCTL_MAGIC))
		return 0;

	ksu_handle_susfs_prctl(option, sys->regs[1], sys->regs[2],
			       sys->regs[3], sys->regs[4]);
	return 0;
}

static struct kprobe susfs_prctl_kp = {
	.symbol_name = "__arm64_sys_prctl",
	.pre_handler = susfs_prctl_pre,
};

void ksu_susfs_bridge_init(void)
{
	int ret = register_kprobe(&susfs_prctl_kp);

	if (ret)
		pr_err("susfs_bridge: register_kprobe(prctl) failed: %d\n", ret);
	else
		pr_info("susfs_bridge: prctl bridge installed\n");
}

void ksu_susfs_bridge_exit(void)
{
	unregister_kprobe(&susfs_prctl_kp);
}
