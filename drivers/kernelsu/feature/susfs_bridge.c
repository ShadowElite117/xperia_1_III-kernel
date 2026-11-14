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
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/string.h>
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

/* Used by fs/namespace.c to detect zygote-spawned processes. */
bool susfs_is_current_zygote_domain(void)
{
	return is_zygote(current_cred());
}

#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
extern int path_umount(struct path *path, int flags);
extern void susfs_run_try_umount_for_current_mnt_ns(void);

/* Called by susfs_try_umount() in fs/susfs.c for each user-defined path. */
void ksu_try_umount(const char *mnt, bool check_mnt, int flags, uid_t uid)
{
	struct path path;
	int err = kern_path(mnt, 0, &path);

	if (err)
		return;

	/* path_umount() releases the path's dentry/mnt references itself. */
	err = path_umount(&path, flags);
	if (err)
		pr_warn("susfs_bridge: umount %s failed: %d\n", mnt, err);
}

/*
 * Umount the susfs user-defined paths and then ksu's default module mount
 * points for the given uid. Called from susfs_run_try_umount_for_current_mnt_ns()
 * in fs/namespace.c (the RUN_UMOUNT manager command).
 */
void susfs_try_umount_all(uid_t uid)
{
	susfs_try_umount(uid);
	ksu_try_umount("/system", true, 0, uid);
	ksu_try_umount("/system_ext", true, 0, uid);
	ksu_try_umount("/vendor", true, 0, uid);
	ksu_try_umount("/product", true, 0, uid);
	ksu_try_umount("/odm", true, 0, uid);
	ksu_try_umount("/data/adb/modules", false, MNT_DETACH, uid);
	ksu_try_umount("/debug_ramdisk", true, MNT_DETACH, uid);
}
#endif

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
		if (arg5 && ksu_access_ok((void __user *)arg5, sizeof(error)))
			if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
				pr_info("susfs_bridge: copy_to_user failed\n");
		return true;
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
	case CMD_SUSFS_ADD_TRY_UMOUNT:
		if (!susfs_caller_is_privileged())
			return false;
		if (!ksu_access_ok((void __user *)arg3,
				   sizeof(struct st_susfs_try_umount))) {
			pr_err("susfs_bridge: ADD_TRY_UMOUNT arg3 not accessible\n");
			return true;
		}
		error = susfs_add_try_umount((struct st_susfs_try_umount __user *)arg3);
		if (arg5 && ksu_access_ok((void __user *)arg5, sizeof(error)))
			if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
				pr_info("susfs_bridge: copy_to_user failed\n");
		return true;
	case CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS:
		if (!susfs_caller_is_privileged())
			return false;
		susfs_run_try_umount_for_current_mnt_ns();
		if (arg5 && ksu_access_ok((void __user *)arg5, sizeof(error)))
			if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
				pr_info("susfs_bridge: copy_to_user failed\n");
		return true;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	case CMD_SUSFS_ADD_SUS_MOUNT:
		if (!susfs_caller_is_privileged())
			return false;
		if (!ksu_access_ok((void __user *)arg3,
				   sizeof(struct st_susfs_sus_mount))) {
			pr_err("susfs_bridge: ADD_SUS_MOUNT arg3 not accessible\n");
			return true;
		}
		error = susfs_add_sus_mount((struct st_susfs_sus_mount __user *)arg3);
		if (arg5 && ksu_access_ok((void __user *)arg5, sizeof(error)))
			if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
				pr_info("susfs_bridge: copy_to_user failed\n");
		return true;
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
	case CMD_SUSFS_ADD_SUS_KSTAT:
	case CMD_SUSFS_ADD_SUS_KSTAT_STATICALLY:
		if (!susfs_caller_is_privileged())
			return false;
		if (!ksu_access_ok((void __user *)arg3,
				   sizeof(struct st_susfs_sus_kstat))) {
			pr_err("susfs_bridge: ADD_SUS_KSTAT arg3 not accessible\n");
			return true;
		}
		error = susfs_add_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
		if (arg5 && ksu_access_ok((void __user *)arg5, sizeof(error)))
			if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
				pr_info("susfs_bridge: copy_to_user failed\n");
		return true;
	case CMD_SUSFS_UPDATE_SUS_KSTAT:
		if (!susfs_caller_is_privileged())
			return false;
		if (!ksu_access_ok((void __user *)arg3,
				   sizeof(struct st_susfs_sus_kstat))) {
			pr_err("susfs_bridge: UPDATE_SUS_KSTAT arg3 not accessible\n");
			return true;
		}
		error = susfs_update_sus_kstat((struct st_susfs_sus_kstat __user *)arg3);
		if (arg5 && ksu_access_ok((void __user *)arg5, sizeof(error)))
			if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
				pr_info("susfs_bridge: copy_to_user failed\n");
		return true;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	case CMD_SUSFS_SET_UNAME:
		if (!susfs_caller_is_privileged())
			return false;
		if (!ksu_access_ok((void __user *)arg3,
				   sizeof(struct st_susfs_uname))) {
			pr_err("susfs_bridge: SET_UNAME arg3 not accessible\n");
			return true;
		}
		error = susfs_set_uname((struct st_susfs_uname __user *)arg3);
		if (arg5 && ksu_access_ok((void __user *)arg5, sizeof(error)))
			if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
				pr_info("susfs_bridge: copy_to_user failed\n");
		return true;
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG:
		if (!susfs_caller_is_privileged())
			return false;
		if (!ksu_access_ok((void __user *)arg3, PAGE_SIZE)) {
			pr_err("susfs_bridge: SET_CMDLINE arg3 not accessible\n");
			return true;
		}
		error = susfs_set_cmdline_or_bootconfig((char __user *)arg3);
		if (arg5 && ksu_access_ok((void __user *)arg5, sizeof(error)))
			if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
				pr_info("susfs_bridge: copy_to_user failed\n");
		return true;
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
	case CMD_SUSFS_ADD_OPEN_REDIRECT:
		if (!susfs_caller_is_privileged())
			return false;
		if (!ksu_access_ok((void __user *)arg3,
				   sizeof(struct st_susfs_open_redirect))) {
			pr_err("susfs_bridge: ADD_OPEN_REDIRECT arg3 not accessible\n");
			return true;
		}
		error = susfs_add_open_redirect((struct st_susfs_open_redirect __user *)arg3);
		if (arg5 && ksu_access_ok((void __user *)arg5, sizeof(error)))
			if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
				pr_info("susfs_bridge: copy_to_user failed\n");
		return true;
#endif
	case CMD_SUSFS_SHOW_VERSION: {
		const char *ver = SUSFS_VERSION;
		size_t len = strlen(ver) + 1;

		if (!ksu_access_ok((void __user *)arg3, len))
			return true;
		error = copy_to_user((void __user *)arg3, ver, len);
		if (arg5 && ksu_access_ok((void __user *)arg5, sizeof(error)))
			if (copy_to_user((void __user *)arg5, &error, sizeof(error)))
				pr_info("susfs_bridge: copy_to_user failed\n");
		return true;
	}
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
