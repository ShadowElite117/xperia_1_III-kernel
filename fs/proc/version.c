// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/utsname.h>

#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
extern void susfs_spoof_uname(struct new_utsname *tmp);

/*
 * Keep /proc/version consistent with a spoofed uname: same release and
 * version, and optionally the build info of the kernel being imitated.
 */
static bool susfs_proc_version_show(struct seq_file *m)
{
	const char *build_info = CONFIG_KSU_SUSFS_SPOOF_PROC_VERSION_BUILD_INFO;
	struct new_utsname tmp;

	memcpy(&tmp, utsname(), sizeof(tmp));
	susfs_spoof_uname(&tmp);
	if (!strcmp(tmp.release, utsname()->release) &&
	    !strcmp(tmp.version, utsname()->version))
		return false;

	if (build_info[0])
		seq_printf(m, "%s version %s %s %s\n", tmp.sysname,
			   tmp.release, build_info, tmp.version);
	else
		seq_printf(m, linux_proc_banner, tmp.sysname, tmp.release,
			   tmp.version);
	return true;
}
#endif

static int version_proc_show(struct seq_file *m, void *v)
{
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	if (susfs_proc_version_show(m))
		return 0;
#endif
	seq_printf(m, linux_proc_banner,
		utsname()->sysname,
		utsname()->release,
		utsname()->version);
	return 0;
}

static int __init proc_version_init(void)
{
	proc_create_single("version", 0, NULL, version_proc_show);
	return 0;
}
fs_initcall(proc_version_init);
