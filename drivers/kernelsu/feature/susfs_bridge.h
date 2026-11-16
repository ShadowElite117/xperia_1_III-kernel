/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_SUSFS_BRIDGE
#define __KSU_H_SUSFS_BRIDGE

/*
 * Bridge between the susfs4ksu kernel patch (which expects the weishu
 * KernelSU prctl command channel) and KernelSU Next, which uses an ioctl
 * supercall and has no native prctl handler. The prctl syscall in
 * kernel/sys.c calls ksu_susfs_handle_prctl() to route the CMD_SUSFS_*
 * commands to susfs.
 */

#include <linux/types.h>

bool ksu_susfs_handle_prctl(int option, unsigned long cmd, unsigned long arg3,
			    unsigned long arg4, unsigned long arg5);
void ksu_susfs_bridge_init(void);
void ksu_susfs_bridge_exit(void);

#endif
