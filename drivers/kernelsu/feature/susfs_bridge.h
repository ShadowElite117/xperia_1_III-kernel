/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __KSU_H_SUSFS_BRIDGE
#define __KSU_H_SUSFS_BRIDGE

/*
 * Bridge between the susfs4ksu kernel patch (which expects the weishu
 * KernelSU prctl command channel) and KernelSU Next, which uses an ioctl
 * supercall and has no native prctl handler. A dedicated kprobe on the
 * prctl syscall routes the CMD_SUSFS_* commands to susfs.
 */

void ksu_susfs_bridge_init(void);
void ksu_susfs_bridge_exit(void);

#endif
