/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Compatibility layer to build the Linux 5.15 ntfs3 driver on Linux 5.4.
 *
 * 5.4 has no idmapped mounts: VFS operations and helpers take no
 * user_namespace. ntfs3 keeps its 5.15 code and signatures; the helpers it
 * calls are mapped to their 5.4 forms here, and the operation tables use
 * thin wrappers that pass &init_user_ns.
 */
#ifndef _LINUX_NTFS3_COMPAT54_H
#define _LINUX_NTFS3_COMPAT54_H

#include <linux/bio.h>
#include <linux/bitops.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/uio.h>
#include <linux/user_namespace.h>

/* include/linux/bitops.h (5.11) */
#ifndef BITS_TO_U64
#define BITS_TO_U64(nr) DIV_ROUND_UP(nr, BITS_PER_TYPE(u64))
#endif

/* include/linux/bio.h (5.12): BIO_MAX_PAGES was renamed */
#ifndef BIO_MAX_VECS
#define BIO_MAX_VECS BIO_MAX_PAGES
#endif

/* include/linux/fs.h (5.12): no idmapped mounts on 5.4. */
#ifndef FS_ALLOW_IDMAP
#define FS_ALLOW_IDMAP 0
#endif

/* VFS helpers that gained a leading struct user_namespace * in 5.12. */
#define inode_init_owner(mnt_userns, inode, dir, mode)                         \
	inode_init_owner(inode, dir, mode)
#define generic_fillattr(mnt_userns, inode, stat) generic_fillattr(inode, stat)
#define setattr_prepare(mnt_userns, dentry, attr) setattr_prepare(dentry, attr)
#define setattr_copy(mnt_userns, inode, attr) setattr_copy(inode, attr)
#define generic_permission(mnt_userns, inode, mask)                            \
	generic_permission(inode, mask)
#define posix_acl_chmod(mnt_userns, inode, mode) posix_acl_chmod(inode, mode)
#define posix_acl_update_mode(mnt_userns, inode, mode, acl)                    \
	posix_acl_update_mode(inode, mode, acl)
#define inode_owner_or_capable(mnt_userns, inode) inode_owner_or_capable(inode)

/* fs/ioctl.c (5.8). 5.4's ioctl_fiemap() already syncs for FIEMAP_FLAG_SYNC. */
static inline int fiemap_prep(struct inode *inode,
			      struct fiemap_extent_info *fieinfo, u64 start,
			      u64 *len, u32 supported_flags)
{
	return fiemap_check_flags(fieinfo, supported_flags);
}

/*
 * lib/iov_iter.c (5.14): unlike iov_iter_copy_from_user_atomic(), this one
 * advances the iterator by the number of bytes copied.
 */
static inline size_t copy_page_from_iter_atomic(struct page *page,
						unsigned int offset,
						size_t bytes,
						struct iov_iter *i)
{
	size_t copied = iov_iter_copy_from_user_atomic(page, i, offset, bytes);

	iov_iter_advance(i, copied);
	return copied;
}

/* lib/iov_iter.c (5.16 / 5.15.y): returns the number of bytes NOT faulted in. */
static inline size_t fault_in_iov_iter_readable(struct iov_iter *i,
						size_t bytes)
{
	return iov_iter_fault_in_readable(i, bytes) ? bytes : 0;
}

#endif /* _LINUX_NTFS3_COMPAT54_H */
