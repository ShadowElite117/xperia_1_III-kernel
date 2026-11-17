/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_NTFS3_REDIRECT_H
#define _LINUX_NTFS3_REDIRECT_H

#ifdef CONFIG_NTFS3_TEXFAT_REDIRECT
const char *ntfs3_texfat_redirect(const char *fstype, const char *dev_name);
#else
static inline const char *ntfs3_texfat_redirect(const char *fstype,
						const char *dev_name)
{
	return fstype;
}
#endif

#endif /* _LINUX_NTFS3_REDIRECT_H */
