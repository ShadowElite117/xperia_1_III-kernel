// SPDX-License-Identifier: GPL-2.0
/*
 * Serve "texfat" mount requests for NTFS volumes with ntfs3.
 *
 * Sony's vold only mounts vfat and exFAT, the latter with the vendor texfat
 * driver. A userspace helper reports NTFS volumes to vold as exFAT; vold then
 * asks for a texfat mount, which is redirected here to ntfs3 when the boot
 * sector carries the NTFS OEM ID (the same test ntfs3 itself applies).
 * Anything else, including real exFAT volumes, still goes to texfat.
 */

#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/ntfs3_redirect.h>
#include <linux/pagemap.h>
#include <linux/string.h>

/* struct NTFS_BOOT::system_ids, at offset 3 of the boot sector */
#define NTFS3_OEM_ID_OFF 3
static const char ntfs3_oem_id[8] = "NTFS    ";

static bool ntfs3_bdev_is_ntfs(const char *dev_name)
{
	struct block_device *bdev;
	struct page *page;
	bool ntfs = false;
	u8 *boot;

	bdev = blkdev_get_by_path(dev_name, FMODE_READ, NULL);
	if (IS_ERR(bdev))
		return false;

	page = read_mapping_page(bdev->bd_inode->i_mapping, 0, NULL);
	if (!IS_ERR(page)) {
		boot = kmap(page);
		ntfs = !memcmp(boot + NTFS3_OEM_ID_OFF, ntfs3_oem_id,
			       sizeof(ntfs3_oem_id));
		kunmap(page);
		put_page(page);
	}

	blkdev_put(bdev, FMODE_READ);
	return ntfs;
}

const char *ntfs3_texfat_redirect(const char *fstype, const char *dev_name)
{
	if (!fstype || !dev_name || strcmp(fstype, "texfat"))
		return fstype;

	if (!ntfs3_bdev_is_ntfs(dev_name))
		return fstype;

	pr_info("ntfs3: %s: NTFS volume, mounting with ntfs3 instead of texfat\n",
		dev_name);
	return "ntfs3";
}
