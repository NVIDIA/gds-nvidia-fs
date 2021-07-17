/*
 * Copyright (c) 2021, NVIDIA CORPORATION. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 *
 */
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/list.h>

#include "nvfs-vers.h"
#include "nvfs-core.h"
#include "nvfs-stat.h"
#include "nvfs-dma.h"
#include "nvfs-pci.h"
#include "config-host.h"

extern struct module_entry modules_list[];
extern struct mutex nvfs_module_mutex;

int nvfs_modules_show(struct seq_file *m, void *v)
{
	int i;
	struct module_entry *mod_entry;

	mutex_lock(&nvfs_module_mutex);
	for (i = 0; i < nr_modules(); i++) {
		mod_entry = &modules_list[i];
		if (mod_entry->found && mod_entry->name) {
			seq_printf(m, "%s: %s\n", mod_entry->name,
				mod_entry->version);
		}
	}
	mutex_unlock(&nvfs_module_mutex);
	return 0;
}

/*
 * open "/proc/dev/nvidia-fs/driver"
 */
static int nvfs_modules_open(struct inode *inode, struct file *file)
{
       return single_open(file, nvfs_modules_show, NULL);
}
#ifdef HAVE_STRUCT_PROC_OPS
const struct proc_ops nvfs_module_ops = {
       .proc_open    	= nvfs_modules_open,
       .proc_read 	= seq_read,
       .proc_lseek	= seq_lseek,
       .proc_release	= single_release,
};
#else
const struct file_operations nvfs_module_ops = {

       .owner          = THIS_MODULE,
       .open           = nvfs_modules_open,
       .read           = seq_read,
       .llseek         = seq_lseek,
       .release        = single_release,
};
#endif

// used by library for parsing
static int nvfs_version_show(struct seq_file *m, void *v)
{
	unsigned int dvers = nvfs_driver_version();
	seq_printf(m, "%s: %u.%u\n", "version",
		nvfs_major_version(dvers), nvfs_minor_version(dvers));
	return 0;
}

/*
 * open "/proc/driver/nvidia-fs/version"
 */
static int nvfs_version_info_open(struct inode *inode, struct file *file)
{
	return single_open(file, nvfs_version_show, NULL);
}

#ifdef HAVE_STRUCT_PROC_OPS
const struct proc_ops nvfs_version_ops = {
	.proc_open	= nvfs_version_info_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};
#else
static const struct file_operations nvfs_version_ops = {
	.owner		= THIS_MODULE,
	.open		= nvfs_version_info_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif	
// used by library for parsing
static int nvfs_bridge_show(struct seq_file *m, void *v)
{
	struct pci_dev *pdev = NULL;
	while ((pdev = nvfs_get_next_acs_device(pdev)) != NULL) {
		seq_printf(m, "%04x:%02x:%02x.%d\n",
			pci_domain_nr(pdev->bus),
			pdev->bus->number,
			PCI_SLOT(pdev->devfn),
			PCI_FUNC(pdev->devfn));
	}
	return 0;
}

/*
 * open "/proc/driver/nvidia-fs/bridges"
 */
static int nvfs_bridge_info_open(struct inode *inode, struct file *file)
{
	return single_open(file, nvfs_bridge_show, NULL);
}

#ifdef HAVE_STRUCT_PROC_OPS
static const struct proc_ops nvfs_bridge_ops = {
	.proc_open	= nvfs_bridge_info_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};
#else
static const struct file_operations nvfs_bridge_ops = {
	.owner		= THIS_MODULE,
	.open		= nvfs_bridge_info_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

// used by nr_devices for parsing
static int nvfs_devices_show(struct seq_file *m, void *v)
{
	unsigned int ndevs = nvfs_get_device_count();
	seq_printf(m, "%u\n", ndevs);
	return 0;
}

/*
 * open "/proc/driver/nvidia-fs/nr_devices"
 */
static int nvfs_devices_info_open(struct inode *inode, struct file *file)
{
	return single_open(file, nvfs_devices_show, NULL);
}

#ifdef HAVE_STRUCT_PROC_OPS
static const struct proc_ops nvfs_devices_ops = {
	.proc_open	= nvfs_devices_info_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};
#else
static const struct file_operations nvfs_devices_ops = {
	.owner		= THIS_MODULE,
	.open		= nvfs_devices_info_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

/*
 * open "/proc/driver/nvidia-fs/peer_affinity"
 */
static int nvfs_peer_affinity_info_open(struct inode *inode, struct file *file)
{
	return single_open(file, nvfs_peer_affinity_show, NULL);
}
#ifdef HAVE_STRUCT_PROC_OPS
static const struct proc_ops nvfs_peer_affinity_ops = {
	.proc_open	= nvfs_peer_affinity_info_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};
#else
static const struct file_operations nvfs_peer_affinity_ops = {
	.owner		= THIS_MODULE,
	.open		= nvfs_peer_affinity_info_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

/*
 * open "/proc/driver/nvidia-fs/peer_distance"
 */

static int nvfs_pci_distance_map_info_open(struct inode *inode, struct file *file)
{
	return single_open(file, nvfs_peer_distance_show, NULL);
}

#ifdef HAVE_STRUCT_PROC_OPS
static const struct proc_ops nvfs_pci_distance_map_ops = {
	.proc_open	= nvfs_pci_distance_map_info_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};
#else
static const struct file_operations nvfs_pci_distance_map_ops = {
	.owner		= THIS_MODULE,
	.open		= nvfs_pci_distance_map_info_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};
#endif

/*
 * initialise the /proc/driver/nvfs/ directory
 */
int nvfs_proc_init(void)
{
	if (!proc_mkdir("driver/nvidia-fs", NULL))
		goto error_dir;

	if (!proc_create("driver/nvidia-fs/devcount", S_IFREG | 0444, NULL,
		&nvfs_devices_ops))
		goto error_entry;

	if (!proc_create("driver/nvidia-fs/version", S_IFREG | 0444, NULL,
		&nvfs_version_ops))
		goto error_entry;

	if (!proc_create("driver/nvidia-fs/bridges", S_IFREG | 0444, NULL,
		&nvfs_bridge_ops))
		goto error_entry;

	if (!proc_create("driver/nvidia-fs/modules", S_IFREG | 0444, NULL,
		&nvfs_module_ops))
		goto error_entry;

#ifdef CONFIG_NVFS_STATS
	if (!proc_create("driver/nvidia-fs/stats", S_IFREG | 0444, NULL,
		&nvfs_stats_fops)) {
		goto error_entry;
	}
#endif

	if (!proc_create("driver/nvidia-fs/peer_affinity", S_IFREG | 0444, NULL,
		&nvfs_peer_affinity_ops)) {
		goto error_entry;
	}

	if (!proc_create("driver/nvidia-fs/peer_distance", S_IFREG | 0444, NULL,
		&nvfs_pci_distance_map_ops)) {
		goto error_entry;
	}

	return 0;

error_entry:
	if (remove_proc_subtree("driver/nvidia-fs", NULL) < 0)
		nvfs_err("remove error for nvfs proc dir\n");
error_dir:
	return -ENOMEM;
}

/*
 * clean up the /proc/fs/nvfs/ directory
 */
void nvfs_proc_cleanup(void)
{
	if (remove_proc_subtree("driver/nvidia-fs", NULL) < 0)
		nvfs_err("remove error for driver/nvidia-fs proc dir\n");
}
