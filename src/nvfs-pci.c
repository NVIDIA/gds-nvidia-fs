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

#include <linux/pci.h>
#include <linux/pci_regs.h>
#include <linux/pci_ids.h>
#include <linux/jhash.h>
#include <linux/seq_file.h>

#include "nvfs-pci.h"
#include "nvfs-core.h"
#include <linux/seq_file.h>
#include <linux/topology.h>

#define MAX_PCIE_BW_INDEX (PCIE_LNK_X32 * 5U)

// for debugging peer ranking
//#define NVFS_PCI_DEBUG

// for simulating peers with non-uniform link-width
//#define SIMULATE_NON_UNIFORM_LINK_SELECTION
//#define PDEVINFO(bus, dev, func) nvfs_bdf2pdevinfo(0, (bus), (dev), (func))

// PCI_EXPRESS_LINK_STATUS_REGISTER : LinkSpeed  :4 bits, LinkWidth  :6 bits

// from drivers/pci/pci.h.
const unsigned char nvfs_pcie_link_speed_table[MAX_LNKSPEED_ENTRIES] = {
	PCI_SPEED_UNKNOWN,		/* 0 */
	PCIE_SPEED_2_5GT,		/* 1 */
	PCIE_SPEED_5_0GT,		/* 2 */
	PCIE_SPEED_8_0GT,		/* 3 */
	PCIE_SPEED_16_0GT,		/* 4 */
#ifdef HAVE_PCIE_SPEED_32_0GT
	PCIE_SPEED_32_0GT,		/* 5 */
#endif
#ifdef HAVE_PCIE_SPEED_64_0GT
	PCIE_SPEED_64_0GT,		/* 6 */
#endif
	PCI_SPEED_UNKNOWN,		/* 7 */
	PCI_SPEED_UNKNOWN,		/* 8 */
	PCI_SPEED_UNKNOWN,		/* 9 */
	PCI_SPEED_UNKNOWN,		/* A */
	PCI_SPEED_UNKNOWN,		/* B */
	PCI_SPEED_UNKNOWN,		/* C */
	PCI_SPEED_UNKNOWN,		/* D */
	PCI_SPEED_UNKNOWN,		/* E */
	PCI_SPEED_UNKNOWN		/* F */
};

const unsigned char nvfs_pcie_link_width_table[MAX_LNKWIDTH_ENTRIES] = {
	PCIE_LNK_WIDTH_RESRV,   /* 0 */
	PCIE_LNK_X1,            /* 1 */
	PCIE_LNK_X2,            /* 2 */
	PCIE_LNK_X4,            /* 3 */
	PCIE_LNK_X8,            /* 4 */
	PCIE_LNK_X12,           /* 5 */
	PCIE_LNK_X16,           /* 6 */
	PCIE_LNK_X32,           /* 7 */
	PCIE_LNK_WIDTH_UNKNOWN, /* 8 */
	PCIE_LNK_WIDTH_UNKNOWN, /* 9 */
	PCIE_LNK_WIDTH_UNKNOWN, /* A */
	PCIE_LNK_WIDTH_UNKNOWN, /* B */
	PCIE_LNK_WIDTH_UNKNOWN, /* C */
	PCIE_LNK_WIDTH_UNKNOWN, /* D */
	PCIE_LNK_WIDTH_UNKNOWN, /* E */
	PCIE_LNK_WIDTH_UNKNOWN, /* F */
};

// capture gpu-peer rank info
struct nvfs_rank_data {
	u32 rank;       // rank
	u16 cross;      // if no common ancestor
	u16 pci_dist;   // pci distance between a GPU and its peer dma device
	u16 bw_index;   // indicator of available bw
	uint64_t count; // counts number of p2p dma ops between the pair
};

// store pci paths
static uint64_t gpu_bdf_map[MAX_GPU_DEVS][MAX_PCI_DEPTH];

static uint64_t peer_bdf_map[MAX_PEER_DEVS][MAX_PCI_DEPTH];

// index tables
static uint64_t gpu_info_table[MAX_GPU_DEVS];

static uint64_t peer_info_table[MAX_PEER_DEVS];

// pci-distance matrix
static struct nvfs_rank_data gpu_rank_matrix[MAX_GPU_DEVS][MAX_PEER_DEVS];

// hash function for pci devinfo
static inline u64 hashfn(u64 value)
{
	static u32 hash_seed = 0;
	return jhash_2words((uint32_t)value , (uint32_t)(value >> 32), hash_seed);
}

// store bdf info to index table and fetch the index
static inline
unsigned int _create_index_entry(uint64_t pcidevinfo,
                                 uint64_t index_table[],
				 unsigned int max_elements)
{
	u32 i = 0;
	u32 idx = hashfn(pcidevinfo) % max_elements;
	while (i < max_elements) {
		if (index_table[idx] == 0)
			return idx;
		idx = (idx + 1 ) % max_elements;
		i++;
	}
	nvfs_err("nvfs_pci: hash index full for pdevinfo :"PCI_INFO_FMT,
			PCI_INFO_ARGS(pcidevinfo));
	return UINT_MAX;
}

// fetch index given bdf info
static inline
unsigned int _lookup_index_entry(uint64_t pcidevinfo,
                                 uint64_t index_table[],
                                 unsigned int max_elements)
{
	u32 i = 0;
	u32 idx = hashfn(pcidevinfo) % max_elements;
	while (i < max_elements) {
		if ((index_table[idx] & NVFS_PDEVINFO_INFO_MASK) == pcidevinfo)
			return idx;
		idx = (idx + 1 ) % max_elements;
		i++;
	}

	nvfs_err("nvfs_pci: no hash entry for pdevinfo:"PCI_INFO_FMT,
			PCI_INFO_ARGS(pcidevinfo));
	return UINT_MAX;
}

/*
 *  Description : given a gpu pci device info (bdf), creates and returns
 *                hash index
 *  @params  : pci device info of the gpu
 *  @returns : index
 */
unsigned int nvfs_create_gpu_hash_entry(uint64_t pdevinfo)
{
	if (!pdevinfo)
		return UINT_MAX;
	return _create_index_entry(pdevinfo, gpu_info_table, MAX_GPU_DEVS);
}

/*
 *  Description : given a peer pci device info (bdf), creates and returns
 *                hash index
 *  @params  : pci device info of the peer device
 *  @returns : index
 */
unsigned int nvfs_create_peer_hash_entry(uint64_t pdevinfo)
{
	if (!pdevinfo)
		return UINT_MAX;
	return _create_index_entry(pdevinfo, peer_info_table, MAX_PEER_DEVS);
}

/*
 *  Description : given a gpu pci device info (bdf), lookup the index
 *  @params  : pci device info of gpu
 *  @returns : hash index
 */
unsigned int nvfs_get_gpu_hash_index(uint64_t pdevinfo)
{
	return _lookup_index_entry(pdevinfo, gpu_info_table, MAX_GPU_DEVS);
}

/*
 *  Description : given a gpu hash index, get the pdevinfo
 *  @params  : gpu hash index
 *  @returns : gpu pci device info on success or 0 on noentry
 */
uint64_t nvfs_lookup_gpu_hash_index_entry(unsigned int index)
{
	return (index < MAX_GPU_DEVS) ? gpu_info_table[index] : 0;
}

/*
 *  Description : given a peer pci device info (bdf), lookup the index
 *  @params  : pci device info of peer device
 *  @returns : hash index
 */
unsigned int nvfs_get_peer_hash_index(uint64_t pdevinfo)
{
	return _lookup_index_entry(pdevinfo, peer_info_table, MAX_PEER_DEVS);
}

/*
 *  Description : given a peer hash index, get the pdevinfo
 *  @params  : peer hash index
 *  @returns : peer pci device info on success or 0 on noentry
 */
uint64_t nvfs_lookup_peer_hash_index_entry(unsigned int index)
{
	return (index < MAX_PEER_DEVS) ? peer_info_table[index] : 0;
}

/*
 *  Description : check if a bridge has ACS enabled
 *  @params     : pci device pointer
 *  @returns    : boolean
 */
static bool nvfs_pcie_acs_enabled(struct pci_dev *pdev) {
	int pos;
	u16 cap, ctrl;

	pos = pci_find_ext_capability(pdev, PCI_EXT_CAP_ID_ACS);
	if (!pos)
		return false;
	pci_read_config_word(pdev, pos + PCI_ACS_CAP, &cap);
	pci_read_config_word(pdev, pos + PCI_ACS_CTRL, &ctrl);
	return cap && (ctrl & 0x7f);
}

/*
 *  Description : get next pci bridge with ACS enabled
 *  @params     : pci device pointer
 *  @returns    : pci device pointer
 */
struct pci_dev *nvfs_get_next_acs_device(struct pci_dev *pdev) {
	// reference to from is dropped internally
	while ((pdev = pci_get_class(PCI_CLASS_BRIDGE_PCI << 8, pdev)) != NULL) {
		if (nvfs_pcie_acs_enabled(pdev))
			break;
	}
	return pdev;
}

/*
 *  Description : calculate current device bandwidth
 *  @params     : pci device pointer (IN), lnk speed (OUT), lnk_width (OUT)
 *  @returns    : bandwidth
 */
static u32 nvfs_pcie_bw_available(struct pci_dev *pdev,
                                  enum pci_bus_speed *speed,
                                  enum pcie_link_width *width) {
    u32 bw;
    int ret;
    u16 lnksta;
    u8 lnk_speed_idx;
	enum pci_bus_speed lnk_speed;
	enum pcie_link_width lnk_width;

	ret = pcie_capability_read_word(pdev, PCI_EXP_LNKSTA, &lnksta);
	if (ret) {
        nvfs_err("error reading link capability register");
	    return 0;
    }

    lnk_width = (lnksta & PCI_EXP_LNKSTA_NLW) >> PCI_EXP_LNKSTA_NLW_SHIFT;
    lnk_speed_idx = lnksta & PCI_EXP_LNKSTA_CLS;
    if (lnk_speed_idx < sizeof(nvfs_pcie_link_speed_table)) {
        lnk_speed = nvfs_pcie_link_speed_table[lnk_speed_idx];
        bw = lnk_width * lnk_speed_idx;
        nvfs_dbg("nvfs_pci pci device %04x:%02x:%02x:%d width:%u "
                "speed_index:%u bw:%u", pci_domain_nr(pdev->bus),
                 pdev->bus->number, PCI_SLOT(pdev->devfn),
                 PCI_FUNC(pdev->devfn), lnk_width, lnk_speed_idx, bw);
    } else {
        bw = 0;
        nvfs_warn("cannot determine bw, unexpected link_speed value for device"
                 "%04x:%02x:%02x:%d\n", pci_domain_nr(pdev->bus),
                 pdev->bus->number, PCI_SLOT(pdev->devfn), PCI_FUNC(pdev->devfn));
    }

    *speed = lnk_speed;
    *width = lnk_width;
    return bw;
}

/*
 *  Description : given a vendor_id, store pci device path for an array of
 devices (bottom-up).
 *  @params    : path array
 *  @params    : max devices for whom to compute path
 *  @vendor_id : vendor id
 *  @returns   : none
 *  Notes      : This function should be invoked atmost once per vendor_type for
 *  	         storing paths during driver initialization.
 *  	         synchronization is not needed.
 */
static void __nvfs_find_all_device_paths(uint64_t paths[][MAX_PCI_DEPTH],
                                         int max_devices,
                                         unsigned int class) {
	unsigned int count = 0, bw = 0;
	unsigned short depth;
	struct pci_dev *pdev = NULL, *ppdev = NULL;
	enum pci_bus_speed lnk_speed = PCI_SPEED_UNKNOWN;
	enum pcie_link_width lnk_width = PCIE_LNK_WIDTH_UNKNOWN;

	while ((pdev = pci_get_class(class, pdev)) != NULL) {
		uint64_t pdevinfo;
		unsigned int idx = UINT_MAX;

		// devices of our interest should be associated with bus
		if (!pdev->bus)
			continue;

		if (pdev->class != class) {
			nvfs_err("nvfs_pci unexpected pci class mismatch, abort path find!\n");
			return;
		}

		pdevinfo = nvfs_pdevinfo(pdev);

		// store speed related attributes for the leaf device
		bw = nvfs_pcie_bw_available(pdev, &lnk_speed, &lnk_width);
		if (bw) {
			#ifdef SIMULATE_NON_UNIFORM_LINK_SELECTION
			if (pdevinfo == PDEVINFO(88,0,1)) {
				lnk_width = 0x04;
				nvfs_info(PCI_INFO_FMT":"PCI_INFO_FMT"\n",
					PCI_INFO_ARGS(pdevinfo), PCI_INFO_ARGS(PDEVINFO(88,0,1)));
			}
			#endif
			nvfs_pdevinfo_set_link_width(&pdevinfo, lnk_width);
			nvfs_pdevinfo_set_link_speed(&pdevinfo, lnk_speed);
		}

		if (PCI_DEV_GPU(class >> 8, pdev->vendor)) {
			idx = nvfs_create_gpu_hash_entry(pdevinfo);
			if (idx == UINT_MAX)
				goto error;
			gpu_info_table[idx] = pdevinfo;
		} else if (PCI_DEV_IB(class >> 8) || PCI_DEV_NVME(class)) {
			idx = nvfs_create_peer_hash_entry(pdevinfo);
			if (idx == UINT_MAX)
				goto error;
			nvfs_pdevinfo_set_class(&pdevinfo, class);
			peer_info_table[idx] = pdevinfo;
		} else {
			#ifdef NVFS_PCI_DEBUG
			nvfs_dbg("nvfs_pci skipping pci device entry "
				"%04x:%02x:%02x:%d\n", pci_domain_nr(pdev->bus),
				pdev->bus->number, PCI_SLOT(pdev->devfn),
				PCI_FUNC(pdev->devfn));
			#endif
			continue;
		}

		nvfs_dbg("nvfs_pci pci device entry[%u] %04x:%02x:%02x:%d path:",
			idx, pci_domain_nr(pdev->bus), pdev->bus->number,
			PCI_SLOT(pdev->devfn),
			PCI_FUNC(pdev->devfn));

		// pci path bottom-up
		depth = 0;
		ppdev = pdev;
		#ifdef NVFS_PCI_DEBUG
		if (pci_find_pcie_root_port(ppdev))
			nvfs_dbg("endpoint path has pcie root port");
		#endif
		// pcie device not hinged on root port
		if (ppdev->bus && pci_is_root_bus(ppdev->bus)) {
			paths[idx][depth] = PCI_NULL_DEV_NORP;
			nvfs_dbg("nvfs_pci no root bridge: %04x:%02x:%02x:%d depth :%u ",
				ppdev->bus ? pci_domain_nr(ppdev->bus) : 0,
				ppdev->bus ? ppdev->bus->number : 0,
				PCI_SLOT(ppdev->devfn), PCI_FUNC(ppdev->devfn), depth);
			goto next;
		}

		do {
			// this does not take a reference to the upstream bridge
			ppdev = pci_upstream_bridge(ppdev);
			if (ppdev) {
				paths[idx][depth] = nvfs_pdevinfo(ppdev);
				if (nvfs_pcie_acs_enabled(ppdev))
					nvfs_pdevinfo_set_acs(&paths[idx][depth]);
				nvfs_dbg("nvfs_pci bridge: %04x:%02x:%02x:%d (acs=%u/%u) depth :%u",
					ppdev->bus ? pci_domain_nr(ppdev->bus) : 0,
					ppdev->bus ? ppdev->bus->number : 0,
					PCI_SLOT(ppdev->devfn), PCI_FUNC(ppdev->devfn),
					nvfs_pdevinfo_get_acs(paths[idx][depth]),
					nvfs_pcie_acs_enabled(ppdev), depth);
				depth++;
				if (depth >= MAX_PCI_DEPTH) {
					nvfs_err("nvfs_pci : pci device path length exceeds limits!");
					break;
				}
			}
		} while (ppdev && ppdev->bus);
next:
		count++;
		if (count >= max_devices) {
			// we are exiting, drop the last ref
			pci_dev_put(pdev); // pci_get_class
			nvfs_err("nvfs_pci: devices from class type :0x%x exceeds device table limits!\n",
				class);
			break;
		}
	}
	return;

error:
	pci_dev_put(pdev); // pci_get_class
	nvfs_err("nvfs_pci: pci_device index table already full!\n");
	return;
}

/*
 *  Description : function to compute numa distance given a gpu_index
 *  		  and an peer_index.
 *  @params  : gpu_index
 *  @params  : peer_index
 *  @returns : numa distance on success or REMOTE_DISTANCE on error.
 */

static unsigned int __nvfs_gpu2peer_numa_distance(unsigned int gpu_index,
		unsigned int peer_index) {
	int na, nb;
	na = nvfs_get_numa_node_from_pdevinfo(gpu_info_table[gpu_index]);
	if (na < 0) {
		nvfs_err("warning: error retrieving numa node for device "PCI_INFO_FMT,
			PCI_INFO_ARGS(gpu_info_table[gpu_index]));
	}

	nb = nvfs_get_numa_node_from_pdevinfo(peer_info_table[peer_index]);
	if (nb < 0) {
		nvfs_err("warning: error retrieving numa node for device "PCI_INFO_FMT,
			PCI_INFO_ARGS(peer_info_table[peer_index]));
	}

    // for systems which are not NUMA aware
    if ((na < 0) && (nb < 0))
        return LOCAL_DISTANCE;
    // for buggy systems, where one has NUMA node set, other not
    else if ((na < 0) || (nb < 0))
        return REMOTE_DISTANCE;
    else
        return node_distance(na, nb);
}

/*
 *  Description : check if gpu and peer pci device reside on the same local numa node
 *                or at a distant numa node
 *  @params  : gpu_index
 *  @params  : peer_index
 *  @returns : true if local or false for remote
 */
static bool nvfs_gpu2peer_islocal(unsigned int gpu_index,
		unsigned int peer_index) {
	if (__nvfs_gpu2peer_numa_distance(gpu_index, peer_index) ==
		LOCAL_DISTANCE)
		return true;
	else
		return false;
}

/*
 *  Description : core function to compute the pci distance given a gpu_index
 *  		  and an peer_index. (an index maps to a device bdf array slot)
 *  @params  : gpu_index
 *  @params  : peer_index
 *  @returns : rank on success or UINT_MAX on error.
 *             Upper 16 bytes of result is set if the distance is cross node.
 */
static unsigned int __nvfs_get_gpu2peer_distance(unsigned int gpu_index,
                                                 unsigned int peer_index) {
	int i = 0, j = 0, i_max = 0;
	u64 pdevinfo = 0;
	bool common = false;
	int lowest_common = -1;
	unsigned int pci_dist = UINT_MAX;
	unsigned int gdepth = 0, pdepth = 0;

	if ((gpu_index >= MAX_GPU_DEVS) || (peer_index >= MAX_PEER_DEVS)) {
		nvfs_err("%s :%u invalid device index %u(max=%u)/%u(max=%u)\n",
			__func__, __LINE__, gpu_index, MAX_GPU_DEVS,
			peer_index, MAX_PEER_DEVS);
		return UINT_MAX;
	}

	// no entry, no paths for given gpu index
	if (!gpu_bdf_map[gpu_index][0]) {
		#ifdef NVFS_PCI_DEBUG
		nvfs_dbg("%s :%u no path entry for gpu device index %u\n",
			__func__, __LINE__, gpu_index);
		#endif
		return UINT_MAX;
	}

	// no entry, no paths for given peer index
	if (!(peer_bdf_map[peer_index][0])) {
		#ifdef NVFS_PCI_DEBUG
		nvfs_dbg("%s :%u no path entry for peer device index %u\n",
			__func__, __LINE__, peer_index);
		#endif
		return UINT_MAX;
	}

	// scan gpu and peer paths to count number of downstream
	// bridges for both

	// top-down scan
	// 1. find highest bridge in gpu path
	// 2. also check for end point hinged directly without root port
	if (gpu_bdf_map[gpu_index][0] != PCI_NULL_DEV_NORP) {
		for (i = MAX_PCI_DEPTH - 1; i >= 0; i--) {
			if (!gpu_bdf_map[gpu_index][i]) {
				gdepth = i;
				continue;
			}
			pdevinfo = gpu_bdf_map[gpu_index][i];
			gdepth = i + 1;
			break;
		}
	} else {
		pdevinfo = PCI_NULL_DEV_NORP;
		gdepth = 0;
	}

	// gpu entry must exist (i >= 0)
	if (pdevinfo == 0) {
		nvfs_err("nvfs_pci: no path entry exists for gpu index, cannot perform "
			"p2p pci affinity calculation");
		return UINT_MAX;
	}

	// scan peer path
	// 1. bottom-up scan
	// 2. locate highest common bridge in gpu and peer paths
	if (peer_bdf_map[peer_index][0] != PCI_NULL_DEV_NORP) {
		for (j = 0; j < MAX_PCI_DEPTH; j++) {
			if (!peer_bdf_map[peer_index][j]) {
				pdepth = j;
				break;
			}
			if (pdevinfo == peer_bdf_map[peer_index][j]) {
				common = true;
				pdepth = j + 1;
				break;
			}
		}
	} else
		pdepth = 0;

	#ifdef NVFS_PCI_DEBUG
	nvfs_dbg("==>i=%u/%u j=%u/%u\n", i, gdepth, j, pdepth);
	#endif

	if (!common) {
		if (nvfs_gpu2peer_islocal(gpu_index, peer_index))
			pci_dist = (unsigned int)BASE_PCI_DISTANCE_CROSSRP + gdepth + pdepth + 1;
		else
			pci_dist = (unsigned int)(2 * BASE_PCI_DISTANCE_CROSSRP) + gdepth + pdepth + 1;
	} else {
		i_max = i;
		while (i >= 0 && j >= 0) {
			if (gpu_bdf_map[gpu_index][i] == peer_bdf_map[peer_index][j]) {
				lowest_common = i;
				i--; gdepth--;
				j--; pdepth--;
				pci_dist = (gdepth + pdepth) + 1;
				#ifdef NVFS_PCI_DEBUG
				nvfs_dbg("<===%u/%u j=%u/%u pci_dist=%u\n", i, gdepth, j, pdepth, pci_dist);
				#endif
				continue;
			}
			break; // got lowest common
		}

		// scan for common switch for acs redir.
		// We are assuming if is ACS is enabled here, it should be configured
		// for the complete upstream path.
		if ((lowest_common > 0) &&
			(nvfs_pdevinfo_get_acs(gpu_bdf_map[gpu_index][lowest_common]))) {
			pci_dist += (i_max - lowest_common);
			nvfs_dbg("overiding pci-distance with acs path length");
		}

		if (pci_dist > PROC_LIMIT_PCI_DISTANCE_COMMONRP)
			nvfs_warn("detected pci-distance more than proc limit :%u/%u",
				pci_dist, PROC_LIMIT_PCI_DISTANCE_COMMONRP);
	}

	nvfs_dbg("nvfs_pci: pci_dist matrix[gpu=%u][peer=%u] "PCI_INFO_FMT"->"PCI_INFO_FMT
		" pci_dist:%u\n", gpu_index, peer_index,
		PCI_INFO_ARGS(gpu_info_table[gpu_index]),
		PCI_INFO_ARGS(peer_info_table[peer_index]), pci_dist);
	return pci_dist;
}

/*
 *  Description: scans and fills all indices of distance matrix
 *  @params  : none
 *  @returns : none
 *  Notes    : This function should be invoked after all device arrays for paths
 *             have been populated.
 */
static void nvfs_get_pci_gpu2peer_distance(void) {
	unsigned int i, j;
	unsigned int rank;
	for (i = 0; i < MAX_GPU_DEVS; i++) {
		for (j = 0; j < MAX_PEER_DEVS; j++) {
			u64 peerinfo = nvfs_lookup_peer_hash_index_entry(j);
			u32 pci_dist = __nvfs_get_gpu2peer_distance(i, j);
			u32 bw = nvfs_pdevinfo_get_link_width(peerinfo) *
				nvfs_pdevinfo_get_link_speed(peerinfo);
			bw = min(bw, MAX_PCIE_BW_INDEX);
			// We give preference to the pci distance, than the bandwidth
			rank = (MAX_PCIE_BW_INDEX - bw) | (pci_dist << 16U);
			gpu_rank_matrix[i][j].rank = rank;
			gpu_rank_matrix[i][j].pci_dist = pci_dist;
			gpu_rank_matrix[i][j].bw_index = bw;
			gpu_rank_matrix[i][j].cross = (pci_dist >= BASE_PCI_DISTANCE_CROSSRP) ? 1 : 0;
			gpu_rank_matrix[i][j].count = 0;
		}
	}
}

/*
 *  Description: main function to create pci-distance matrix.
 *               The pci devices we are interested in are probed by class
 *               and a distance matrix is generated based on pci closeness.
 *  @params  : none
 *  @returns : none
 */
void nvfs_fill_gpu2peer_distance_table_once(void) {
	memset ((u8 *)gpu_bdf_map, 0, sizeof(gpu_bdf_map));
	memset ((u8 *)peer_bdf_map, 0, sizeof(peer_bdf_map));
	memset ((u8 *)gpu_info_table, 0, sizeof(gpu_info_table));
	memset ((u8 *)peer_info_table, 0, sizeof(peer_info_table));

	nvfs_dbg("nvfs listing GPU paths:\n");
	__nvfs_find_all_device_paths(gpu_bdf_map, MAX_GPU_DEVS, PCI_CLASS_DISPLAY_3D << 8);
	__nvfs_find_all_device_paths(gpu_bdf_map, MAX_GPU_DEVS, PCI_CLASS_DISPLAY_VGA << 8);

	nvfs_dbg("nvfs listing IB paths:\n");
	__nvfs_find_all_device_paths(peer_bdf_map, MAX_PEER_DEVS, PCI_CLASS_NETWORK_INFINIBAND << 8);
	__nvfs_find_all_device_paths(peer_bdf_map, MAX_PEER_DEVS, PCI_CLASS_NETWORK_ETHERNET << 8);

	nvfs_dbg("nvfs listing NVME paths:\n");
	__nvfs_find_all_device_paths(peer_bdf_map, MAX_PEER_DEVS, PCI_CLASS_STORAGE_EXPRESS);

	// compute distance matrix
	nvfs_get_pci_gpu2peer_distance();
}

/*
 *  Description: get pci distance between a GPU and the peer dma device
 *  @params  : struct device *, peer dma device
 *  @params  : gpu hash index
 *  @returns : rank i.e pci-distance
 */
unsigned int nvfs_get_gpu2peer_distance(struct device *dev, unsigned int gpu_index) {
	u64 peerdevinfo;
	unsigned int peer_index, rank;
	struct pci_dev *pdev = to_pci_dev(dev);

	if (!pdev || !pdev->bus)
		return UINT_MAX;

	peerdevinfo = nvfs_pdevinfo(pdev);
	if (unlikely(gpu_index >= MAX_GPU_DEVS)) {
		nvfs_err("nvfs_pci: invalid gpu index to distance func\n");
		return UINT_MAX;
	}

	peer_index = nvfs_get_peer_hash_index(peerdevinfo);
	if (unlikely(peer_index >= MAX_PEER_DEVS)) {
		nvfs_err("nvfs_pci: invalid peer device index to distance func\n");
		return UINT_MAX;
	}

	rank = gpu_rank_matrix[gpu_index][peer_index].rank;
	#ifdef NVFS_PCI_DEBUG
	nvfs_dbg("nvfs_get_gpu2peer_distance "PCI_INFO_FMT"(%u)->"PCI_INFO_FMT
		"(%u) rank :%u\n",
		PCI_INFO_ARGS(gpu_info_table[gpu_index]), gpu_index,
		PCI_INFO_ARGS(peer_info_table[peer_index]), peer_index, rank);
	#endif
	return rank;
}

/*
 *  Description: updates peer usage count for a gpu
 *  @params  : gpu hash index
 *  @params  : peer device bdf
 *  TBD : use atomic_inc
 */
void nvfs_update_peer_usage(unsigned int gpu_index, u64 peer_pdevinfo) {
	unsigned int peer_index = nvfs_get_peer_hash_index(peer_pdevinfo);
	if (unlikely((gpu_index >= MAX_GPU_DEVS) || (peer_index >= MAX_PEER_DEVS))) {
		#ifdef NVFS_PCI_DEBUG
		nvfs_warn("nvfs_pci: invalid lookup index, gpu_index=%u:peer_index=%u",
			gpu_index, peer_index);
		#endif
	} else {
		gpu_rank_matrix[gpu_index][peer_index].count++;
		#ifdef NVFS_PCI_DEBUG
		nvfs_dbg("nvfs_pci: peer hit count [gpu_index=%u : peer_index=%u] %llu",
			gpu_index, peer_index, gpu_rank_matrix[gpu_index][peer_index].count);
		#endif
	}
}

/*
 *  Description: get total number of dma operations between a gpu and all its peers
 *      which are at given `pci-dist` away
 *  @params  : gpu hash index
 *  @params  : distance to match
 *  @returns : count
 */
uint64_t nvfs_aggregate_peer_usage_by_distance(unsigned int gpu_index, unsigned int pci_dist) {
	unsigned int i;
	uint64_t count = 0;
	if (unlikely(gpu_index >= MAX_GPU_DEVS)) {
		nvfs_err("nvfs_pci: invalid lookup index %u", gpu_index);
	} else if (unlikely(pci_dist >= BASE_PCI_DISTANCE_CROSSRP)) {
		for (i = 0; i < MAX_PEER_DEVS; i++) {
			if (gpu_rank_matrix[gpu_index][i].pci_dist >= pci_dist) {
				count += gpu_rank_matrix[gpu_index][i].count;
				#ifdef NVFS_PCI_DEBUG
				nvfs_dbg("nvfs_pci: rank no %u peer hit [%u:%u] %llu",
					rank, gpu_index, i, gpu_rank_matrix[gpu_index][i].count);
				#endif
			}
		}
	} else {
		for (i = 0; i < MAX_PEER_DEVS; i++) {
			if (gpu_rank_matrix[gpu_index][i].pci_dist == pci_dist) {
				count += gpu_rank_matrix[gpu_index][i].count;
				#ifdef NVFS_PCI_DEBUG
				nvfs_dbg("nvfs_pci: rank no %u peer hit [%u:%u] %llu",
					rank, gpu_index, i, gpu_rank_matrix[gpu_index][i].count);
				#endif
			}
		}
	}
	return count;
}

/*
 *  Description: calculate overall percentage of cross node operations for a gpu
 *  @params  : gpu hash index
 *  @returns : percentage of cross traffic
 */
unsigned int nvfs_aggregate_cross_peer_usage(unsigned int gpu_index) {
	int i;
	uint64_t count = 0, net = 0;
	if (unlikely(gpu_index >= MAX_GPU_DEVS)) {
		nvfs_err("nvfs_pci: invalid lookup index %u", gpu_index);
	} else {
		for (i = 0; i < MAX_PEER_DEVS; i++) {
			net += gpu_rank_matrix[gpu_index][i].count;
			if (gpu_rank_matrix[gpu_index][i].cross) {
				count += gpu_rank_matrix[gpu_index][i].count;
				#ifdef NVFS_PCI_DEBUG
				nvfs_dbg("nvfs_pci: rank no %u cross peer hit "
					"[gpu_index=%u:peer_index=%u] %llu",
					gpu_rank_matrix[gpu_index][i].rank, gpu_index, i,
					gpu_rank_matrix[gpu_index][i].count);
				#endif
			}
		}
	}
	#ifdef NVFS_PCI_DEBUG
	nvfs_dbg("%s : %llu/%llu", __func__, count, net);
	#endif
	return net ? (100 * count)/net : 0;
}

/*
 *  Description: reset all IO counts between gpus and its peers
 *  @returns :
 */
void nvfs_reset_peer_affinity_stats(void) {
	unsigned int i, j;

	for (i = 0; i < MAX_GPU_DEVS; i++) {
		for (j = 0; j < MAX_PEER_DEVS; j++)
			gpu_rank_matrix[i][j].count = 0;
	}
}

/*
 *  Description : proc function to show gpu2peer distance map
 *  @returns    : always 0
 *  Note        : The output format has a dependency on user-space library (cufile-driver).
 *                Changes here will therefore require to update the driver major
 *                version and also the major-version of the user-space library
 */
int nvfs_peer_distance_show(struct seq_file *m, void *data) {
	unsigned int i, j;

	seq_printf(m, "gpu\t\tpeer\t\tpeerrank\tp2pdist\tlink\tgen\tnuma\tnp2p\tclass\n");
	for (i = 0; i < MAX_GPU_DEVS; i++) {
		u64 pdevinfo = nvfs_lookup_gpu_hash_index_entry(i);
		if (!pdevinfo)
			continue;

		for (j = 0; j < MAX_PEER_DEVS; j++) {
			u64 peerinfo = nvfs_lookup_peer_hash_index_entry(j);
			if (!peerinfo)
				continue;
			seq_printf(m, PCI_INFO_FMT"\t"PCI_INFO_FMT"\t0x%08x\t0x%04x\t0x%02x\t0x%02x\t0x%02x\t%llu\t%s\n",
				PCI_INFO_ARGS(pdevinfo),
				PCI_INFO_ARGS(peerinfo),
				gpu_rank_matrix[i][j].rank,
				gpu_rank_matrix[i][j].pci_dist,
				nvfs_pdevinfo_get_link_width(peerinfo),
				nvfs_pdevinfo_get_link_speed(peerinfo),
				nvfs_get_numa_node_from_pdevinfo(peerinfo),
				gpu_rank_matrix[i][j].count,
				nvfs_pdevinfo_get_class_name(peerinfo));
		}
	}
	return 0;
}

/*
 *  Description: proc function to show p2p distribution based on pci-distance
 *  @returns   : always 0
 */
int nvfs_peer_affinity_show(struct seq_file *m, void *v)
{
	unsigned int i, j;

	if (!nvfs_peer_stats_enabled)
		return 0;

	seq_printf(m, "GPU P2P DMA distribution based on pci-distance\n\n");
	seq_printf(m, "(last column indicates p2p via root complex)\n");
	for (i = 0; i < MAX_GPU_DEVS; i++) {
		u64 pdevinfo = nvfs_lookup_gpu_hash_index_entry(i);
		if (!pdevinfo)
			continue;
		seq_printf(m, "GPU :"PCI_INFO_FMT":", PCI_INFO_ARGS(pdevinfo));
		for (j = 1; j <= PROC_LIMIT_PCI_DISTANCE_COMMONRP; j++) {
			seq_printf(m, "%llu ", nvfs_aggregate_peer_usage_by_distance(i, j));
		}
		// cross root port
		seq_printf(m, "%llu\n",
			nvfs_aggregate_peer_usage_by_distance(i, BASE_PCI_DISTANCE_CROSSRP));
	}
	return 0;
}
