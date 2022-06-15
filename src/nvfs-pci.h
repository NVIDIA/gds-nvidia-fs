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

#ifndef __NVFS_PCI_H_
#define __NVFS_PCI_H_

#include <linux/pci.h>
#include <asm/pci.h>

// User space has a dependency on device class names
#define PCI_NVME_CLASS_NAME "nvme"

#define PCI_NETWORK_CLASS_NAME "network"

// User space has a parsing dependency on this format string
// Note: please do not change this
#define PCI_INFO_FMT  "%04x:%02x:%02x.%u "

#define PCI_INFO_ARGS(pci_info) \
	(uint32_t)((uint64_t)(pci_info) >> 32), \
	((uint16_t)(pci_info) >> 8), PCI_SLOT((uint8_t)(pci_info)), PCI_FUNC((uint8_t)(pci_info))

#define MAX_GPU_DEVS    64U // On DGX-2, 16 GPUS

#define MAX_PEER_DEVS   64U // On DGX-2, 8 IB Ports

#define MAX_PCI_DEPTH   16U // On DGX-2, max-depth 5

// proc limit for pci distance under same Port
#define PROC_LIMIT_PCI_DISTANCE_COMMONRP (2 * MAX_PCI_DEPTH)

// minimum distance applied where nodes cross RP
#define BASE_PCI_DISTANCE_CROSSRP S8_MAX

// special case for null entry for pci paths without root port
#define PCI_NULL_DEV_NORP (UINT_MAX - 1)

// device classes probed by nvidia-fs for generating pci-distance matrix
#define PCI_CLASS_NETWORK_INFINIBAND 0x207

#define PCI_DEV_GPU(class, vendor) \
	(((vendor) == PCI_VENDOR_ID_NVIDIA) && \
	 (((class) == PCI_CLASS_DISPLAY_VGA) || \
	  (((class) == PCI_CLASS_DISPLAY_3D))))

#define PCI_DEV_IB(class) \
	((((class) == PCI_CLASS_NETWORK_ETHERNET) || \
	  (((class) == PCI_CLASS_NETWORK_INFINIBAND))))

#define PCI_DEV_NVME(class) \
	((class) == PCI_CLASS_STORAGE_EXPRESS)

//acs info bit for pdevinfo
#define NVFS_PDEVINFO_ACS_CHECK_BIT 16

//class info bit for pdevinfo
#define NVFS_PDEVINFO_NVME_CHECK_BIT 17

#define NVFS_PDEVINFO_NET_CHECK_BIT  18

//nibble for storing pci link speed idx (refer link speed LUT)
#define NVFS_PDEVINFO_LNKSPEED_BIT  24

//nibble for storing pci link width idx (refer link width LUT)
#define NVFS_PDEVINFO_LNKWIDTH_BIT  28

// clear mask for pdevinfo info fields
#define NVFS_PDEVINFO_INFO_MASK ~(0xFFFF0000ULL)

#define MAX_LNKSPEED_ENTRIES 16U

#define MAX_LNKWIDTH_ENTRIES 16U

extern const unsigned char nvfs_pcie_link_speed_table[MAX_LNKSPEED_ENTRIES];

extern const unsigned char nvfs_pcie_link_width_table[MAX_LNKWIDTH_ENTRIES];

// combines domain, bus, device, function to uint64_t
static inline uint64_t nvfs_pdevinfo(struct pci_dev *pdev) {
	uint64_t pdevinfo = 0;
	if (pdev->bus) {
		pdevinfo |= (uint32_t)pci_domain_nr(pdev->bus);
		pdevinfo <<= 32;
		pdevinfo |= PCI_DEVID(pdev->bus->number, pdev->devfn);
	} else
		pdevinfo |= PCI_DEVID(0, pdev->devfn);
	return pdevinfo;
}

static inline uint64_t nvfs_bdf2pdevinfo(int dom, int bus, int dev, int func) {
	uint64_t pdevinfo = 0;
	pdevinfo |= (uint32_t)dom;
	pdevinfo <<= 32;
	pdevinfo |= (bus << 8U);
	pdevinfo |= ((dev << 3U) | func);
	return pdevinfo;
}

// embed ACS info to pdevinfo
static inline void nvfs_pdevinfo_set_acs(uint64_t *pdevinfo) {
	*pdevinfo |= (1ULL << NVFS_PDEVINFO_ACS_CHECK_BIT);
}

static inline bool nvfs_pdevinfo_get_acs(uint64_t pdevinfo) {
	return pdevinfo & (1ULL << NVFS_PDEVINFO_ACS_CHECK_BIT);
}

// embed class info to pdevinfo
static inline void nvfs_pdevinfo_set_class(uint64_t *pdevinfo, unsigned int dev_class) {
	if (PCI_DEV_IB(dev_class >> 8))
		*pdevinfo |= (1ULL << NVFS_PDEVINFO_NET_CHECK_BIT);
	else if (PCI_DEV_NVME(dev_class))
		*pdevinfo |= (1ULL << NVFS_PDEVINFO_NVME_CHECK_BIT);
	else {
		pr_err("unsupported device class :0x%x\n", dev_class);
	}
}

static inline const char* nvfs_pdevinfo_get_class_name(uint64_t pdevinfo) {
	if (pdevinfo & (1ULL << NVFS_PDEVINFO_NET_CHECK_BIT))
		return PCI_NETWORK_CLASS_NAME;
	else if (pdevinfo & (1ULL << NVFS_PDEVINFO_NVME_CHECK_BIT))
		return PCI_NVME_CLASS_NAME;
	else
		return "x";
}

// embed device link speed to pdevinfo
// note : from spec, link_speed cannot be greater than a nibble
static inline void nvfs_pdevinfo_set_link_speed(uint64_t *pdevinfo,
                                                enum pci_bus_speed link_speed) {
    size_t i = 0;
    size_t speed_idx = 0;

    for (i = 0; i < MAX_LNKWIDTH_ENTRIES; i++) {
        if (link_speed == nvfs_pcie_link_speed_table[i]) {
            speed_idx = i;
            speed_idx <<= (NVFS_PDEVINFO_LNKSPEED_BIT - 1);
            *pdevinfo |= speed_idx;
            break;
        }
    }
}

static inline u32 nvfs_pdevinfo_get_link_speed(uint64_t pdevinfo) {
    uint32_t speed = (uint32_t) pdevinfo;
    speed >>= (NVFS_PDEVINFO_LNKSPEED_BIT - 1);
    speed &= 0x0fU;
    return speed;
}

// embed device link width to pdevinfo
// note: from spec, link_width can be greater than a nibble.
// So use an index for storing attribute for link width
static inline void nvfs_pdevinfo_set_link_width(uint64_t *pdevinfo,
                                                enum pcie_link_width link_width) {
    size_t i = 0;
    uint64_t width_idx = 0;
    for (i = 0; i < MAX_LNKWIDTH_ENTRIES; i++) {
        if (link_width == nvfs_pcie_link_width_table[i]) {
            width_idx = i;
            width_idx <<= (NVFS_PDEVINFO_LNKWIDTH_BIT - 1);
            *pdevinfo |= width_idx;
            break;
        }
    }
}

static inline u32 nvfs_pdevinfo_get_link_width(uint64_t pdevinfo) {
    uint32_t width_idx = (uint32_t) pdevinfo, width = 0;
    width_idx >>= (NVFS_PDEVINFO_LNKWIDTH_BIT - 1);
    width_idx &= 0x0fU;
    width = (u32) nvfs_pcie_link_width_table[width_idx];
    return width;
}

static inline struct pci_dev *nvfs_get_pdev_from_pdevinfo(uint64_t pdevinfo) {
	int domain, bus, devfn;

	pdevinfo &= NVFS_PDEVINFO_INFO_MASK;
	domain = (int)((uint64_t)(pdevinfo) >> 32);
	bus    = (int)((uint32_t)(pdevinfo) >> 8);
	devfn  = (int)((uint8_t) (pdevinfo) & 0xFF);
	return pci_get_domain_bus_and_slot(domain, bus, devfn);
}

// get numa node associated with a pci device
static inline int nvfs_get_numa_node_from_pdevinfo(uint64_t pdevinfo) {
	int node = -1;
	struct pci_dev *pdev;
	pdev = nvfs_get_pdev_from_pdevinfo(pdevinfo);
	if (pdev) {
		node = pcibus_to_node(pdev->bus);
		pci_dev_put(pdev);
	}
	return node;
}

struct pci_dev *nvfs_get_next_acs_device(struct pci_dev *from);

// one-time pci-distance table initialization
void nvfs_fill_gpu2peer_distance_table_once(void);

// get hash-key for gpu pciinfo
unsigned int nvfs_get_gpu_hash_index(u64 pdevinfo);

// get gpu pci info for hash-key
uint64_t nvfs_lookup_gpu_hash_index_entry(unsigned int index);

// get gpu p2p info for hash-key
uint64_t nvfs_lookup_peer_hash_index_entry(unsigned int index);

// return pci-distance between a gpu(hash-key) and peer dma source
unsigned int nvfs_get_gpu2peer_distance(struct device *dev, unsigned int gpuindex);

// stats
void nvfs_update_peer_usage(unsigned int gpu_index, u64 peer_pdevinfo);

unsigned int nvfs_aggregate_cross_peer_usage(unsigned int gpu_index);

void nvfs_reset_peer_affinity_stats(void);

int nvfs_peer_distance_show(struct seq_file *m, void *v);

int nvfs_peer_affinity_show(struct seq_file *m, void *v);
#endif
