# nvidia-fs 

GPUDirect Storage kernel driver to read/write data from supported storage using cufile APIs

## Overview 

GPUDirect Storage kernel driver nvidia-fs.ko is a kernel module to orchestrate IO directly from DMA/RDMA capable storage to user allocated GPU memory on NVIDIA Graphics cards.

Currently the driver supports following storage solutions.

- XFS and EXT4 filesystem in ordered mode on NVMe/NVMeOF/ScaleFlux CSD devices.
- NFS over RDMA with MOFED 5.1 and above 
- RDMA capable distributed filesystems like DDN Exascaler, WekaFS, and VAST.
- ScaleFlux Computational storage

For more details on using GPUDirect Storage please visit https://docs.nvidia.com/gpudirect-storage/index.html
GDS documents and online resources provide additional context for the optimal use of and understanding of GPUDirect Storage.

## Requirements
 - NVIDIA Tesla or Quadro class GPUs based on Pascal, Volta, Turing or Ampere
 - NVMe/NVMeOF storage devices or supported distributed filesystem
 - Linux kernel between 4.15.0.x and above 
 - MOFED 5.1 or above
 - cuda toolkit 10.0 and above
 - GPU display driver >= 418.40

## Build and installation

```shell
 $ cd src
 $ export CONFIG_MOFED_VERSION=$(ofed_info -s | cut -d '-' -f 2)
 $ sudo make
 $ sudo insmod nvidia-fs.ko
```
