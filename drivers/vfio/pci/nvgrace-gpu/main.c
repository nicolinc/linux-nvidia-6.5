// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES. All rights reserved
 */

#include <linux/pci.h>
#include <linux/vfio_pci_core.h>
#include <linux/vfio.h>

/* Memory size expected as non cached and reserved by the VM driver */
#define RESMEM_SIZE 0x40000000
#define MEMBLK_SIZE 0x20000000

struct mem_region {
	phys_addr_t memphys; /* Base address of the region */
	size_t memlength;    /* Region size */
	u32 bar_regs[2];     /* Emulated BAR offset registers */
	void *memmap;        /* Memremap pointer to the region */
};

struct nvgrace_gpu_vfio_pci_core_device {
	struct vfio_pci_core_device core_device;
	/* Cached and usable memory for the VM. */
	struct mem_region usemem;
	/* Non cached memory carved out from the end of device memory */
	struct mem_region resmem;
	struct mutex memmap_lock;
};

/* Choose the structure corresponding to the BAR under question. */
static int nvgrace_gpu_vfio_pci_get_mem_region(int index,
		struct nvgrace_gpu_vfio_pci_core_device *nvdev,
		struct mem_region *region)
{
	if (index == VFIO_PCI_BAR4_REGION_INDEX)
		*region = nvdev->usemem;
	else if (index == VFIO_PCI_BAR2_REGION_INDEX)
		*region = nvdev->resmem;
	else
		return -EINVAL;

	return 0;
}

static bool nvgrace_gpu_vfio_pci_is_fake_bar(int index)
{
	if (index == VFIO_PCI_BAR2_REGION_INDEX ||
	    index == VFIO_PCI_BAR4_REGION_INDEX)
		return true;

	return false;
}

static void init_fake_bar_emu_regs(struct vfio_device *core_vdev)
{
	struct nvgrace_gpu_vfio_pci_core_device *nvdev = container_of(
		core_vdev, struct nvgrace_gpu_vfio_pci_core_device,
		core_device.vdev);

	nvdev->resmem.bar_regs[0] = PCI_BASE_ADDRESS_MEM_TYPE_64 |
				    PCI_BASE_ADDRESS_MEM_PREFETCH;
	nvdev->resmem.bar_regs[1] = 0;
	nvdev->usemem.bar_regs[0] = PCI_BASE_ADDRESS_MEM_TYPE_64 |
				    PCI_BASE_ADDRESS_MEM_PREFETCH;
	nvdev->usemem.bar_regs[1] = 0;
}

static bool is_fake_bar_pcicfg_emu_reg_access(loff_t pos)
{
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(pos);
	u64 offset = pos & VFIO_PCI_OFFSET_MASK;

	if ((index == VFIO_PCI_CONFIG_REGION_INDEX) &&
	    (offset >= PCI_BASE_ADDRESS_2 && offset <= PCI_BASE_ADDRESS_5))
		return true;

	return false;
}

static int nvgrace_gpu_vfio_pci_open_device(struct vfio_device *core_vdev)
{
	struct vfio_pci_core_device *vdev =
		container_of(core_vdev, struct vfio_pci_core_device, vdev);
	struct nvgrace_gpu_vfio_pci_core_device *nvdev = container_of(
		core_vdev, struct nvgrace_gpu_vfio_pci_core_device,
		core_device.vdev);
	int ret;

	ret = vfio_pci_core_enable(vdev);
	if (ret)
		return ret;

	vfio_pci_core_finish_enable(vdev);

	init_fake_bar_emu_regs(core_vdev);

	mutex_init(&nvdev->memmap_lock);

	return 0;
}

static void nvgrace_gpu_vfio_pci_close_device(struct vfio_device *core_vdev)
{
	struct nvgrace_gpu_vfio_pci_core_device *nvdev = container_of(
		core_vdev, struct nvgrace_gpu_vfio_pci_core_device,
		core_device.vdev);

	if (nvdev->usemem.memmap) {
		memunmap(nvdev->usemem.memmap);
		nvdev->usemem.memmap = NULL;
	}

	mutex_destroy(&nvdev->memmap_lock);

	vfio_pci_core_close_device(core_vdev);
}

static int nvgrace_gpu_vfio_pci_mmap(struct vfio_device *core_vdev,
				     struct vm_area_struct *vma)
{
	struct nvgrace_gpu_vfio_pci_core_device *nvdev = container_of(
		core_vdev, struct nvgrace_gpu_vfio_pci_core_device, core_device.vdev);

	unsigned long start_pfn;
	unsigned int index;
	u64 req_len, pgoff, end;
	int ret = 0;
	struct mem_region memregion;

	index = vma->vm_pgoff >> (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT);

	if (!nvgrace_gpu_vfio_pci_is_fake_bar(index))
		return vfio_pci_core_mmap(core_vdev, vma);

	ret = nvgrace_gpu_vfio_pci_get_mem_region(index, nvdev, &memregion);
	if (ret)
		return ret;

	/*
	 * Request to mmap the BAR. Map to the CPU accessible memory on the
	 * GPU using the memory information gathered from the system ACPI
	 * tables.
	 */
	pgoff = vma->vm_pgoff &
		((1U << (VFIO_PCI_OFFSET_SHIFT - PAGE_SHIFT)) - 1);

	if (check_sub_overflow(vma->vm_end, vma->vm_start, &req_len) ||
		check_add_overflow(PHYS_PFN(memregion.memphys), pgoff, &start_pfn) ||
		check_add_overflow(PFN_PHYS(pgoff), req_len, &end))
		return -EOVERFLOW;

	/*
	 * Check that the mapping request does not go beyond available device
	 * memory size
	 */
	if (end > memregion.memlength)
		return -EINVAL;

	/*
	 * The carved out region of the device memory needs the NORMAL_NC
	 * property. Communicate as such to the hypervisor.
	 */
	if (index == VFIO_PCI_BAR2_REGION_INDEX)
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	/*
	 * Perform a PFN map to the memory and back the device BAR by the
	 * GPU memory.
	 *
	 * The available GPU memory size may not be power-of-2 aligned. Map up
	 * to the size of the device memory. If the memory access is beyond the
	 * actual GPU memory size, it will be handled by the vfio_device_ops
	 * read/write.
	 *
	 * During device reset, the GPU is safely disconnected to the CPU
	 * and access to the BAR will be immediately returned preventing
	 * machine check.
	 */
	ret = remap_pfn_range(vma, vma->vm_start, start_pfn,
			      req_len, vma->vm_page_prot);
	if (ret)
		return ret;

	vma->vm_pgoff = start_pfn;

	return 0;
}

static long
nvgrace_gpu_vfio_pci_ioctl_get_region_info(struct vfio_device *core_vdev,
					    unsigned long arg)
{
	unsigned long minsz = offsetofend(struct vfio_region_info, offset);
	struct nvgrace_gpu_vfio_pci_core_device *nvdev = container_of(
		core_vdev, struct nvgrace_gpu_vfio_pci_core_device, core_device.vdev);
	struct vfio_region_info_cap_sparse_mmap *sparse;
	struct vfio_info_cap caps = { .buf = NULL, .size = 0 };
	struct vfio_region_info info;
	struct mem_region memregion;
	uint32_t size;
	int ret;

	if (copy_from_user(&info, (void __user *)arg, minsz))
		return -EFAULT;

	if (info.argsz < minsz)
		return -EINVAL;

	if (nvgrace_gpu_vfio_pci_is_fake_bar(info.index)) {
		ret = nvgrace_gpu_vfio_pci_get_mem_region(info.index, nvdev, &memregion);
		if (ret)
			return ret;
		/*
		 * Request to determine the BAR region information. Send the
		 * GPU memory information.
		 */
		size = struct_size(sparse, areas, 1);

		/*
		 * Setup for sparse mapping for the device memory. Only the
		 * available device memory on the hardware is shown as a
		 * mappable region.
		 */
		sparse = kzalloc(size, GFP_KERNEL);
		if (!sparse)
			return -ENOMEM;

		sparse->nr_areas = 1;
		sparse->areas[0].offset = 0;
		sparse->areas[0].size = memregion.memlength;
		sparse->header.id = VFIO_REGION_INFO_CAP_SPARSE_MMAP;
		sparse->header.version = 1;

		ret = vfio_info_add_capability(&caps, &sparse->header, size);
		kfree(sparse);
		if (ret)
			return ret;

		info.offset = VFIO_PCI_INDEX_TO_OFFSET(info.index);
		/*
		 * The available GPU memory size may not be power-of-2 aligned.
		 * Given that the memory is exposed as a BAR and may not be
		 * aligned, roundup to the next power-of-2.
		 */
		info.size = roundup_pow_of_two(memregion.memlength);
		info.flags = VFIO_REGION_INFO_FLAG_READ |
			VFIO_REGION_INFO_FLAG_WRITE |
			VFIO_REGION_INFO_FLAG_MMAP;

		if (caps.size) {
			info.flags |= VFIO_REGION_INFO_FLAG_CAPS;
			if (info.argsz < sizeof(info) + caps.size) {
				info.argsz = sizeof(info) + caps.size;
				info.cap_offset = 0;
			} else {
				vfio_info_cap_shift(&caps, sizeof(info));
				if (copy_to_user((void __user *)arg +
						 sizeof(info), caps.buf,
						 caps.size)) {
					kfree(caps.buf);
					return -EFAULT;
				}
				info.cap_offset = sizeof(info);
			}
			kfree(caps.buf);
		}
		return copy_to_user((void __user *)arg, &info, minsz) ?
				    -EFAULT : 0;
	}
	return vfio_pci_core_ioctl(core_vdev, VFIO_DEVICE_GET_REGION_INFO, arg);
}

static long nvgrace_gpu_vfio_pci_ioctl(struct vfio_device *core_vdev,
					unsigned int cmd, unsigned long arg)
{
	if (cmd == VFIO_DEVICE_GET_REGION_INFO)
		return nvgrace_gpu_vfio_pci_ioctl_get_region_info(core_vdev, arg);

	if (cmd == VFIO_DEVICE_RESET)
		init_fake_bar_emu_regs(core_vdev);

	return vfio_pci_core_ioctl(core_vdev, cmd, arg);
}

static int nvgrace_gpu_memmap(struct nvgrace_gpu_vfio_pci_core_device *nvdev,
			      struct mem_region *memregion)
{
	mutex_lock(&nvdev->memmap_lock);
	if (!memregion->memmap) {
		memregion->memmap = memremap(memregion->memphys, memregion->memlength, MEMREMAP_WB);
		if (!memregion->memmap) {
			mutex_unlock(&nvdev->memmap_lock);
			return -ENOMEM;
		}
	}
	mutex_unlock(&nvdev->memmap_lock);

	return 0;
}

/*
 * Read count bytes from the device memory at an offset. The actual device
 * memory size (available) may not be a power-of-2. So the driver fakes
 * the size to a power-of-2 (reported) when exposing to a user space driver.
 *
 * Read request beyond the actual device size is filled with ~0, while
 * those beyond the actual reported size is skipped.
 *
 * A read from a negative or an offset greater than reported size, a negative
 * count are considered error conditions and returned with an -EINVAL.
 */
static ssize_t
nvgrace_gpu_read_mem(void __user *buf, size_t count, loff_t *ppos,
		     struct mem_region memregion)
{
	u64 offset = *ppos & VFIO_PCI_OFFSET_MASK;
	size_t mem_count, i, bar_size = roundup_pow_of_two(memregion.memlength);
	u8 val = 0xFF;

	if (offset >= bar_size)
		return -EINVAL;

	/* Clip short the read request beyond reported BAR size */
	count = min(count, bar_size - (size_t)offset);

	/*
	 * Determine how many bytes to be actually read from the device memory.
	 * Read request beyond the actual device memory size is filled with ~0,
	 * while those beyond the actual reported size is skipped.
	 */
	if (offset >= memregion.memlength)
		mem_count = 0;
	else
		mem_count = min(count, memregion.memlength - (size_t)offset);

	/*
	 * Handle read on the BAR2 region. Map to the target device memory
	 * physical address and copy to the request read buffer.
	 */
	if (copy_to_user(buf, (u8 *)memregion.memmap + offset, mem_count))
		return -EFAULT;

	/*
	 * Only the device memory present on the hardware is mapped, which may
	 * not be power-of-2 aligned. A read to an offset beyond the device memory
	 * size is filled with ~0.
	 */
	for (i = mem_count; i < count; i++)
		put_user(val, (unsigned char __user *)(buf + i));

	*ppos += count;
	return count;
}

static ssize_t pcibar_read_emu(struct nvgrace_gpu_vfio_pci_core_device *nvdev,
				char __user *buf, size_t count, loff_t *ppos)
{
	u64 pos = *ppos & VFIO_PCI_OFFSET_MASK;
	u32 val;

	if (!IS_ALIGNED(pos, 4) || !(is_fake_bar_pcicfg_emu_reg_access(*ppos)))
		return -EINVAL;

	switch (pos) {
	case PCI_BASE_ADDRESS_2:
		val = nvdev->resmem.bar_regs[0];
		break;
	case PCI_BASE_ADDRESS_3:
		val = nvdev->resmem.bar_regs[1];
		break;
	case PCI_BASE_ADDRESS_4:
		val = nvdev->usemem.bar_regs[0];
		break;
	case PCI_BASE_ADDRESS_5:
		val = nvdev->usemem.bar_regs[1];
		break;
	}

	if (copy_to_user(buf, &val, count))
		return -EFAULT;

	*ppos += count;
	return count;
}

static ssize_t nvgrace_gpu_vfio_pci_read(struct vfio_device *core_vdev,
					  char __user *buf, size_t count, loff_t *ppos)
{
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	struct nvgrace_gpu_vfio_pci_core_device *nvdev = container_of(
		core_vdev, struct nvgrace_gpu_vfio_pci_core_device,
		core_device.vdev);
	struct mem_region memregion;
	int ret;

	if (nvgrace_gpu_vfio_pci_is_fake_bar(index)) {
		ret = nvgrace_gpu_vfio_pci_get_mem_region(index, nvdev, &memregion);
		if (ret)
			return ret;

		ret = nvgrace_gpu_memmap(nvdev, &memregion);
		if (ret)
			return ret;

		return nvgrace_gpu_read_mem(buf, count, ppos, memregion);
	}

	if (is_fake_bar_pcicfg_emu_reg_access(*ppos))
		return pcibar_read_emu(nvdev, buf, count, ppos);

	return vfio_pci_core_read(core_vdev, buf, count, ppos);
}

/*
 * Write count bytes to the device memory at a given offset. The actual device
 * memory size (available) may not be a power-of-2. So the driver fakes the
 * size to a power-of-2 (reported) when exposing to a user space driver.
 *
 * Write request beyond the actual device size are dropped, while those
 * beyond the actual reported size are skipped entirely.
 *
 * A write to a negative or an offset greater than the reported size, a
 * negative count are considered error conditions and returned with an -EINVAL.
 */
static ssize_t
nvgrace_gpu_write_mem(size_t count, loff_t *ppos, const void __user *buf,
		      struct mem_region memregion)
{
	u64 offset = *ppos & VFIO_PCI_OFFSET_MASK;
	size_t mem_count, bar_size = roundup_pow_of_two(memregion.memlength);

	if (offset >= bar_size)
		return -EINVAL;

	/* Clip short the write request beyond reported BAR size */
	count = min(count, bar_size - (size_t)offset);

	/*
	 * Determine how many bytes to be actually written to the device memory.
	 * Do not write to the offset beyond available size.
	 */
	if (offset >= memregion.memlength)
		goto exitfn;

	mem_count = min(count, memregion.memlength - (size_t)offset);

	/*
	 * Only the device memory present on the hardware is mapped, which may
	 * not be power-of-2 aligned. A write to the BAR2 region implies an
	 * access outside the available device memory on the hardware. Drop
	 * those write requests.
	 */
	if (copy_from_user((u8 *)memregion.memmap + offset, buf, mem_count))
		return -EFAULT;

exitfn:
	*ppos += count;
	return count;
}

static ssize_t pcibar_write_emu(struct nvgrace_gpu_vfio_pci_core_device *nvdev,
				 const char __user *buf, size_t count, loff_t *ppos)
{
	u64 pos = *ppos & VFIO_PCI_OFFSET_MASK;
	u64 size;
	u32 val;

	if (!IS_ALIGNED(pos, 4) || !(is_fake_bar_pcicfg_emu_reg_access(*ppos)))
		return -EINVAL;

	if (copy_from_user(&val, buf, count))
		return -EFAULT;

	if (val == 0xffffffff) {
		switch (pos) {
		case PCI_BASE_ADDRESS_2:
			size = ~(roundup_pow_of_two(nvdev->resmem.memlength) - 1);
			nvdev->resmem.bar_regs[0] = (size & GENMASK(31, 4)) |
				(nvdev->resmem.bar_regs[0] & GENMASK(3, 0));
			break;
		case PCI_BASE_ADDRESS_3:
			size = ~(roundup_pow_of_two(nvdev->resmem.memlength) - 1);
			nvdev->resmem.bar_regs[1] = size >> 32;
			break;
		case PCI_BASE_ADDRESS_4:
			size = ~(roundup_pow_of_two(nvdev->usemem.memlength) - 1);
			nvdev->usemem.bar_regs[0] = (size & GENMASK(31, 4)) |
				(nvdev->usemem.bar_regs[0] & GENMASK(3, 0));
			break;
		case PCI_BASE_ADDRESS_5:
			size = ~(roundup_pow_of_two(nvdev->usemem.memlength) - 1);
			nvdev->usemem.bar_regs[1] = size >> 32;
			break;
		}
	} else {
		switch (pos) {
		case PCI_BASE_ADDRESS_2:
			nvdev->resmem.bar_regs[0] = val;
			break;
		case PCI_BASE_ADDRESS_3:
			nvdev->resmem.bar_regs[1] = val;
			break;
		case PCI_BASE_ADDRESS_4:
			nvdev->usemem.bar_regs[0] = val;
			break;
		case PCI_BASE_ADDRESS_5:
			nvdev->usemem.bar_regs[1] = val;
			break;
		}
	}

	*ppos += count;
	return count;
}

static ssize_t nvgrace_gpu_vfio_pci_write(struct vfio_device *core_vdev,
					   const char __user *buf, size_t count, loff_t *ppos)
{
	unsigned int index = VFIO_PCI_OFFSET_TO_INDEX(*ppos);
	struct nvgrace_gpu_vfio_pci_core_device *nvdev = container_of(
		core_vdev, struct nvgrace_gpu_vfio_pci_core_device, core_device.vdev);
	struct mem_region memregion;
	int ret;

	if (nvgrace_gpu_vfio_pci_is_fake_bar(index)) {
		ret = nvgrace_gpu_vfio_pci_get_mem_region(index, nvdev, &memregion);
		if (ret)
			return ret;

		ret = nvgrace_gpu_memmap(nvdev, &memregion);
		if (ret)
			return ret;

		return nvgrace_gpu_write_mem(count, ppos, buf, memregion);
	}

	if (is_fake_bar_pcicfg_emu_reg_access(*ppos))
		return pcibar_write_emu(nvdev, buf, count, ppos);

	return vfio_pci_core_write(core_vdev, buf, count, ppos);
}

static const struct vfio_device_ops nvgrace_gpu_vfio_pci_ops = {
	.name = "nvgrace-gpu-vfio-pci",
	.init = vfio_pci_core_init_dev,
	.release = vfio_pci_core_release_dev,
	.open_device = nvgrace_gpu_vfio_pci_open_device,
	.close_device = nvgrace_gpu_vfio_pci_close_device,
	.ioctl = nvgrace_gpu_vfio_pci_ioctl,
	.read = nvgrace_gpu_vfio_pci_read,
	.write = nvgrace_gpu_vfio_pci_write,
	.mmap = nvgrace_gpu_vfio_pci_mmap,
	.request = vfio_pci_core_request,
	.match = vfio_pci_core_match,
	.bind_iommufd = vfio_iommufd_physical_bind,
	.unbind_iommufd = vfio_iommufd_physical_unbind,
	.attach_ioas = vfio_iommufd_physical_attach_ioas,
	.detach_ioas = vfio_iommufd_physical_detach_ioas,
};

static struct
nvgrace_gpu_vfio_pci_core_device *nvgrace_gpu_drvdata(struct pci_dev *pdev)
{
	struct vfio_pci_core_device *core_device = dev_get_drvdata(&pdev->dev);

	return container_of(core_device, struct nvgrace_gpu_vfio_pci_core_device,
			    core_device);
}

static int
nvgrace_gpu_vfio_pci_fetch_memory_property(struct pci_dev *pdev,
					    struct nvgrace_gpu_vfio_pci_core_device *nvdev)
{
	int ret;
	u64 memphys, memlength;

	/*
	 * The memory information is present in the system ACPI tables as DSD
	 * properties nvidia,gpu-mem-base-pa and nvidia,gpu-mem-size.
	 */
	ret = device_property_read_u64(&pdev->dev, "nvidia,gpu-mem-base-pa",
				       &(memphys));
	if (ret)
		return ret;

	if (memphys > type_max(phys_addr_t))
		return -EOVERFLOW;

	ret = device_property_read_u64(&pdev->dev, "nvidia,gpu-mem-size",
				       &(memlength));
	if (ret)
		return ret;

	if (memlength > type_max(size_t))
		return -EOVERFLOW;

	/*
	 * If the C2C link is not up due to an error, the coherent device
	 * memory size is returned as 0. Fail in such case.
	 */
	if (memlength == 0)
		return -ENOMEM;

	/*
	 * The VM GPU device driver needs a non-cacheable region to support
	 * the MIG feature. Since the device memory is mapped as NORMAL cached,
	 * carve out a region from the end with a different NORMAL_NC
	 * property (called as reserved memory and represented as resmem). This
	 * region then is exposed as a 64b BAR (region 2 and 3) to the VM, while
	 * exposing the rest (termed as usable memory and represented using usemem)
	 * as cacheable 64b BAR (region 4 and 5).
	 *
	 *               devmem (memlength)
	 * |-------------------------------------------------|
	 * |                                           |
	 * usemem.phys/memphys                         resmem.phys
	 */
	nvdev->usemem.memphys = memphys;

	/*
	 * The device memory exposed to the VM is added to the kernel by the
	 * VM driver module in chunks of memory block size. Only the usable
	 * memory (usemem) is added to the kernel for usage by the VM
	 * workloads. Make the usable memory size memblock aligned.
	 */
	if (check_sub_overflow(memlength, RESMEM_SIZE,
			       &nvdev->usemem.memlength)) {
		ret = -EOVERFLOW;
		goto done;
	}
	nvdev->usemem.memlength = round_down(nvdev->usemem.memlength,
					     MEMBLK_SIZE);
	if ((check_add_overflow(nvdev->usemem.memphys,
	     nvdev->usemem.memlength, &nvdev->resmem.memphys)) ||
	    (check_sub_overflow(memlength, nvdev->usemem.memlength,
	     &nvdev->resmem.memlength))) {
		ret = -EOVERFLOW;
		goto done;
	}

done:
	return ret;
}

static int nvgrace_gpu_vfio_pci_probe(struct pci_dev *pdev,
				       const struct pci_device_id *id)
{
	struct nvgrace_gpu_vfio_pci_core_device *nvdev;
	int ret;

	nvdev = vfio_alloc_device(nvgrace_gpu_vfio_pci_core_device, core_device.vdev,
				  &pdev->dev, &nvgrace_gpu_vfio_pci_ops);
	if (IS_ERR(nvdev))
		return PTR_ERR(nvdev);

	dev_set_drvdata(&pdev->dev, nvdev);

	ret = nvgrace_gpu_vfio_pci_fetch_memory_property(pdev, nvdev);
	if (ret)
		goto out_put_vdev;

	ret = vfio_pci_core_register_device(&nvdev->core_device);
	if (ret)
		goto out_put_vdev;

	return ret;

out_put_vdev:
	vfio_put_device(&nvdev->core_device.vdev);
	return ret;
}

static void nvgrace_gpu_vfio_pci_remove(struct pci_dev *pdev)
{
	struct nvgrace_gpu_vfio_pci_core_device *nvdev = nvgrace_gpu_drvdata(pdev);
	struct vfio_pci_core_device *vdev = &nvdev->core_device;

	vfio_pci_core_unregister_device(vdev);
	vfio_put_device(&vdev->vdev);
}

static const struct pci_device_id nvgrace_gpu_vfio_pci_table[] = {
	/* GH200 120GB */
	{ PCI_DRIVER_OVERRIDE_DEVICE_VFIO(PCI_VENDOR_ID_NVIDIA, 0x2342) },
	/* GH200 480GB */
	{ PCI_DRIVER_OVERRIDE_DEVICE_VFIO(PCI_VENDOR_ID_NVIDIA, 0x2345) },
	{}
};

MODULE_DEVICE_TABLE(pci, nvgrace_gpu_vfio_pci_table);

static struct pci_driver nvgrace_gpu_vfio_pci_driver = {
	.name = KBUILD_MODNAME,
	.id_table = nvgrace_gpu_vfio_pci_table,
	.probe = nvgrace_gpu_vfio_pci_probe,
	.remove = nvgrace_gpu_vfio_pci_remove,
	.err_handler = &vfio_pci_core_err_handlers,
	.driver_managed_dma = true,
};

module_pci_driver(nvgrace_gpu_vfio_pci_driver);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Ankit Agrawal <ankita@nvidia.com>");
MODULE_AUTHOR("Aniket Agashe <aniketa@nvidia.com>");
MODULE_DESCRIPTION(
	"VFIO NVGRACE GPU PF - User Level driver for NVIDIA devices with CPU coherently accessible device memory");
