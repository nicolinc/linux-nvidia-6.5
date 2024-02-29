// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2021-2024 TEGRA241 CORPORATION & AFFILIATES */

#define dev_fmt(fmt) "tegra241_cmdqv: " fmt

#include <linux/acpi.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/iommu.h>
#include <linux/iopoll.h>
#include <linux/kvm_host.h>
#include <linux/platform_device.h>
#include <linux/vfio.h>
#include <uapi/linux/iommufd.h>
// FIXME should drop them
#include <linux/iommufd.h>
#include "../../iommufd/iommufd_private.h"

#include <acpi/acpixf.h>

#include "arm-smmu-v3.h"

#define TEGRA241_CMDQV_HID		"NVDA200C"

/* CMDQV register page base and size defines */
#define TEGRA241_CMDQV_CONFIG_BASE	(0)
#define TEGRA241_CMDQV_CONFIG_SIZE	(SZ_64K)
#define TEGRA241_VCMDQ_PAGE0_BASE	(TEGRA241_CMDQV_CONFIG_BASE + SZ_64K)
#define TEGRA241_VCMDQ_PAGE1_BASE	(TEGRA241_VCMDQ_PAGE0_BASE + SZ_64K)
#define TEGRA241_VINTF_VCMDQ_BASE	(TEGRA241_VCMDQ_PAGE1_BASE + SZ_64K)

/* CMDQV global config regs */
#define TEGRA241_CMDQV_CONFIG		0x0000
#define  CMDQV_EN			BIT(0)

#define TEGRA241_CMDQV_PARAM		0x0004
#define  CMDQV_NUM_SID_PER_VM_LOG2	GENMASK(15, 12)
#define  CMDQV_NUM_VINTF_LOG2		GENMASK(11, 8)
#define  CMDQV_NUM_VCMDQ_LOG2		GENMASK(7, 4)
#define  CMDQV_VER			GENMASK(3, 0)

#define TEGRA241_CMDQV_STATUS		0x0008
#define  CMDQV_STATUS			GENMASK(2, 1)
#define  CMDQV_ENABLED			BIT(0)

#define TEGRA241_CMDQV_VINTF_ERR_MAP	0x0014
#define TEGRA241_CMDQV_VINTF_INT_MASK	0x001C
#define TEGRA241_CMDQV_VCMDQ_ERR_MAP0	0x0024
#define TEGRA241_CMDQV_VCMDQ_ERR_MAP(i)	(0x0024 + 0x4*(i))

#define TEGRA241_CMDQV_CMDQ_ALLOC(q)	(0x0200 + 0x4*(q))
#define  CMDQV_CMDQ_ALLOC_VINTF		GENMASK(20, 15)
#define  CMDQV_CMDQ_ALLOC_LVCMDQ	GENMASK(7, 1)
#define  CMDQV_CMDQ_ALLOCATED		BIT(0)

/* VINTF config regs */
#define TEGRA241_VINTF(v)		(0x1000 + 0x100*(v))

#define TEGRA241_VINTFi_CONFIG(i)		(TEGRA241_VINTF(i) + TEGRA241_VINTF_CONFIG)
#define TEGRA241_VINTFi_STATUS(i)		(TEGRA241_VINTF(i) + TEGRA241_VINTF_STATUS)
#define TEGRA241_VINTFi_SID_MATCH(i, s)	(TEGRA241_VINTF(i) + TEGRA241_VINTF_SID_MATCH(s))
#define TEGRA241_VINTFi_SID_REPLACE(i, s)	(TEGRA241_VINTF(i) + TEGRA241_VINTF_SID_REPLACE(s))
#define TEGRA241_VINTFi_CMDQ_ERR_MAP(i,m)	(TEGRA241_VINTF(i) + TEGRA241_VINTF_CMDQ_ERR_MAP(m))

#define TEGRA241_VINTF_CONFIG		0x0000
#define  VINTF_HYP_OWN			BIT(17)
#define  VINTF_VMID			GENMASK(16, 1)
#define  VINTF_EN			BIT(0)

#define TEGRA241_VINTF_STATUS		0x0004
#define  VINTF_STATUS			GENMASK(3, 1)
#define  VINTF_ENABLED			BIT(0)
#define  VINTF_VI_NUM_LVCMDQ		GENMASK(23, 16)

#define TEGRA241_VINTF_SID_MATCH(s)	(0x0040 + 0x4*(s))
#define TEGRA241_VINTF_SID_REPLACE(s)	(0x0080 + 0x4*(s))

#define TEGRA241_VINTF_CMDQ_ERR_MAP(m)	(0x00C0 + 0x4*(m))

/* VCMDQ config regs */
/* -- PAGE0 -- */
#define TEGRA241_VCMDQ_PAGE0(q)		(TEGRA241_VCMDQ_PAGE0_BASE + 0x80*(q))

#define TEGRA241_VCMDQ_CONS		0x00000
#define  VCMDQ_CONS_ERR			GENMASK(30, 24)

#define TEGRA241_VCMDQ_PROD		0x00004

#define TEGRA241_VCMDQ_CONFIG		0x00008
#define  VCMDQ_EN			BIT(0)

#define TEGRA241_VCMDQ_STATUS		0x0000C
#define  VCMDQ_ENABLED			BIT(0)

#define TEGRA241_VCMDQ_GERROR		0x00010
#define TEGRA241_VCMDQ_GERRORN		0x00014

/* -- PAGE1 -- */
#define TEGRA241_VCMDQ_PAGE1(q)		(TEGRA241_VCMDQ_PAGE1_BASE + 0x80*(q))
#define  VCMDQ_ADDR			GENMASK(47, 5)
#define  VCMDQ_LOG2SIZE			GENMASK(4, 0)

#define TEGRA241_VCMDQ_BASE		0x00000
#define TEGRA241_VCMDQ_CONS_INDX_BASE	0x00008

/* VINTF logical-VCMDQ pages */
#define TEGRA241_VINTFi_PAGE0(i) 	(TEGRA241_VINTF_VCMDQ_BASE + SZ_128K*(i))
#define TEGRA241_VINTFi_PAGE1(i) 	(TEGRA241_VINTFi_PAGE0(i) + SZ_64K)
#define TEGRA241_VINTFi_VCMDQ_PAGE0(i, q) \
					(TEGRA241_VINTFi_PAGE0(i) + 0x80*(q))
#define TEGRA241_VINTFi_VCMDQ_PAGE1(i, q) \
					(TEGRA241_VINTFi_PAGE1(i) + 0x80*(q))

/* MMIO helpers */
#define cmdqv_readl(reg) \
	readl(cmdqv->base + TEGRA241_CMDQV_##reg)
#define cmdqv_readl_relaxed(reg) \
	readl_relaxed(cmdqv->base + TEGRA241_CMDQV_##reg)
#define cmdqv_write(val, reg) \
	writel((val), cmdqv->base + TEGRA241_CMDQV_##reg)
#define cmdqv_writel_relaxed(val, reg) \
	writel_relaxed((val), cmdqv->base + TEGRA241_CMDQV_##reg)

#define vintf_readl(reg) \
	readl(vintf->base + TEGRA241_VINTF_##reg)
#define vintf_readl_relaxed(reg) \
	readl_relaxed(vintf->base + TEGRA241_VINTF_##reg)
#define vintf_writel(val, reg) \
	writel((val), vintf->base + TEGRA241_VINTF_##reg)
#define vintf_writel_relaxed(val, reg) \
	writel_relaxed((val), vintf->base + TEGRA241_VINTF_##reg)

#define vcmdq_page0_readl(reg) \
	readl(vcmdq->page0 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page0_readl_relaxed(reg) \
	readl_relaxed(vcmdq->page0 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page0_writel(val, reg) \
	writel((val), vcmdq->page0 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page0_writel_relaxed(val, reg) \
	writel_relaxed((val), vcmdq->page0 + TEGRA241_VCMDQ_##reg)

#define vcmdq_page1_readl(reg) \
	readl(vcmdq->page1 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page1_readl_relaxed(reg) \
	readl_relaxed(vcmdq->page1 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page1_writel(val, reg) \
	writel((val), vcmdq->page1 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page1_writel_relaxed(val, reg) \
	writel_relaxed((val), vcmdq->page1 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page1_writeq(val, reg) \
	writeq((val), vcmdq->page1 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page1_writeq_relaxed(val, reg) \
	writeq_relaxed((val), vcmdq->page1 + TEGRA241_VCMDQ_##reg)

/* Logging helpers */
#define cmdqv_warn(fmt, ...) \
	dev_warn(cmdqv->dev, fmt, ##__VA_ARGS__)
#define cmdqv_err(fmt, ...) \
	dev_err(cmdqv->dev, fmt, ##__VA_ARGS__)
#define cmdqv_info(fmt, ...) \
	dev_info(cmdqv->dev, fmt, ##__VA_ARGS__)
#define cmdqv_dbg(fmt, ...) \
	dev_dbg(cmdqv->dev, fmt, ##__VA_ARGS__)

#define vintf_warn(fmt, ...) \
	dev_warn(cmdqv->dev, "VINTF%u: " fmt, vintf->idx, ##__VA_ARGS__)
#define vintf_err(fmt, ...) \
	dev_err(cmdqv->dev, "VINTF%u: " fmt, vintf->idx, ##__VA_ARGS__)
#define vintf_info(fmt, ...) \
	dev_info(cmdqv->dev, "VINTF%u: " fmt, vintf->idx, ##__VA_ARGS__)
#define vintf_dbg(fmt, ...) \
	dev_dbg(cmdqv->dev, "VINTF%u: " fmt, vintf->idx, ##__VA_ARGS__)

#define vcmdq_warn(fmt, ...)                                       \
	do {                                                       \
		if (vcmdq->vintf)                                  \
			vintf_warn("VCMDQ%u/LVCMDQ%u: " fmt,       \
				   vcmdq->idx, vcmdq->logical_idx, \
				   ##__VA_ARGS__);                 \
		else                                               \
			dev_warn(cmdqv->dev, "VCMDQ%u: " fmt,      \
				 vcmdq->idx, ##__VA_ARGS__);       \
	} while (0)
#define vcmdq_err(fmt, ...)                                        \
	do {                                                       \
		if (vcmdq->vintf)                                  \
			vintf_err("VCMDQ%u/LVCMDQ%u: " fmt,        \
				  vcmdq->idx, vcmdq->logical_idx,  \
				  ##__VA_ARGS__);                  \
		else                                               \
			dev_err(cmdqv->dev, "VCMDQ%u: " fmt,       \
				vcmdq->idx, ##__VA_ARGS__);        \
	} while (0)
#define vcmdq_info(fmt, ...)                                       \
	do {                                                       \
		if (vcmdq->vintf)                                  \
			vintf_info("VCMDQ%u/LVCMDQ%u: " fmt,       \
				   vcmdq->idx, vcmdq->logical_idx, \
				   ##__VA_ARGS__);                 \
		else                                               \
			dev_info(cmdqv->dev, "VCMDQ%u: " fmt,      \
				 vcmdq->idx, ##__VA_ARGS__);       \
	} while (0)
#define vcmdq_dbg(fmt, ...)                                        \
	do {                                                       \
		if (vcmdq->vintf)                                  \
			vintf_dbg("VCMDQ%u/LVCMDQ%u: " fmt,        \
				  vcmdq->idx, vcmdq->logical_idx,  \
				  ##__VA_ARGS__);                  \
		else                                               \
			dev_dbg(cmdqv->dev, "VCMDQ%u: " fmt,       \
				vcmdq->idx, ##__VA_ARGS__);        \
	} while (0)

static bool bypass_vcmdq = false;
module_param(bypass_vcmdq, bool, 0444);
MODULE_PARM_DESC(bypass_vcmdq,
	"This allows to bypass VCMDQ by using default SMMU internal CMDQ.");

struct tegra241_vcmdq {
	u16 idx;
	u16 logical_idx;

	struct arm_smmu_cmdq cmdq;
	struct tegra241_vintf *vintf;

	void __iomem *page0;
	void __iomem *page1;
};

struct tegra241_vintf {
	struct iommufd_viommu core;

	u16 idx;
	u16 vmid;
	u32 cfg;
	u32 status;

	void __iomem *base;
	struct tegra241_cmdqv *cmdqv;
	struct tegra241_vcmdq **vcmdqs;
	struct arm_smmu_domain *smmu_domain;

#define TEGRA241_VINTF_NUM_SLOTS 16
	struct xarray		sids;
};
#define viommu_to_vintf(v) container_of(v, struct tegra241_vintf, core)

struct tegra241_cmdqv {
	struct arm_smmu_device *smmu;

	struct device *dev;
	struct resource res;
	void __iomem *base;
	resource_size_t ioaddr;
	int irq;

	/* CMDQV Hardware Params */
	u16 num_total_vintfs;
	u16 num_total_vcmdqs;
	u16 num_vcmdqs_per_vintf;

	struct xarray vcmdqs;
	struct xarray vintfs;
	struct tegra241_vintf **vintf;
};

static void tegra241_cmdqv_handle_vintf0_error(struct tegra241_cmdqv *cmdqv)
{
	struct tegra241_vintf *vintf = cmdqv->vintf[0];
	int i;

	/* Cache error status to bypass VCMDQs until error is recovered */
	vintf->status = vintf_readl_relaxed(STATUS);

	for (i = 0; i < 4; i++) {
		u32 lvcmdq_err_map = vintf_readl_relaxed(CMDQ_ERR_MAP(i));

		while (lvcmdq_err_map) {
			int qidx = ffs(lvcmdq_err_map) - 1;
			struct tegra241_vcmdq *vcmdq = vintf->vcmdqs[qidx];
			u32 gerrorn, gerror;

			lvcmdq_err_map &= ~BIT(qidx);

			__arm_smmu_cmdq_skip_err(cmdqv->dev, &vcmdq->cmdq.q);

			gerrorn = vcmdq_page0_readl_relaxed(GERRORN);
			gerror = vcmdq_page0_readl_relaxed(GERROR);
			vcmdq_page0_writel(gerror, GERRORN);
		}
	}

	/* Now status should be clean, cache it again */
	vintf->status = vintf_readl_relaxed(STATUS);
}

static irqreturn_t tegra241_cmdqv_isr(int irq, void *devid)
{
	struct tegra241_cmdqv *cmdqv = (struct tegra241_cmdqv *)devid;
	u32 vintf_errs[2];
	u32 vcmdq_errs[4];

	vintf_errs[0] = cmdqv_readl_relaxed(VINTF_ERR_MAP);
	vintf_errs[1] = cmdqv_readl_relaxed(VINTF_ERR_MAP + 0x4);

	vcmdq_errs[0] = cmdqv_readl_relaxed(VCMDQ_ERR_MAP(0));
	vcmdq_errs[1] = cmdqv_readl_relaxed(VCMDQ_ERR_MAP(1));
	vcmdq_errs[2] = cmdqv_readl_relaxed(VCMDQ_ERR_MAP(2));
	vcmdq_errs[3] = cmdqv_readl_relaxed(VCMDQ_ERR_MAP(3));

	cmdqv_warn("unexpected cmdqv error reported\n");
	cmdqv_warn(" vintf_map: 0x%08X%08X\n", vintf_errs[1], vintf_errs[0]);
	cmdqv_warn(" vcmdq_map: 0x%08X%08X%08X%08X\n",
		   vcmdq_errs[3], vcmdq_errs[2], vcmdq_errs[1], vcmdq_errs[0]);

	/* Handle VINTF0 and its VCMDQs */
	if (vintf_errs[0] & 0x1)
		tegra241_cmdqv_handle_vintf0_error(cmdqv);

	return IRQ_HANDLED;
}

/* Adapt struct arm_smmu_cmdq init sequences from arm-smmu-v3.c for VCMDQs */
static int tegra241_cmdqv_init_one_vcmdq(struct tegra241_vcmdq *vcmdq)
{
	struct tegra241_cmdqv *cmdqv = vcmdq->vintf->cmdqv;
	struct arm_smmu_cmdq *cmdq = &vcmdq->cmdq;
	struct arm_smmu_queue *q = &cmdq->q;
	char name[16];
	int ret;

	sprintf(name, "vcmdq%u", vcmdq->idx);

	q->llq.max_n_shift = ilog2(SZ_64K >> CMDQ_ENT_SZ_SHIFT);

	/* Use the common helper to init the VCMDQ, and then... */
	ret = arm_smmu_init_one_queue(cmdqv->smmu, q, vcmdq->page0,
				      TEGRA241_VCMDQ_PROD, TEGRA241_VCMDQ_CONS,
				      CMDQ_ENT_DWORDS, name);
	if (ret)
		return ret;

	/* ...override q_base to write VCMDQ_BASE registers */
	q->q_base  = q->base_dma & VCMDQ_ADDR;
	q->q_base |= FIELD_PREP(VCMDQ_LOG2SIZE, q->llq.max_n_shift);

	/* All VCMDQs support CS_NONE only for CMD_SYNC */
	q->quirks = CMDQ_QUIRK_SYNC_CS_NONE_ONLY;

	return arm_smmu_cmdq_init(cmdqv->smmu, cmdq);
}

struct arm_smmu_cmdq *tegra241_cmdqv_get_cmdq(struct arm_smmu_device *smmu, u64 *cmds, int n)

{
	struct tegra241_cmdqv *cmdqv = smmu->tegra241_cmdqv;
	struct tegra241_vintf *vintf = cmdqv->vintf[0];
	u16 qidx;

	/* Use SMMU CMDQ if vintf[0] is uninitialized */
	if (!FIELD_GET(VINTF_ENABLED, vintf->status))
		return &smmu->cmdq;

	/* Use SMMU CMDQ if vintf[0] has error status */
	if (FIELD_GET(VINTF_STATUS, vintf->status))
		return &smmu->cmdq;

	/* Check for supported CMDs if VINTF is owned by guest (not hypervisor) */
	if (!FIELD_GET(VINTF_HYP_OWN, vintf->cfg)) {
		u64 opcode = (n) ? FIELD_GET(CMDQ_0_OP, cmds[0]) : CMDQ_OP_CMD_SYNC;

		/* List all supported CMDs for vintf->cmdq pathway */
		switch (opcode) {
		case CMDQ_OP_TLBI_NH_ASID:
		case CMDQ_OP_TLBI_NH_VA:
		case CMDQ_OP_TLBI_S12_VMALL:
		case CMDQ_OP_TLBI_S2_IPA:
		case CMDQ_OP_ATC_INV:
			break;
		default:
			/* Unsupported CMDs go for smmu->cmdq pathway */
			return &smmu->cmdq;
		}
	}

	/*
	 * Select a vcmdq to use. Here we use a temporal solution to
	 * balance out traffic on cmdq issuing: each cmdq has its own
	 * lock, if all cpus issue cmdlist using the same cmdq, only
	 * one CPU at a time can enter the process, while the others
	 * will be spinning at the same lock.
	 */
	qidx = smp_processor_id() % cmdqv->num_vcmdqs_per_vintf;
	return &vintf->vcmdqs[qidx]->cmdq;
}

static int tegra241_vintf0_init_vcmdq(struct tegra241_vcmdq *vcmdq)
{
	struct tegra241_vintf *vintf = vcmdq->vintf;
	struct tegra241_cmdqv *cmdqv = vintf->cmdqv;
	u32 regval;
	int ret;

	/* Setup struct arm_smmu_cmdq data members */
	tegra241_cmdqv_init_one_vcmdq(vcmdq);

	/* Configure and enable the vcmdq */
	vcmdq_page0_writel_relaxed(0, PROD);
	vcmdq_page0_writel_relaxed(0, CONS);

	vcmdq_page1_writeq_relaxed(vcmdq->cmdq.q.q_base, BASE);
	vcmdq_page0_writel_relaxed(VCMDQ_EN, CONFIG);
	ret = readl_poll_timeout(vcmdq->page0 + TEGRA241_VCMDQ_STATUS,
				 regval, regval == VCMDQ_ENABLED,
				 1, ARM_SMMU_POLL_TIMEOUT_US);
	if (ret) {
		u32 gerror = vcmdq_page0_readl_relaxed(GERROR);
		u32 gerrorn = vcmdq_page0_readl_relaxed(GERRORN);
		u32 cons = vcmdq_page0_readl_relaxed(CONS);

		vcmdq_err("failed to enable\n");
		vcmdq_err("  GERROR=0x%X\n", gerror);
		vcmdq_err("  GERRORN=0x%X\n", gerrorn);
		vcmdq_err("  CONS=0x%X\n", cons);
		return ret;
	}

	vcmdq_info("inited\n");
	return 0;
}

int tegra241_cmdqv_device_reset(struct arm_smmu_device *smmu)
{
	struct tegra241_cmdqv *cmdqv = smmu->tegra241_cmdqv;
	struct tegra241_vintf *vintf = cmdqv->vintf[0];
	u32 regval;
	u16 qidx;
	int ret;

	/* Setup vintf[0] for host kernel */
	vintf->idx = 0;
	vintf->cmdqv = cmdqv;
	vintf->base = cmdqv->base + TEGRA241_VINTF(0);

	/*
	 * Note that HYP_OWN bit is wired to zero when running in guest kernel
	 * regardless of enabling it here, as !HYP_OWN cmdqs have a restricted
	 * set of supported commands, by following the HW design.
	 */
	regval = FIELD_PREP(VINTF_HYP_OWN, 1);
	vintf_writel(regval, CONFIG);

	regval |= FIELD_PREP(VINTF_EN, 1);
	vintf_writel(regval, CONFIG);

	/*
	 * As being mentioned above, HYP_OWN bit is wired to zero for a guest
	 * kernel, so read back regval from HW to ensure that reflects in cfg
	 */
	vintf->cfg = vintf_readl(CONFIG);

	ret = readl_relaxed_poll_timeout(vintf->base + TEGRA241_VINTF_STATUS,
					 regval, regval & VINTF_ENABLED,
					 1, ARM_SMMU_POLL_TIMEOUT_US);
	if (ret) {
		vintf_err("failed to enable: STATUS = 0x%08X\n", regval);
		return ret;
	}

	vintf->status = regval;

	/* Allocate vcmdqs to vintf */
	for (qidx = 0; qidx < cmdqv->num_vcmdqs_per_vintf; qidx++) {
		regval  = FIELD_PREP(CMDQV_CMDQ_ALLOC_VINTF, vintf->idx);
		regval |= FIELD_PREP(CMDQV_CMDQ_ALLOC_LVCMDQ, qidx);
		regval |= CMDQV_CMDQ_ALLOCATED;
		cmdqv_writel_relaxed(regval, CMDQ_ALLOC(qidx));
	}

	/* Build an arm_smmu_cmdq for each vcmdq allocated to vintf */
	vintf->vcmdqs = devm_kcalloc(cmdqv->dev, cmdqv->num_vcmdqs_per_vintf,
				     sizeof(*vintf->vcmdqs), GFP_KERNEL);
	if (!vintf->vcmdqs)
		return -ENOMEM;

	for (qidx = 0; qidx < cmdqv->num_vcmdqs_per_vintf; qidx++) {
		struct tegra241_vcmdq *vcmdq;

		vcmdq = devm_kzalloc(cmdqv->dev, sizeof(*vcmdq), GFP_KERNEL);
		if (!vcmdq)
			return -ENOMEM;
		vcmdq->vintf = vintf;
		vcmdq->idx = vcmdq->logical_idx = qidx;
		vcmdq->page0 = cmdqv->base + TEGRA241_VCMDQ_PAGE0(qidx);
		vcmdq->page1 = cmdqv->base + TEGRA241_VCMDQ_PAGE1(qidx);
		ret = tegra241_vintf0_init_vcmdq(vcmdq);
		if (ret)
			return ret;
		vintf->vcmdqs[qidx] = vcmdq;
	}

	/* Reserve vintf[0] for kernel and hypervisor use */
	xa_init_flags(&cmdqv->vintfs, XA_FLAGS_ALLOC1 | XA_FLAGS_ACCOUNT);
	xa_init_flags(&cmdqv->vcmdqs, XA_FLAGS_ALLOC | XA_FLAGS_ACCOUNT);

	if (cmdqv->vintf && cmdqv->vintf[0])
		cmdqv->vintf[0] = vintf;

	return 0;
}

static int tegra241_cmdqv_acpi_is_memory(struct acpi_resource *res, void *data)
{
	struct resource_win win;

	return !acpi_dev_resource_address_space(res, &win);
}

static int tegra241_cmdqv_acpi_get_irqs(struct acpi_resource *ares, void *data)
{
	struct resource r;
	int *irq = data;

	if (*irq <= 0 && acpi_dev_resource_interrupt(ares, 0, &r))
		*irq = r.start;

	return 1; /* No need to add resource to the list */
}

static struct tegra241_cmdqv *
tegra241_cmdqv_find_resource(struct arm_smmu_device *smmu, int id)
{
	struct tegra241_cmdqv *cmdqv = NULL;
	struct device *dev = smmu->dev;
	struct list_head resource_list;
	struct resource_entry *rentry;
	struct acpi_device *adev;
	const char *match_uid;
	int ret;

	if (acpi_disabled)
		return NULL;

	/* Look for a device in the DSDT whose _UID matches the SMMU node ID */
	match_uid = kasprintf(GFP_KERNEL, "%u", id);
	adev = acpi_dev_get_first_match_dev(TEGRA241_CMDQV_HID,
					    match_uid, -1);
	kfree(match_uid);

	if (!adev)
		return NULL;

	dev_info(dev, "found companion CMDQV device, %s\n",
		 dev_name(&adev->dev));

	INIT_LIST_HEAD(&resource_list);
	ret = acpi_dev_get_resources(adev, &resource_list,
				     tegra241_cmdqv_acpi_is_memory, NULL);
	if (ret < 0) {
		dev_err(dev, "failed to get memory resource: %d\n", ret);
		goto put_dev;
	}

	cmdqv = devm_kzalloc(dev, sizeof(*cmdqv), GFP_KERNEL);
	if (!cmdqv)
		goto free_list;

	cmdqv->dev = dev;
	cmdqv->smmu = smmu;

	rentry = list_first_entry_or_null(&resource_list,
					  struct resource_entry, node);
	if (!rentry) {
		cmdqv_err("failed to get memory resource entry\n");
		goto free_cmdqv;
	}

	cmdqv->res = *(rentry->res);

	cmdqv->base = devm_ioremap_resource(smmu->dev, rentry->res);
	if (IS_ERR(cmdqv->base)) {
		cmdqv_err("failed to ioremap: %ld\n", PTR_ERR(cmdqv->base));
		goto free_cmdqv;
	}

	acpi_dev_free_resource_list(&resource_list);

	cmdqv->ioaddr = rentry->res->start;

	INIT_LIST_HEAD(&resource_list);

	ret = acpi_dev_get_resources(adev, &resource_list,
				     tegra241_cmdqv_acpi_get_irqs, &cmdqv->irq);
	if (ret < 0 || cmdqv->irq <= 0) {
		cmdqv_warn("no cmdqv interrupt. errors will not be reported\n");
	} else {
		ret = devm_request_irq(smmu->dev, cmdqv->irq,
				       tegra241_cmdqv_isr, 0,
				       "tegra241-cmdqv", cmdqv);
		if (ret) {
			cmdqv_err("failed to request irq (%d): %d\n",
				  cmdqv->irq, ret);
			goto iounmap;
		}
	}

	goto free_list;

iounmap:
	devm_iounmap(cmdqv->dev, cmdqv->base);
	devm_release_mem_region(smmu->dev, cmdqv->res.start,
				resource_size(&cmdqv->res));
free_cmdqv:
	devm_kfree(cmdqv->dev, cmdqv);
	cmdqv = NULL;
free_list:
	acpi_dev_free_resource_list(&resource_list);
put_dev:
	put_device(&adev->dev);

	return cmdqv;
}

struct tegra241_cmdqv *
tegra241_cmdqv_acpi_probe(struct arm_smmu_device *smmu, int id)
{
	struct tegra241_cmdqv *cmdqv;
	u32 regval;

	if (bypass_vcmdq) {
		dev_info_once(smmu->dev,
			      "bypass_vcmdq=true. Disabling VCMDQ support");
		return NULL;
	}

	cmdqv = tegra241_cmdqv_find_resource(smmu, id);
	if (!cmdqv)
		return NULL;

	regval = cmdqv_readl_relaxed(CONFIG);
	if (!FIELD_GET(CMDQV_EN, regval)) {
		cmdqv_err("CMDQV h/w disabled: CMDQV_CONFIG=0x%08X\n", regval);
		goto free_res;
	}

	regval = cmdqv_readl_relaxed(STATUS);
	if (!FIELD_GET(CMDQV_ENABLED, regval) ||
	    FIELD_GET(CMDQV_STATUS, regval)) {
		cmdqv_err("CMDQV h/w not ready: CMDQV_STATUS=0x%08X\n", regval);
		goto free_res;
	}

	regval = cmdqv_readl_relaxed(PARAM);
	cmdqv->num_total_vintfs = 1 << FIELD_GET(CMDQV_NUM_VINTF_LOG2, regval);
	cmdqv->num_total_vcmdqs = 1 << FIELD_GET(CMDQV_NUM_VCMDQ_LOG2, regval);
	cmdqv->num_vcmdqs_per_vintf =
		cmdqv->num_total_vcmdqs / cmdqv->num_total_vintfs;

	cmdqv->vintf = devm_kcalloc(cmdqv->dev, cmdqv->num_total_vintfs,
				    sizeof(*cmdqv->vintf), GFP_KERNEL);
	if (!cmdqv->vintf)
		goto free_res;

	cmdqv->vintf[0] = devm_kzalloc(cmdqv->dev, sizeof(*(cmdqv->vintf[0])),
				       GFP_KERNEL);
	if (!cmdqv->vintf[0])
		goto free_vintf;

	return cmdqv;

free_vintf:
	devm_kfree(cmdqv->dev, cmdqv->vintf);
free_res:
	if (cmdqv->irq > 0)
		devm_free_irq(smmu->dev, cmdqv->irq, cmdqv);
	devm_iounmap(smmu->dev, cmdqv->base);
	devm_release_mem_region(smmu->dev, cmdqv->res.start,
				resource_size(&cmdqv->res));
	devm_kfree(smmu->dev, cmdqv);

	return NULL;
}

static void tegra241_vintf_deinit_vcmdq(struct tegra241_vcmdq *vcmdq)
{
	struct tegra241_vintf *vintf = vcmdq->vintf;
	struct tegra241_cmdqv *cmdqv = vintf->cmdqv;
	u32 regval;

	vcmdq_page0_writel(0, CONFIG);
	if (readl_poll_timeout(vcmdq->page0 + TEGRA241_VCMDQ_STATUS,
			       regval, regval != VCMDQ_ENABLED,
			       1, ARM_SMMU_POLL_TIMEOUT_US)) {
		u32 gerrorn = vcmdq_page0_readl_relaxed(GERRORN);
		u32 gerror = vcmdq_page0_readl_relaxed(GERROR);
		u32 cons = vcmdq_page0_readl_relaxed(CONS);

		vcmdq_err("failed to enable\n");
		vcmdq_err("  GERROR=0x%X\n", gerror);
		vcmdq_err("  GERRORN=0x%X\n", gerrorn);
		vcmdq_err("  CONS=0x%X\n", cons);
	}
	vcmdq_page0_writel_relaxed(0, PROD);
	vcmdq_page0_writel_relaxed(0, CONS);
	vcmdq_page1_writeq_relaxed(0, BASE);
	vcmdq_page1_writeq_relaxed(0, CONS_INDX_BASE);

	vcmdq_info("cleared\n");
}

static int tegra241_vintf_init_vcmdq(struct tegra241_vcmdq *vcmdq,
				     phys_addr_t q_base, u32 log2size)
{
	struct tegra241_vintf *vintf = vcmdq->vintf;
	struct tegra241_cmdqv *cmdqv = vintf->cmdqv;
	u64 regval64;

	tegra241_vintf_deinit_vcmdq(vcmdq);

	regval64 = (q_base & VCMDQ_ADDR) | FIELD_PREP(VCMDQ_LOG2SIZE, log2size);
	vcmdq_page1_writeq_relaxed(regval64, BASE);

	vcmdq_info("allocated at host PA 0x%llx size 0x%lx\n",
		   q_base, 1UL << log2size);
	return 0;
}

struct iommufd_viommu *
tegra241_cmdqv_viommu_alloc(struct tegra241_cmdqv *cmdqv,
			    struct arm_smmu_domain *smmu_domain)
{
	struct tegra241_vintf *vintf;
	int qidx, idx, ret;
	u32 regval;

	vintf = iommufd_alloc_viommu(tegra241_vintf, core);
	if (!vintf)
		return ERR_PTR(-ENOMEM);

	ret = xa_alloc(&cmdqv->vintfs, &idx, vintf,
		       XA_LIMIT(1, cmdqv->num_total_vintfs - 1),
		       GFP_KERNEL_ACCOUNT);
	if (ret) {
		dev_err(cmdqv->dev, "failed to allocate vintfs x_array\n");
		goto out_free;
	}
	cmdqv->vintf[idx] = vintf;

	vintf->idx = idx;
	vintf->cmdqv = cmdqv;
	vintf->vmid = smmu_domain->vmid;
	vintf->smmu_domain = smmu_domain;
	vintf->base = cmdqv->base + TEGRA241_VINTF(idx);

	xa_init_flags(&vintf->sids, XA_FLAGS_ALLOC1 | XA_FLAGS_ACCOUNT);

	regval = FIELD_PREP(VINTF_VMID, vintf->vmid) |
		 FIELD_PREP(VINTF_EN, 1);
	writel(regval, vintf->base + TEGRA241_VINTF_CONFIG);

	/* Build an arm_smmu_cmdq for each vcmdq allocated to vintf */
	vintf->vcmdqs = kcalloc(cmdqv->num_vcmdqs_per_vintf,
				sizeof(*vintf->vcmdqs), GFP_KERNEL);
	if (!vintf->vcmdqs) {
		ret = -ENOMEM;
		goto out_xa_erase;
	}

	for (qidx = 0; qidx < cmdqv->num_vcmdqs_per_vintf; qidx++) {
		u16 vcmdq_idx = cmdqv->num_vcmdqs_per_vintf * vintf->idx + qidx;
		struct tegra241_vcmdq *vcmdq;

		/* Allocate vcmdqs to vintf */
		regval  = FIELD_PREP(CMDQV_CMDQ_ALLOC_VINTF, vintf->idx);
		regval |= FIELD_PREP(CMDQV_CMDQ_ALLOC_LVCMDQ, qidx);
		regval |= CMDQV_CMDQ_ALLOCATED;
		cmdqv_writel_relaxed(regval, CMDQ_ALLOC(vcmdq_idx));

		vcmdq = kzalloc(sizeof(*vcmdq), GFP_KERNEL);
		if (!vcmdq) {
			ret = -ENOMEM;
			goto out_free_vcmdq;
		}
		vcmdq->vintf = vintf;
		vcmdq->idx = vcmdq_idx;
		vcmdq->logical_idx = qidx;
		vcmdq->page0 = cmdqv->base + TEGRA241_VINTFi_VCMDQ_PAGE0(vintf->idx, qidx);
		vcmdq->page1 = cmdqv->base + TEGRA241_VINTFi_VCMDQ_PAGE1(vintf->idx, qidx);
		vintf->vcmdqs[qidx] = vcmdq;
	}

	vintf_info("allocated with vmid (%d)\n", vintf->vmid);

	return &vintf->core;

out_free_vcmdq:
	while (qidx--)
		kfree(vintf->vcmdqs[qidx]);
	kfree(vintf->vcmdqs);
out_xa_erase:
	xa_erase(&cmdqv->vintfs, vintf->idx);
out_free:
	kfree(vintf);
	return ERR_PTR(ret);
}

int tegra241_cmdqv_viommu_set_data(struct tegra241_cmdqv *cmdqv,
				   struct iommufd_viommu *viommu,
				   const struct iommu_user_data *user_data)
{
	struct tegra241_vintf *vintf = viommu_to_vintf(viommu);
	struct arm_smmu_domain *smmu_domain =
		to_smmu_domain(viommu->hwpt->common.domain);
	struct iommu_viommu_tegra241_vcmdq arg;
	phys_addr_t q_base;
	int ret;

	ret = iommu_copy_struct_from_user(&arg, user_data,
					  IOMMU_VIOMMU_DATA_TEGRA241_VCMDQ,
					  cons_idx_base);
	if (ret)
		return ret;

	if (!arg.vcmdq_base || arg.vcmdq_base & ~VCMDQ_ADDR)
		return -EINVAL;
	if (!arg.vcmdq_log2size || arg.vcmdq_log2size > VCMDQ_LOG2SIZE)
		return -EINVAL;
	if (arg.vcmdq_id >= cmdqv->num_vcmdqs_per_vintf)
		return -EINVAL;
	q_base = arm_smmu_domain_ipa_to_pa(smmu_domain, arg.vcmdq_base);
	if (!q_base)
		return -EINVAL;
	vintf_info("init logical-VCMDQ%d\n", arg.vcmdq_id);
	return tegra241_vintf_init_vcmdq(
		vintf->vcmdqs[arg.vcmdq_id], q_base, arg.vcmdq_log2size);
}

int tegra241_cmdqv_viommu_reset(struct tegra241_cmdqv *cmdqv,
				struct iommufd_viommu *viommu)
{
	struct tegra241_vintf *vintf = viommu_to_vintf(viommu);
	int qidx;

	/* Disable LVCMDQs of the VINTF0; clear their PROD and CONS indexes too */
	for (qidx = 0; qidx < cmdqv->num_vcmdqs_per_vintf; qidx++)
		tegra241_vintf_deinit_vcmdq(vintf->vcmdqs[qidx]);
	return 0;
}

void tegra241_cmdqv_viommu_free(struct tegra241_cmdqv *cmdqv,
				struct iommufd_viommu *viommu)
{
	struct tegra241_vintf *vintf = viommu_to_vintf(viommu);
	int qidx;

	/* Disable LVCMDQs of the VINTF0; clear their PROD and CONS indexes too */
	for (qidx = 0; qidx < cmdqv->num_vcmdqs_per_vintf; qidx++)
		tegra241_vintf_deinit_vcmdq(vintf->vcmdqs[qidx]);

	/* Disable and cleanup VINTF configurations */
	vintf_writel_relaxed(0, CONFIG);

	xa_erase(&cmdqv->vintfs, vintf->idx);
	/* IOMMUFD core frees viommu, i.e. vintf */
	cmdqv->vintf[vintf->idx] = NULL;
	vintf_info("deallocated with vmid (%d)\n", vintf->vmid);
}

int tegra241_cmdqv_viommu_set_dev_id(struct iommufd_viommu *viommu,
				     struct arm_smmu_master *master,
				     u64 dev_id)
{
	struct tegra241_vintf *vintf =
		container_of(viommu, struct tegra241_vintf, core);
	struct arm_smmu_stream *stream = &master->streams[0];
	int slot, ret;

	WARN_ON(master->num_streams != 1);

	/* Find an empty slot of SID_MATCH and SID_REPLACE */
	ret = xa_alloc(&vintf->sids, &slot, stream,
		       XA_LIMIT(0, TEGRA241_VINTF_NUM_SLOTS - 1),
		       GFP_KERNEL_ACCOUNT);
	if (ret)
		return ret;

	vintf_writel_relaxed(stream->id, SID_REPLACE(slot));
	vintf_writel_relaxed(dev_id << 1 | 0x1, SID_MATCH(slot));
	stream->cmdqv_sid_slot = slot;

	return 0;
}

void tegra241_cmdqv_viommu_unset_dev_id(struct iommufd_viommu *viommu,
					struct arm_smmu_master *master)
{
	struct tegra241_vintf *vintf =
		container_of(viommu, struct tegra241_vintf, core);
	struct arm_smmu_stream *stream = &master->streams[0];
	int slot = stream->cmdqv_sid_slot;

	vintf_writel_relaxed(0, SID_REPLACE(slot));
	vintf_writel_relaxed(0, SID_MATCH(slot));
	WARN_ON(stream != xa_erase(&vintf->sids, slot));
}

unsigned long tegra241_cmdqv_get_mmap_pfn(struct tegra241_cmdqv *cmdqv,
					  struct iommufd_viommu *viommu,
					  size_t pgsize)
{
	struct tegra241_vintf *vintf =
		container_of(viommu, struct tegra241_vintf, core);

	return (cmdqv->ioaddr + TEGRA241_VINTFi_PAGE0(vintf->idx)) >> PAGE_SHIFT;
}
