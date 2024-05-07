// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (C) 2021-2024 NVIDIA CORPORATION & AFFILIATES. */

#define dev_fmt(fmt) "tegra241_cmdqv: " fmt

#include <linux/acpi.h>
#include <linux/debugfs.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/iommu.h>
#include <linux/iopoll.h>

#include <acpi/acpixf.h>

#include "arm-smmu-v3.h"

#define TEGRA241_CMDQV_HID		"NVDA200C"

/* CMDQV register page base and size defines */
#define TEGRA241_CMDQV_CONFIG_BASE	(0)
#define TEGRA241_CMDQV_CONFIG_SIZE	(SZ_64K)
#define TEGRA241_VCMDQ_PAGE0_BASE	(TEGRA241_CMDQV_CONFIG_BASE + SZ_64K)
#define TEGRA241_VCMDQ_PAGE1_BASE	(TEGRA241_VCMDQ_PAGE0_BASE + SZ_64K)
#define TEGRA241_VINTF_PAGE_BASE	(TEGRA241_VCMDQ_PAGE1_BASE + SZ_64K)

/* CMDQV global base regs */
#define TEGRA241_CMDQV_CONFIG		0x0000
#define  CMDQV_EN			BIT(0)

#define TEGRA241_CMDQV_PARAM		0x0004
#define  CMDQV_NUM_VINTF_LOG2		GENMASK(11, 8)
#define  CMDQV_NUM_VCMDQ_LOG2		GENMASK(7, 4)

#define TEGRA241_CMDQV_STATUS		0x0008
#define  CMDQV_ENABLED			BIT(0)

#define TEGRA241_CMDQV_VINTF_ERR_MAP	0x0014
#define TEGRA241_CMDQV_VINTF_INT_MASK	0x001C
#define TEGRA241_CMDQV_CMDQ_ERR_MAP_64(m) \
					(0x0024 + 0x8*(m))

#define TEGRA241_CMDQV_CMDQ_ALLOC(q)	(0x0200 + 0x4*(q))
#define  CMDQV_CMDQ_ALLOC_VINTF		GENMASK(20, 15)
#define  CMDQV_CMDQ_ALLOC_LVCMDQ	GENMASK(7, 1)
#define  CMDQV_CMDQ_ALLOCATED		BIT(0)

/* VINTF base regs */
#define TEGRA241_VINTF(v)		(0x1000 + 0x100*(v))

#define TEGRA241_VINTF_CONFIG		0x0000
#define  VINTF_HYP_OWN			BIT(17)
#define  VINTF_VMID			GENMASK(16, 1)
#define  VINTF_EN			BIT(0)

#define TEGRA241_VINTF_STATUS		0x0004
#define  VINTF_STATUS			GENMASK(3, 1)
#define  VINTF_ENABLED			BIT(0)

#define TEGRA241_VINTF_LVCMDQ_ERR_MAP_64(m) \
					(0x00C0 + 0x8*(m))
#define  LVCMDQ_ERR_MAP_NUM_64		2

/* VCMDQ base regs */
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
#define TEGRA241_VINTFi_PAGE0(i)	(TEGRA241_VINTF_PAGE_BASE + SZ_128K*(i))
#define TEGRA241_VINTFi_PAGE1(i)	(TEGRA241_VINTFi_PAGE0(i) + SZ_64K)
#define TEGRA241_VINTFi_LVCMDQ_PAGE0(i, q) \
					(TEGRA241_VINTFi_PAGE0(i) + 0x80*(q))
#define TEGRA241_VINTFi_LVCMDQ_PAGE1(i, q) \
					(TEGRA241_VINTFi_PAGE1(i) + 0x80*(q))

/* MMIO helpers */
#define cmdqv_readl(_cmdqv, _regname) \
	readl((_cmdqv)->base + TEGRA241_CMDQV_##_regname)
#define cmdqv_readl_relaxed(_cmdqv, _regname) \
	readl_relaxed((_cmdqv)->base + TEGRA241_CMDQV_##_regname)
#define cmdqv_readq_relaxed(_cmdqv, _regname) \
	readq_relaxed((_cmdqv)->base + TEGRA241_CMDQV_##_regname)
#define cmdqv_writel(_cmdqv, val, _regname) \
	writel((val), (_cmdqv)->base + TEGRA241_CMDQV_##_regname)
#define cmdqv_writel_relaxed(_cmdqv, val, _regname) \
	writel_relaxed((val), (_cmdqv)->base + TEGRA241_CMDQV_##_regname)

#define vintf_readl(_vintf, _regname) \
	readl((_vintf)->base + TEGRA241_VINTF_##_regname)
#define vintf_readq_relaxed(_vintf, _regname) \
	readq_relaxed((_vintf)->base + TEGRA241_VINTF_##_regname)
#define vintf_readl_relaxed(_vintf, _regname) \
	readl_relaxed((_vintf)->base + TEGRA241_VINTF_##_regname)
#define vintf_writel(_vintf, val, _regname) \
	writel((val), (_vintf)->base + TEGRA241_VINTF_##_regname)
#define vintf_writel_relaxed(_vintf, val, _regname) \
	writel_relaxed((val), (_vintf)->base + TEGRA241_VINTF_##_regname)

#define vcmdq_page0_readl(_vcmdq, _regname) \
	readl((_vcmdq)->page0 + TEGRA241_VCMDQ_##_regname)
#define vcmdq_page0_readl_relaxed(_vcmdq, _regname) \
	readl_relaxed((_vcmdq)->page0 + TEGRA241_VCMDQ_##_regname)
#define vcmdq_page0_writel(_vcmdq, val, _regname) \
	writel((val), (_vcmdq)->page0 + TEGRA241_VCMDQ_##_regname)
#define vcmdq_page0_writel_relaxed(_vcmdq, val, _regname) \
	writel_relaxed((val), (_vcmdq)->page0 + TEGRA241_VCMDQ_##_regname)

#define vcmdq_page1_readl(_vcmdq, reg) \
	readl((_vcmdq)->page1 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page1_readl_relaxed(_vcmdq, reg) \
	readl_relaxed((_vcmdq)->page1 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page1_readq_relaxed(_vcmdq, reg) \
	readq_relaxed((_vcmdq)->page1 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page1_writel(_vcmdq, val, reg) \
	writel((val), (_vcmdq)->page1 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page1_writel_relaxed(_vcmdq, val, reg) \
	writel_relaxed((val), (_vcmdq)->page1 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page1_writeq(_vcmdq, val, reg) \
	writeq((val), (_vcmdq)->page1 + TEGRA241_VCMDQ_##reg)
#define vcmdq_page1_writeq_relaxed(_vcmdq, val, reg) \
	writeq_relaxed((val), (_vcmdq)->page1 + TEGRA241_VCMDQ_##reg)


static bool disable_cmdqv;
module_param(disable_cmdqv, bool, 0444);
MODULE_PARM_DESC(disable_cmdqv,
	"This allows to disable CMDQV HW and use default SMMU internal CMDQ.");

static bool bypass_vcmdq;
module_param(bypass_vcmdq, bool, 0444);
MODULE_PARM_DESC(bypass_vcmdq,
	"This allows to bypass VCMDQ for debugging use or perf comparison.");

/**
 * struct tegra241_vcmdq - Virtual Command Queue
 * @idx: Global index in the CMDQV HW
 * @lidx: Local index in the VINTF
 * @enabled: Enable status
 * @cmdqv: CMDQV HW pointer
 * @vintf: VINTF HW pointer
 * @cmdq: Command Queue struct
 * @page0: MMIO Page0 base address
 * @page1: MMIO Page1 base address
 */
struct tegra241_vcmdq {
	u16 idx;
	u16 lidx;

	bool enabled;

	struct tegra241_cmdqv *cmdqv;
	struct tegra241_vintf *vintf;
	struct arm_smmu_cmdq cmdq;

	void __iomem *page0;
	void __iomem *page1;
};

/**
 * struct tegra241_vintf - Virtual Interface
 * @idx: Global index in the CMDQV HW
 * @enabled: Enable status
 * @hyp_own: Owned by hypervisor (in-kernel)
 * @cmdqv: CMDQV HW pointer
 * @vcmdqs: List of VCMDQ pointers
 * @base: MMIO base address
 */
struct tegra241_vintf {
	u16 idx;

	bool enabled;
	bool hyp_own;

	struct tegra241_cmdqv *cmdqv;
	struct tegra241_vcmdq **vcmdqs;

	void __iomem *base;
};

/**
 * struct tegra241_cmdqv - CMDQ-V for SMMUv3
 * @smmu: SMMUv3 pointer
 * @base: MMIO base address
 * @irq: IRQ number
 * @num_vintfs: Total number of VINTFs
 * @num_vcmdqs: Total number of VCMDQs
 * @num_vcmdqs_per_vintf: Number of preallocated VCMDQs per VINTF
 * @vintf_ids: VINTF id allocator
 * @vtinfs: List of VINTFs
 */
struct tegra241_cmdqv {
	struct arm_smmu_device *smmu;

	void __iomem *base;
	int irq;

	/* CMDQV Hardware Params */
	u16 num_vintfs;
	u16 num_vcmdqs;
	u16 num_vcmdqs_per_vintf;

	struct ida vintf_ids;

	struct tegra241_vintf **vintfs;
};

/* Config and Polling Helpers */

static inline int tegra241_cmdqv_write_config(struct tegra241_cmdqv *cmdqv,
					      void __iomem *addr_config,
					      void __iomem *addr_status,
					      u32 regval, const char *header,
					      bool *out_enabled)
{
	bool en = regval & BIT(0);
	int ret;

	writel(regval, addr_config);
	ret = readl_poll_timeout(addr_status, regval,
				 en ? regval & BIT(0) : !(regval & BIT(0)),
				 1, ARM_SMMU_POLL_TIMEOUT_US);
	if (ret)
		dev_err(cmdqv->smmu->dev, "%sfailed to %sable, STATUS=0x%08X\n",
			header, en ? "en" : "dis", regval);
	if (out_enabled)
		WRITE_ONCE(*out_enabled, regval & BIT(0));
	return ret;
}

static inline int cmdqv_write_config(struct tegra241_cmdqv *cmdqv, u32 regval)
{
	return tegra241_cmdqv_write_config(cmdqv,
					   cmdqv->base + TEGRA241_CMDQV_CONFIG,
					   cmdqv->base + TEGRA241_CMDQV_STATUS,
					   regval, "CMDQV: ", NULL);
}

static inline int vintf_write_config(struct tegra241_vintf *vintf, u32 regval)
{
	char header[16];

	snprintf(header, 16, "VINTF%u: ", vintf->idx);
	return tegra241_cmdqv_write_config(vintf->cmdqv,
					   vintf->base + TEGRA241_VINTF_CONFIG,
					   vintf->base + TEGRA241_VINTF_STATUS,
					   regval, header, &vintf->enabled);
}

static inline const char *lvcmdq_error_header(struct tegra241_vcmdq *vcmdq)
{
	static char header[32];

	if (WARN_ON(!vcmdq->vintf))
		return "";
	snprintf(header, 32, "VINTF%u: VCMDQ%u/LVCMDQ%u: ",
		vcmdq->vintf->idx, vcmdq->idx, vcmdq->lidx);
	return header;
}

static inline int vcmdq_write_config(struct tegra241_vcmdq *vcmdq, u32 regval)
{
	return tegra241_cmdqv_write_config(vcmdq->cmdqv,
					   vcmdq->page0 + TEGRA241_VCMDQ_CONFIG,
					   vcmdq->page0 + TEGRA241_VCMDQ_STATUS,
					   regval, lvcmdq_error_header(vcmdq),
					   &vcmdq->enabled);
}

/* ISR Functions */

static void tegra241_vintf0_handle_error(struct tegra241_vintf *vintf)
{
	int i;

	for (i = 0; i < LVCMDQ_ERR_MAP_NUM_64; i++) {
		u64 lmap = vintf_readq_relaxed(vintf, LVCMDQ_ERR_MAP_64(i));

		while (lmap) {
			unsigned long lidx = __ffs64(lmap) - 1;
			struct tegra241_vcmdq *vcmdq = vintf->vcmdqs[lidx];
			u32 gerror = vcmdq_page0_readl_relaxed(vcmdq, GERROR);

			__arm_smmu_cmdq_skip_err(vintf->cmdqv->smmu,
						 &vcmdq->cmdq.q);
			vcmdq_page0_writel(vcmdq, gerror, GERRORN);
			lmap &= ~BIT_ULL(lidx);
		}
	}
}

static irqreturn_t tegra241_cmdqv_isr(int irq, void *devid)
{
	struct tegra241_cmdqv *cmdqv = (struct tegra241_cmdqv *)devid;
	u64 vintf_map = cmdqv_readq_relaxed(cmdqv, VINTF_ERR_MAP);

	dev_warn(cmdqv->smmu->dev,
		 "unexpected error reported. vintf_map: %016llx, vcmdq_map: %016llx%016llx\n",
		 vintf_map, cmdqv_readq_relaxed(cmdqv, CMDQ_ERR_MAP_64(1)),
		 cmdqv_readq_relaxed(cmdqv, CMDQ_ERR_MAP_64(0)));

	/* Handle VINTF0 and its LVCMDQs */
	if (vintf_map & BIT_ULL(0))
		tegra241_vintf0_handle_error(cmdqv->vintfs[0]);

	return IRQ_HANDLED;
}

/* Command Queue Selecting Function */

static bool tegra241_vintf_support_cmd(struct tegra241_vintf *vintf, u8 opcode)
{
       /* Hypervisor-owned VINTF can execute any command in its VCMDQs */
	if (READ_ONCE(vintf->hyp_own))
		return true;

	/* Guest-owned VINTF must Check against the list of supported CMDs */
	switch (opcode) {
	case CMDQ_OP_TLBI_NH_ASID:
	case CMDQ_OP_TLBI_NH_VA:
	case CMDQ_OP_ATC_INV:
		return true;
	default:
		return false;
	}
}

struct arm_smmu_cmdq *tegra241_cmdqv_get_cmdq(struct arm_smmu_device *smmu,
					      u8 opcode)
{
	struct tegra241_cmdqv *cmdqv = smmu->tegra241_cmdqv;
	struct tegra241_vintf *vintf = cmdqv->vintfs[0];
	struct tegra241_vcmdq *vcmdq;
	u16 lidx;

	if (READ_ONCE(bypass_vcmdq))
		return &smmu->cmdq;

	/* Use SMMU CMDQ if vintfs[0] is uninitialized */
	if (!READ_ONCE(vintf->enabled))
		return &smmu->cmdq;

	/* Unsupported CMD go for smmu->cmdq pathway */
	if (!tegra241_vintf_support_cmd(vintf, opcode))
		return &smmu->cmdq;

	/*
	 * Select a vcmdq to use. Here we use a temporal solution to
	 * balance out traffic on cmdq issuing: each cmdq has its own
	 * lock, if all cpus issue cmdlist using the same cmdq, only
	 * one CPU at a time can enter the process, while the others
	 * will be spinning at the same lock.
	 */
	lidx = smp_processor_id() % cmdqv->num_vcmdqs_per_vintf;
	vcmdq = vintf->vcmdqs[lidx];
	if (!vcmdq || !READ_ONCE(vcmdq->enabled))
		return &smmu->cmdq;
	return &vcmdq->cmdq;
}

/* Device Reset (HW init/deinit) Functions */

static void tegra241_vcmdq_hw_deinit(struct tegra241_vcmdq *vcmdq)
{
	u32 gerrorn, gerror;

	if (vcmdq_write_config(vcmdq, 0)) {
		dev_err(vcmdq->cmdqv->smmu->dev,
			"%sGERRORN=0x%X, GERROR=0x%X, CONS=0x%X\n",
			lvcmdq_error_header(vcmdq),
			vcmdq_page0_readl_relaxed(vcmdq, GERRORN),
			vcmdq_page0_readl_relaxed(vcmdq, GERROR),
			vcmdq_page0_readl_relaxed(vcmdq, CONS));
	}
	vcmdq_page0_writel_relaxed(vcmdq, 0, PROD);
	vcmdq_page0_writel_relaxed(vcmdq, 0, CONS);
	vcmdq_page1_writeq_relaxed(vcmdq, 0, BASE);
	vcmdq_page1_writeq_relaxed(vcmdq, 0, CONS_INDX_BASE);

	gerrorn = vcmdq_page0_readl_relaxed(vcmdq, GERRORN);
	gerror = vcmdq_page0_readl_relaxed(vcmdq, GERROR);
	if (gerror != gerrorn) {
		dev_warn(vcmdq->cmdqv->smmu->dev,
			 "%suncleared error detected, resetting\n",
			 lvcmdq_error_header(vcmdq));
		vcmdq_page0_writel(vcmdq, gerror, GERRORN);
	}

	dev_dbg(vcmdq->cmdqv->smmu->dev,
		"%sdeinited\n", lvcmdq_error_header(vcmdq));
}

static int tegra241_vcmdq_hw_init(struct tegra241_vcmdq *vcmdq)
{
	int ret;

	/* Reset VCMDQ */
	tegra241_vcmdq_hw_deinit(vcmdq);

	/* Configure and enable VCMDQ */
	vcmdq_page1_writeq_relaxed(vcmdq, vcmdq->cmdq.q.q_base, BASE);

	ret = vcmdq_write_config(vcmdq, VCMDQ_EN);
	if (ret) {
		dev_err(vcmdq->cmdqv->smmu->dev,
			"%sGERRORN=0x%X, GERROR=0x%X, CONS=0x%X\n",
			lvcmdq_error_header(vcmdq),
			vcmdq_page0_readl_relaxed(vcmdq, GERRORN),
			vcmdq_page0_readl_relaxed(vcmdq, GERROR),
			vcmdq_page0_readl_relaxed(vcmdq, CONS));
		return ret;
	}

	dev_dbg(vcmdq->cmdqv->smmu->dev,
		"%sinited\n", lvcmdq_error_header(vcmdq));
	return 0;
}

static void tegra241_vintf_hw_deinit(struct tegra241_vintf *vintf)
{
	u16 lidx;

	for (lidx = 0; lidx < vintf->cmdqv->num_vcmdqs_per_vintf; lidx++)
		if (vintf->vcmdqs && vintf->vcmdqs[lidx])
			tegra241_vcmdq_hw_deinit(vintf->vcmdqs[lidx]);
	vintf_write_config(vintf, 0);
}

static int tegra241_vintf_hw_init(struct tegra241_vintf *vintf, bool hyp_own)
{
	u32 regval;
	u16 lidx;
	int ret;

	/* Reset VINTF */
	tegra241_vintf_hw_deinit(vintf);

	/* Configure and enable VINTF */
	/*
	 * Note that HYP_OWN bit is wired to zero when running in guest kernel,
	 * whether enabling it here or not, as !HYP_OWN cmdq HWs only support a
	 * restricted set of supported commands.
	 */
	regval = FIELD_PREP(VINTF_HYP_OWN, hyp_own);
	vintf_writel(vintf, regval, CONFIG);

	ret = vintf_write_config(vintf, regval | VINTF_EN);
	if (ret)
		return ret;
	/*
	 * As being mentioned above, HYP_OWN bit is wired to zero for a guest
	 * kernel, so read it back from HW to ensure that reflects in hyp_own
	 */
	vintf->hyp_own = !!(VINTF_HYP_OWN & vintf_readl(vintf, CONFIG));

	for (lidx = 0; lidx < vintf->cmdqv->num_vcmdqs_per_vintf; lidx++) {
		if (vintf->vcmdqs && vintf->vcmdqs[lidx]) {
			ret = tegra241_vcmdq_hw_init(vintf->vcmdqs[lidx]);
			if (ret) {
				tegra241_vintf_hw_deinit(vintf);
				return ret;
			}
		}
	}

	return 0;
}

int tegra241_cmdqv_device_reset(struct arm_smmu_device *smmu)
{
	struct tegra241_cmdqv *cmdqv = smmu->tegra241_cmdqv;
	struct tegra241_vintf *vintf = cmdqv->vintfs[0];
	u16 qidx, lidx, idx;
	u32 regval;
	int ret;

	/* Reset CMDQV */
	regval = cmdqv_readl_relaxed(cmdqv, CONFIG);
	ret = cmdqv_write_config(cmdqv, regval & ~CMDQV_EN);
	if (ret)
		return ret;
	ret = cmdqv_write_config(cmdqv, regval | CMDQV_EN);
	if (ret)
		return ret;

	/* Assign preallocated global VCMDQs to each VINTF as LVCMDQs */
	for (idx = 0, qidx = 0; idx < cmdqv->num_vintfs; idx++) {
		for (lidx = 0; lidx < cmdqv->num_vcmdqs_per_vintf; lidx++) {
			regval  = FIELD_PREP(CMDQV_CMDQ_ALLOC_VINTF, idx);
			regval |= FIELD_PREP(CMDQV_CMDQ_ALLOC_LVCMDQ, lidx);
			regval |= CMDQV_CMDQ_ALLOCATED;
			cmdqv_writel_relaxed(cmdqv, regval, CMDQ_ALLOC(qidx++));
		}
	}

	return tegra241_vintf_hw_init(vintf, true);
}

/* Probe Functions */

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
tegra241_cmdqv_find_resource(struct arm_smmu_device *smmu,
			     struct acpi_iort_node *node)
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
	match_uid = kasprintf(GFP_KERNEL, "%u", node->identifier);
	adev = acpi_dev_get_first_match_dev(TEGRA241_CMDQV_HID, match_uid, -1);
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

	cmdqv = kzalloc(sizeof(*cmdqv), GFP_KERNEL);
	if (!cmdqv)
		goto free_list;

	cmdqv->smmu = smmu;

	rentry = list_first_entry_or_null(&resource_list,
					  struct resource_entry, node);
	if (!rentry) {
		dev_err(dev, "failed to get memory resource entry\n");
		goto free_cmdqv;
	}

	cmdqv->base = ioremap(rentry->res->start, resource_size(rentry->res));
	if (IS_ERR(cmdqv->base)) {
		dev_err(dev, "failed to ioremap: %ld\n", PTR_ERR(cmdqv->base));
		goto free_cmdqv;
	}

	acpi_dev_free_resource_list(&resource_list);

	INIT_LIST_HEAD(&resource_list);

	ret = acpi_dev_get_resources(adev, &resource_list,
				     tegra241_cmdqv_acpi_get_irqs, &cmdqv->irq);
	if (ret < 0 || cmdqv->irq <= 0) {
		dev_warn(dev, "no interrupt. errors will not be reported\n");
	} else {
		ret = request_irq(cmdqv->irq, tegra241_cmdqv_isr, 0,
				  "tegra241-cmdqv", cmdqv);
		if (ret) {
			dev_err(dev, "failed to request irq (%d): %d\n",
				cmdqv->irq, ret);
			goto iounmap;
		}
	}

	goto free_list;

iounmap:
	iounmap(cmdqv->base);
free_cmdqv:
	kfree(cmdqv);
	cmdqv = NULL;
free_list:
	acpi_dev_free_resource_list(&resource_list);
put_dev:
	put_device(&adev->dev);

	return cmdqv;
}

static int tegra241_vcmdq_alloc_smmu_cmdq(struct tegra241_vcmdq *vcmdq)
{
	struct arm_smmu_device *smmu = vcmdq->cmdqv->smmu;
	struct arm_smmu_cmdq *cmdq = &vcmdq->cmdq;
	struct arm_smmu_queue *q = &cmdq->q;
	char name[16];
	int ret;

	snprintf(name, 16, "vcmdq%u", vcmdq->idx);

	q->llq.max_n_shift = ilog2(SZ_64K >> CMDQ_ENT_SZ_SHIFT);

	/* Use the common helper to init the VCMDQ, and then... */
	ret = arm_smmu_init_one_queue(smmu, q, vcmdq->page0,
				      TEGRA241_VCMDQ_PROD, TEGRA241_VCMDQ_CONS,
				      CMDQ_ENT_DWORDS, name);
	if (ret)
		return ret;

	/* ...override q_base to write VCMDQ_BASE registers */
	q->q_base = q->base_dma & VCMDQ_ADDR;
	q->q_base |= FIELD_PREP(VCMDQ_LOG2SIZE, q->llq.max_n_shift);

	/* All VCMDQs support CS_NONE only for CMD_SYNC */
	q->quirks = CMDQ_QUIRK_SYNC_CS_NONE_ONLY;

	return arm_smmu_cmdq_init(smmu, cmdq);
}

static void tegra241_vcmdq_free_smmu_cmdq(struct tegra241_vcmdq *vcmdq)
{
	struct arm_smmu_queue *q = &vcmdq->cmdq.q;
	size_t nents = 1 << q->llq.max_n_shift;
	size_t qsz = nents << CMDQ_ENT_SZ_SHIFT;

	if (!q->base)
		return;
	dmam_free_coherent(vcmdq->cmdqv->smmu->dev, qsz, q->base, q->base_dma);
}

static int tegra241_vintf_init_lvcmdq(struct tegra241_vintf *vintf, u16 lidx,
				      struct tegra241_vcmdq *vcmdq)
{
	struct tegra241_cmdqv *cmdqv = vintf->cmdqv;
	u16 idx = vintf->idx;

	vcmdq->idx = idx * cmdqv->num_vcmdqs_per_vintf + lidx;
	vcmdq->lidx = lidx;
	vcmdq->cmdqv = cmdqv;
	vcmdq->vintf = vintf;
	vcmdq->page0 = cmdqv->base + TEGRA241_VINTFi_LVCMDQ_PAGE0(idx, lidx);
	vcmdq->page1 = cmdqv->base + TEGRA241_VINTFi_LVCMDQ_PAGE1(idx, lidx);
	return 0;
}

static struct tegra241_vcmdq *
tegra241_vintf_alloc_lvcmdq(struct tegra241_vintf *vintf, u16 lidx)
{
	struct tegra241_cmdqv *cmdqv = vintf->cmdqv;
	struct tegra241_vcmdq *vcmdq;
	int ret;

	vcmdq = kzalloc(sizeof(*vcmdq), GFP_KERNEL);
	if (!vcmdq)
		return ERR_PTR(-ENOMEM);

	ret = tegra241_vintf_init_lvcmdq(vintf, lidx, vcmdq);
	if (ret)
		goto free_vcmdq;

	/* Build an arm_smmu_cmdq for each vcmdq allocated to vintf */
	ret = tegra241_vcmdq_alloc_smmu_cmdq(vcmdq);
	if (ret)
		goto free_vcmdq;

	dev_dbg(cmdqv->smmu->dev, "%sallocated\n", lvcmdq_error_header(vcmdq));
	return vcmdq;
free_vcmdq:
	kfree(vcmdq);
	return ERR_PTR(ret);
}

static void tegra241_vintf_free_lvcmdq(struct tegra241_vcmdq *vcmdq)
{
	tegra241_vcmdq_free_smmu_cmdq(vcmdq);

	dev_dbg(vcmdq->cmdqv->smmu->dev,
		"%sdeallocated\n", lvcmdq_error_header(vcmdq));
	kfree(vcmdq);
}

static int tegra241_cmdqv_init_vintf(struct tegra241_cmdqv *cmdqv, u16 max_idx,
				     struct tegra241_vintf *vintf)
{

	u16 idx;
	int ret;

	ret = ida_alloc_max(&cmdqv->vintf_ids, max_idx, GFP_KERNEL);
	if (ret < 0)
		return ret;
	idx = ret;

	vintf->idx = idx;
	vintf->cmdqv = cmdqv;
	vintf->base = cmdqv->base + TEGRA241_VINTF(idx);

	vintf->vcmdqs = kcalloc(cmdqv->num_vcmdqs_per_vintf,
				sizeof(*vintf->vcmdqs), GFP_KERNEL);
	if (!vintf->vcmdqs) {
		ida_free(&cmdqv->vintf_ids, idx);
		return -ENOMEM;
	}

	cmdqv->vintfs[idx] = vintf;
	return ret;
}

static void tegra241_cmdqv_deinit_vintf(struct tegra241_cmdqv *cmdqv, u16 idx)
{
	kfree(cmdqv->vintfs[idx]->vcmdqs);
	ida_free(&cmdqv->vintf_ids, idx);
	cmdqv->vintfs[idx] = NULL;
}

struct dentry *cmdqv_debugfs_dir;

static int tegra241_cmdqv_probe(struct tegra241_cmdqv *cmdqv)
{
	struct tegra241_vintf *vintf;
	u32 regval;
	u16 lidx;
	int ret;

	regval = cmdqv_readl(cmdqv, CONFIG);
	if (disable_cmdqv) {
		dev_info(cmdqv->smmu->dev,
			 "disable_cmdqv=true. Falling back to SMMU CMDQ\n");
		cmdqv_write_config(cmdqv, regval & ~CMDQV_EN);
		return -ENODEV;
	}

	ret = cmdqv_write_config(cmdqv, regval | CMDQV_EN);
	if (ret)
		return ret;

	regval = cmdqv_readl_relaxed(cmdqv, PARAM);
	cmdqv->num_vintfs = 1 << FIELD_GET(CMDQV_NUM_VINTF_LOG2, regval);
	cmdqv->num_vcmdqs = 1 << FIELD_GET(CMDQV_NUM_VCMDQ_LOG2, regval);
	cmdqv->num_vcmdqs_per_vintf = cmdqv->num_vcmdqs / cmdqv->num_vintfs;

	cmdqv->vintfs = kcalloc(cmdqv->num_vintfs,
				sizeof(*cmdqv->vintfs), GFP_KERNEL);
	if (!cmdqv->vintfs)
		return -ENOMEM;
	ida_init(&cmdqv->vintf_ids);

	vintf = kzalloc(sizeof(*vintf), GFP_KERNEL);
	if (!vintf) {
		ret = -ENOMEM;
		goto destroy_ids;
	}

	/* Init vintfs[0] for in-kernel use */
	ret = tegra241_cmdqv_init_vintf(cmdqv, 0, vintf);
	if (ret) {
		dev_err(cmdqv->smmu->dev, "failed to init vintf0: %d\n", ret);
		goto free_vintf;
	}

	/* Preallocate logical vcmdqs to vintf */
	for (lidx = 0; lidx < cmdqv->num_vcmdqs_per_vintf; lidx++) {
		struct tegra241_vcmdq *vcmdq;

		vcmdq = tegra241_vintf_alloc_lvcmdq(vintf, lidx);
		if (IS_ERR(vcmdq)) {
			ret = PTR_ERR(vcmdq);
			goto free_lvcmdq;
		}
		vintf->vcmdqs[lidx] = vcmdq;
	}

#ifdef CONFIG_IOMMU_DEBUGFS
	if (!cmdqv_debugfs_dir) {
		cmdqv_debugfs_dir =
			debugfs_create_dir("tegra241_cmdqv", iommu_debugfs_dir);
		debugfs_create_bool("bypass_vcmdq", 0644,
				    cmdqv_debugfs_dir, &bypass_vcmdq);
	}
#endif

	return 0;

free_lvcmdq:
	for (lidx--; lidx >= 0; lidx--)
		tegra241_vintf_free_lvcmdq(vintf->vcmdqs[lidx]);
	tegra241_cmdqv_deinit_vintf(cmdqv, vintf->idx);
free_vintf:
	kfree(vintf);
destroy_ids:
	ida_destroy(&cmdqv->vintf_ids);
	kfree(cmdqv->vintfs);
	return ret;
}

struct tegra241_cmdqv *tegra241_cmdqv_acpi_probe(struct arm_smmu_device *smmu,
						 struct acpi_iort_node *node)
{
	struct tegra241_cmdqv *cmdqv;

	cmdqv = tegra241_cmdqv_find_resource(smmu, node);
	if (!cmdqv)
		return NULL;

	if (tegra241_cmdqv_probe(cmdqv)) {
		if (cmdqv->irq > 0)
			free_irq(cmdqv->irq, cmdqv);
		iounmap(cmdqv->base);
		kfree(cmdqv);
		return NULL;
	}

	return cmdqv;
}

/* Remove Functions */

static void tegra241_vintf_remove_lvcmdq(struct tegra241_vintf *vintf, u16 lidx)
{
	tegra241_vcmdq_hw_deinit(vintf->vcmdqs[lidx]);
	tegra241_vintf_free_lvcmdq(vintf->vcmdqs[lidx]);
	vintf->vcmdqs[lidx] = NULL;
}

static void tegra241_cmdqv_remove_vintf(struct tegra241_cmdqv *cmdqv, u16 idx)
{
	struct tegra241_vintf *vintf = cmdqv->vintfs[idx];
	u16 lidx;

	/* Remove lvcmdq resources */
	for (lidx = 0; lidx < vintf->cmdqv->num_vcmdqs_per_vintf; lidx++)
		if (vintf->vcmdqs[lidx])
			tegra241_vintf_remove_lvcmdq(vintf, lidx);

	/* Remove vintf resources */
	tegra241_vintf_hw_deinit(vintf);
	ida_free(&cmdqv->vintf_ids, vintf->idx);
	cmdqv->vintfs[idx] = NULL;

	dev_dbg(cmdqv->smmu->dev, "VINTF%u: deallocated\n", vintf->idx);
	kfree(vintf->vcmdqs);
	kfree(vintf);
}

void tegra241_cmdqv_device_remove(struct arm_smmu_device *smmu)
{
	struct tegra241_cmdqv *cmdqv = smmu->tegra241_cmdqv;
	u16 idx;

	/* Remove vintf resources */
	for (idx = 0; idx < cmdqv->num_vintfs; idx++) {
		if (cmdqv->vintfs[idx]) {
			/* Only vintf0 should remain at this stage */
			WARN_ON(idx > 0);
			tegra241_cmdqv_remove_vintf(cmdqv, idx);
		}
	}

	/* Remove cmdqv resources */
	ida_destroy(&cmdqv->vintf_ids);
	smmu->tegra241_cmdqv = NULL;

	if (cmdqv->irq > 0)
		free_irq(cmdqv->irq, cmdqv);
	iounmap(cmdqv->base);
	kfree(cmdqv->vintfs);
	kfree(cmdqv);
}
