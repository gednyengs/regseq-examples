#include <linux/clk.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_irq.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/wait.h>
#include <linux/uaccess.h>

#include "SimpleAES.h"

// =============================================================================
// Driver Info
// =============================================================================

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Org Simple");
MODULE_DESCRIPTION("SimpleAES Device Specification");
MODULE_VERSION("0.1.0");

// =============================================================================
// Function Prototypes
// =============================================================================

// Device functions

static irqreturn_t SimpleAES_IrqHandler(int irq_no, void *dev_id);
static Result_BoolError SimpleAES_Encrypt(SimpleAES *InstancePtr, u8 key[],
					  u8 i_data[], u8 o_data[]);
static Result_BoolError SimpleAES_Decrypt(SimpleAES *InstancePtr, u8 key[],
					  u8 i_data[], u8 o_data[]);
static Result_BoolError SimpleAES_RunOp(SimpleAES *InstancePtr,
					ORG_SIMPLE_OpMode mode, u8 key[],
					u8 i_data[], u8 o_data[]);
static bool SimpleAES_Busy(SimpleAES *InstancePtr);
static Result_BoolError SimpleAES_SetMode(SimpleAES *InstancePtr,
					  ORG_SIMPLE_OpMode mode);
static Result_BoolError SimpleAES_SetKeyAddr(SimpleAES *InstancePtr, u32 addr);
static Result_BoolError SimpleAES_SetInputAddr(SimpleAES *InstancePtr,
					       u32 addr);
static Result_BoolError SimpleAES_SetOutputAddr(SimpleAES *InstancePtr,
						u32 addr);
static void SimpleAES_WaitCompletion(SimpleAES *InstancePtr);

// std.Notification<Error>

static int Notification_Error_Init(Notification_Error *InstancePtr);
static void Notification_Error_Send(Notification_Error *InstancePtr,
				    ORG_SIMPLE_Error data);
static int Notification_Error_Receive(Notification_Error *InstancePtr,
				      ORG_SIMPLE_Error *DataPtr);
static void Notification_Error_DeInit(Notification_Error *InstancePtr);

// Character device (cdev) callbacks

static int simpleaes_cdev_open(struct inode *inode_ptr, struct file *file_ptr);
static int simpleaes_cdev_release(struct inode *inode_ptr,
				  struct file *file_ptr);
static long simpleaes_cdev_ioctl(struct file *file_ptr, unsigned int cmd,
				 unsigned long arg);

// Device management

static int SimpleAES_probe(struct platform_device *pdev);
static int SimpleAES_remove(struct platform_device *pdev);

// =============================================================================
// Variable Definitions
// =============================================================================

static struct file_operations simpleaes_cdev_fops = {
	.open		= simpleaes_cdev_open,
	.unlocked_ioctl = simpleaes_cdev_ioctl,
	.release	= simpleaes_cdev_release,
};

// =============================================================================
// Function Definitions
// =============================================================================

// Device functions

static irqreturn_t SimpleAES_IrqHandler(int irq_no, void *dev_id)
{
	SimpleAES *simpleaes_ptr = (SimpleAES *)dev_id;

	Notification_Error *notif   = &simpleaes_ptr->notif;
	void __iomem *ptr	    = simpleaes_ptr->regfile.ptr;
	struct spinlock_t *lock_ptr = &simpleaes_ptr->regfile.lock;

	unsigned long lock_irq_flags;
	u32 irq_stat;
	u32 stat_err;

	spin_lock_irqsave(lock_ptr, lock_irq_flags);

	irq_stat = SIMPLEAES_REG_READ(IRQ, ptr);
	if (irq_stat[0] == 1) {
		Notification_Error_Send(notif, ERROR_OK);
	} else if (irq_stat[1] == 1) {
		stat_err = SIMPLEAES_FIELD_READ(ERR, STAT, ptr);
		switch (stat_err) {
		case 1:
			Notification_Error_Send(notif, ERROR_KEY);
			break;
		case 2:
			Notification_Error_Send(notif, ERROR_INPUT);
			break;
		case 3:
			Notification_Error_Send(notif, ERROR_OUTPUT);
			break;
		}
	}

	SIMPLEAES_REG_WRITE(irq_stat, IRQ, ptr);

	spin_unlock_irqrestore(lock_ptr, lock_irq_flags);

	return IRQ_HANDLED;
}

static Result_BoolError SimpleAES_Encrypt(SimpleAES *InstancePtr, u8 key[],
					  u8 i_data[], u8 o_data[])
{
	return SimpleAES_RunOp(InstancePtr, ORG_SIMPLE_OPMODE_ENCRYPT, key,
			       i_data, o_data);
}

static Result_BoolError SimpleAES_Decrypt(SimpleAES *InstancePtr, u8 key[],
					  u8 i_data[], u8 o_data[])
{
	return SimpleAES_RunOp(InstancePtr, ORG_SIMPLE_OPMODE_DECRYPT, key,
			       i_data, o_data);
}

static bool SimpleAES_Busy(SimpleAES *InstancePtr)
{
	void __iomem *ptr	    = InstancePtr->regfile.ptr;
	struct spinlock_t *lock_ptr = &InstancePtr->regfile.lock;
	unsigned long lock_irq_flags;
	u32 stat_busy;

	spin_lock_irqsave(lock_ptr, lock_irq_flags);
	stat_busy = SIMPLEAES_FIELD_READ(BUSY, STAT, ptr);
	spin_unlock_irqrestore(lock_ptr, lock_irq_flags);

	return stat_busy == 1;
}

static Result_BoolError SimpleAES_SetMode(SimpleAES *InstancePtr,
					  ORG_SIMPLE_OpMode mode)
{
	void __iomem *ptr	    = InstancePtr->regfile.ptr;
	struct spinlock_t *lock_ptr = &InstancePtr->regfile.lock;
	unsigned long lock_irq_flags;

	if (SimpleAES_Busy(InstancePtr)) {
		return RESULT_BOOLERROR_ERROR(ERROR_BUSY);
	}

	spin_lock_irqsave(lock_ptr, lock_irq_flags);
	SIMPLEAES_FIELD_WRITE((u32)mode, OP, CTRL, ptr);
	SIMPLEAES_FIELD_WRITE(1, IE, CTRL, ptr);
	spin_unlock_irqrestore(lock_ptr, lock_irq_flags);

	return RESULT_BOOLERROR_BOOL(1);
}

static Result_BoolError SimpleAES_SetKeyAddr(SimpleAES *InstancePtr, u32 addr)
{
	void __iomem *ptr	    = InstancePtr->regfile.ptr;
	struct spinlock_t *lock_ptr = &InstancePtr->regfile.lock;
	unsigned long lock_irq_flags;

	spin_lock_irqsave(lock_ptr, lock_irq_flags);
	SIMPLEAES_REG_WRITE(addr, KAR, ptr);
	spin_unlock_irqrestore(lock_ptr, lock_irq_flags);

	return RESULT_BOOLERROR_BOOL(1);
}

static Result_BoolError SimpleAES_SetInputAddr(SimpleAES *InstancePtr, u32 addr)
{
	void __iomem *ptr	    = InstancePtr->regfile.ptr;
	struct spinlock_t *lock_ptr = &InstancePtr->regfile.lock;
	unsigned long lock_irq_flags;

	spin_lock_irqsave(lock_ptr, lock_irq_flags);
	SIMPLEAES_REG_WRITE(addr, IAR, ptr);
	spin_unlock_irqrestore(lock_ptr, lock_irq_flags);

	return RESULT_BOOLERROR_BOOL(1);
}

static Result_BoolError SimpleAES_SetOutputAddr(SimpleAES *InstancePtr,
						u32 addr)
{
	void __iomem *ptr	    = InstancePtr->regfile.ptr;
	struct spinlock_t *lock_ptr = &InstancePtr->regfile.lock;
	unsigned long lock_irq_flags;

	spin_lock_irqsave(lock_ptr, lock_irq_flags);
	SIMPLEAES_REG_WRITE(addr, OAR, ptr);
	spin_unlock_irqrestore(lock_ptr, lock_irq_flags);

	return RESULT_BOOLERROR_BOOL(1);
}

static Result_BoolError SimpleAES_RunOp(SimpleAES *InstancePtr,
					ORG_SIMPLE_OpMode mode, u8 key[],
					u8 i_data[], u8 o_data[])
{
	struct device *dev_ptr = &InstancePtr->pdev.dev;

	HwBuffer key_buf, in_buffer, out_buffer;
	Result_BoolError ret_err_boolerror = RESULT_BOOLERROR_OK(1);
	Result_BoolError err_boolerror;
	ORG_SIMPLE_Error notif_val;
	unsigned long ret_copy;

	key_buf.cpu_addr = dma_alloc_coherent(dev_ptr, ORG_SIMPLE_KD_SIZE,
					      &key_buf.bus_addr, GFP_KERNEL);
	if (IS_ERR(key_buf.cpu_addr)) {
		dev_err(dev_ptr, "failed to allocate buffer for key");
		ret_err_boolerror = RESULT_BOOLERROR_ERROR(ERROR_KEY);
		goto __simpleaes_runop_ret;
	}

	input_buf.cpu_addr = dma_alloc_coherent(
		dev_ptr, ORG_SIMPLE_KD_SIZE, &input_buf.bus_addr, GFP_KERNEL);
	if (IS_ERR(input_buf.cpu_addr)) {
		dev_err(dev_ptr, "failed to allocate buffer for input data");
		ret_err_boolerror = RESULT_BOOLERROR_ERROR(ERROR_INPUT);
		goto __simpleaes_runop_undo_res1;
	}

	output_buf.cpu_addr = dma_alloc_coherent(
		dev_ptr, ORG_SIMPLE_KD_SIZE, &output_buf.bus_addr, GFP_KERNEL);
	if (IS_ERR(output_buf.cpu_addr)) {
		dev_err(dev_ptr, "failed to allocate buffer for output data");
		ret_err_boolerror = RESULT_BOOLERROR_ERROR(ERROR_OUTPUT);
		goto __simpleaes_runop_undo_res2;
	}

	err_boolerror = SimpleAES_SetMode(InstancePtr, mode);
	if (err_boolerror.variant == RESULT_ERR) {
		dev_err(dev_ptr, "failed to set operation mode");
		ret_err_boolerror = err_boolerror;
		goto __simpleaes_runop_undo_res3;
	}

	ret_copy = copy_from_user(key_buf.cpu_addr, key, ORG_SIMPLE_KD_SIZE);
	if (ret_copy) {
		dev_err("failed to copy key");
		ret_err_boolerror = RESULT_BOOLERROR_ERROR(ERROR_KEY);
		goto __simpleaes_runop_undo_res3;
	}

	ret_copy =
		copy_from_user(input_buf.cpu_addr, i_data, ORG_SIMPLE_KD_SIZE);
	if (ret_copy) {
		dev_err("failed to copy input data");
		ret_err_boolerror = RESULT_BOOLERROR_ERROR(ERROR_INPUT);
		goto __simpleaes_runop_undo_res3;
	}

	err_boolerror =
		SimpleAES_SetKeyAddr(InstancePtr, (u32)key_buf.bus_addr);
	if (err_boolerror.variant == RESULT_ERR) {
		dev_err(dev_ptr, "failed to set key address");
		ret_err_boolerror = err_boolerror;
		goto __simpleaes_runop_undo_res3;
	}

	err_boolerror =
		SimpleAES_SetInputAddr(InstancePtr, (u32)input_buf.bus_addr);
	if (err_boolerror.variant == RESULT_ERR) {
		dev_err(dev_ptr, "failed to set input data address");
		ret_err_boolerror = err_boolerror;
		goto __simpleaes_runop_undo_res3;
	}

	err_boolerror =
		SimpleAES_SetOutputAddr(InstancePtr, (u32)output_buf.bus_addr);
	if (err_boolerror.variant == RESULT_ERR) {
		dev_err(dev_ptr, "failed to set output data address");
		ret_err_boolerror = err_boolerror;
		goto __simpleaes_runop_undo_res3;
	}

	if (Notification_Error_Receive(&InstancePtr->notif, &notif_val)) {
		dev_err(dev_ptr, "Operation failed");
		ret_err_boolerror = RESULT_BOOLERROR_ERROR(ERROR_OTHER);
		goto __simpleaes_runop_undo_res3;
	}

	ret_copy =
		copy_to_user(o_data, output_buf.cpu_addr, ORG_SIMPLE_KD_SIZE);
	if (ret_copy) {
		dev_err("failed to copy output data");
		ret_err_boolerror = RESULT_BOOLERROR_ERROR(ERROR_OUTPUT);
		goto __simpleaes_runop_undo_res3;
	}

	goto __simpleaes_runop_ret;

__simpleaes_runop_undo_res3:
	dma_free_coherent(dev_ptr, ORG_SIMPLE_KD_SIZE, output_buf.cpu_addr,
			  output_buf.bus_addr);

__simpleaes_runop_undo_res2:
	dma_free_coherent(dev_ptr, ORG_SIMPLE_KD_SIZE, input_buf.cpu_addr,
			  input_buf.bus_addr);

__simpleaes_runop_undo_res1:
	dma_free_coherent(dev_ptr, ORG_SIMPLE_KD_SIZE, key_buf.cpu_addr,
			  key_buf.bus_addr);

__simpleaes_runop_ret:
	return ret_err_boolerror;
}

// std.Notification<Error>

static int Notification_Error_Init(Notification_Error *InstancePtr)
{
	init_waitqueue_head(&InstancePtr->wq);
	InstancePtr->flag = 0;
	return 0;
}

static void Notification_Error_Send(Notification_Error *InstancePtr,
				    ORG_SIMPLE_Error data)
{
	InstancePtr->flag = 1;
	InstancePtr->data = data;
	wake_up_interruptible(&InstancePtr->wq);
}

static int Notification_Error_Receive(Notification_Error *InstancePtr,
				      ORG_SIMPLE_Error *DataPtr)
{
	int ret = wait_event_interruptible(InstancePtr->wq,
					   InstancePtr->flag == 1);
	if (InstancePtr->flag != 1) {
		return -EAGAIN;
	}

	InstancePtr->flag = 0;
	*DataPtr	  = InstancePtr->data;
	return ret;
}

static void Notification_Error_DeInit(Notification_Error *InstancePtr)
{
}

// Character device (cdev) callbacks

static int simpleaes_cdev_open(struct inode *inode_ptr, struct file *file_ptr)
{
	return 0;
}

static int simpleaes_cdev_release(struct inode *inode_ptr,
				  struct file *file_ptr)
{
	return 0;
}

static long simpleaes_cdev_ioctl(struct file *file_ptr, unsigned int cmd,
				 unsigned long arg)
{
	IOCTL_Data data;
	Result_BoolError err_boolerror;
	SimpleAES *simpleaes_ptr =
		(SimpleAES *)container_of(file_ptr->f_op, SimpleAES, f_ops);

	switch (cmd) {
	case IOCTL_ENCRYPT:
		if (copy_from_user((void *)&data, (void *)arg, sizeof(data))) {
			return -EFAULT;
		}
		err_boolerror = SimpleAES_Encrypt(simpleaes_ptr, data.key_ptr,
						  data.i_data_ptr,
						  data.o_data_ptr);
		if (err_boolerror.variant == RESULT_ERR) {
			return -EIO;
		}
	case IOCTL_DECRYPT:
		if (copy_from_user((void *)&data, (void *)arg, sizeof(data))) {
			return -EFAULT;
		}
		err_boolerror = SimpleAES_Decrypt(simpleaes_ptr, data.key_ptr,
						  data.i_data_ptr,
						  data.o_data_ptr);
		if (err_boolerror.variant == RESULT_ERR) {
			return -EIO;
		}
	default:
		return -EINVAL;
	}

	return 0;
}

// Device management

static int SimpleAES_probe(struct platform_device *pdev)
{
	int ret = 0;

	//--------------------------------------------------------------------------
	// 1. Allocate device instance data
	//--------------------------------------------------------------------------
	SimpleAES *simpleaes_ptr = (SimpleAES *)devm_kzalloc(
		&pdev->dev, sizeof(SimpleAES), GFP_KERNEL);
	if (IS_ERR(simpleaes_ptr)) {
		dev_err(&pdev->dev,
			"Failed to allocate memory for device instance data");
		ret = PTR_ERR(simpleaes_ptr);
		goto SimpleAES_probe_ret;
	}

	//--------------------------------------------------------------------------
	// 2. Get device interrupt resource
	//--------------------------------------------------------------------------

	simpleaes_ptr->irq_line =
		platform_get_irq_byname(pdev, "simpleaes-irq");
	if (simpleaes_ptr->irq_line <= 0) {
		dev_err(&pdev->dev, "simpleaes-irq interrupt not found");
		ret = -ENODATA;
		goto SimpleAES_probe_ret;
	}

	//--------------------------------------------------------------------------
	// 3. Get device register space resource
	//--------------------------------------------------------------------------

	simpleaes_ptr->regfile.ptr =
		devm_platform_ioremap_resource_byname(pdev, "simpleaes-regmem");
	if (IS_ERR(simpleaes_ptr->regfile.ptr)) {
		dev_err(&pdev->dev,
			"simpleaes-regmem memory resource not found");
		ret = PTR_ERR(simpleaes_ptr->regfile.ptr);
		goto SimpleAES_probe_ret;
	}

	//--------------------------------------------------------------------------
	// 4. Get device clock resource
	//--------------------------------------------------------------------------

	simpleaes_ptr->axi_clock = devm_clk_get_byname(pdev, "simpleaes-clock");
	if (IS_ERR(simpleaes_ptr->axi_clock)) {
		dev_err(&pdev->dev, "simpleaes-clock clock resource not found");
		ret = PTR_ERR(simpleaes_ptr->axi_clock);
		goto SimpleAES_probe_ret;
	}

	//--------------------------------------------------------------------------
	// 5. Initialize resources
	//--------------------------------------------------------------------------

	// Notification (notif)
	Notification_Error_Init(&simpleaes_ptr->notif);

	// Interrupt (irq_line)
	ret = request_irq(simpleaes_ptr->irq_line, SimpleAES_IrqHandler,
			  IRQF_SHARED, "simpleaes-irq", pdev);
	if (ret) {
		dev_err(&pdev->dev,
			"Failed to request and set up interrupt handler");
		goto SimpleAES_probe_ret;
	}

	// Clock (axi_clock)
	ret = clk_prepare_enable(simpleaes_ptr->axi_clock);
	if (ret) {
		dev_err(&pdev->dev, "Failed to enable clock");
		goto SimpleAES_probe_ret;
	}

	// Lock (regfile)
	spin_lock_init(&simpleaes_ptr->regfile.lock);

	//--------------------------------------------------------------------------
	// 6. Create 'character device' (cdev) user interface
	//--------------------------------------------------------------------------

	simpleaes_ptr->f_ops.open	    = simpleaes_cdev_open;
	simpleaes_ptr->f_ops.release	    = simpleaes_cdev_release;
	simpleaes_ptr->f_ops.unlocked_ioctl = simpleaes_cdev_ioctl;

	ret = alloc_chrdev_region(&simpleaes_ptr->cdev.devno, 0, 1,
				  SIMPLEAES_DEVICE_NAME);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to allocate major number");
		goto SimpleAES_probe_error_free_irq;
	}

	cdev_init(&simpleaes_ptr->cdev.cdev, &simpleaes_ptr->f_ops);
	ret = cdev_add(&simpleaes_ptr->cdev.cdev, simpleaes_ptr->cdev.devno, 1);
	if (ret < 0) {
		dev_err(&pdev->dev, "Failed to add character device");
		goto SimpleAES_probe_error_unregister_chrdev_region;
	}

	simpleaes_ptr->cdev.class_ptr =
		class_create(THIS_MODULE, SIMPLEAES_DEVICE_NAME);
	if (IR_ERR(simpleaes_ptr->cdev.class_ptr)) {
		dev_err(&pdev->dev, "Failed to create device class");
		ret = PTR_ERR(simpleaes_ptr->cdev.class_ptr);
		goto SimpleAES_probe_error_cdev_del;
	}

	simpleaes_ptr->cdev.device_ptr = device_create(
		simpleaes_ptr->cdev.class_ptr, NULL, simpleaes_ptr->cdev.devno,
		NULL, SIMPLEAES_DEVICE_NAME);
	if (IS_ERR(simpleaes_ptr->cdev.device_ptr)) {
		dev_err(&pdev->dev, "Failed to create cdev");
		ret = PTR_ERR(simpleaes_ptr->cdev.device_ptr);
		goto SimpleAES_probe_error_class_destroy;
	}

	//--------------------------------------------------------------------------
	// 7. Store instance data structure
	//--------------------------------------------------------------------------

	simpleaes_ptr->pdev_ptr = pdev;
	platform_set_drvdata(pdev, simpleaes_ptr);

	return 0;

	//--------------------------------------------------------------------------
	// Return path
	//--------------------------------------------------------------------------

SimpleAES_probe_error_class_destroy:
	class_destroy(simpleaes_ptr->cdev.class_ptr);

SimpleAES_probe_error_cdev_del:
	cdev_del(&simpleaes_ptr->cdev.cdev);

SimpleAES_probe_error_unregister_chrdev_region:
	unregister_chrdev_region(simpleaes_ptr->cdev.devno, 1);

SimpleAES_probe_error_free_irq:
	free_irq(simpleaes_ptr->irq_line, pdev);

SimpleAES_probe_error_clk_deinit:
	clk_disable_unprepare(simpleaes_ptr->axi_clock);

SimpleAES_probe_ret:
	return ret;
}

static int SimpleAES_remove(struct platform_device *pdev)
{
	SimpleAES *simpleaes_ptr = pdev->private_data;

	// CDEV
	device_destroy(simpleaes_ptr->cdev.class_ptr,
		       simpleaes_ptr->cdev.devno);
	class_destroy(simpleaes_ptr->cdev.class_ptr);
	cdev_del(&simpleaes_ptr->cdev.cdev);
	unregister_chrdev_region(simpleaes_ptr->cdev.devno, 1);

	// Clock
	clk_disable_unprepare(simpleaes_ptr->axi_clock);

	// Interrupt
	free_irq(simpleaes_ptr->irq_line, pdev);
}

// =============================================================================
// Driver Registration
// =============================================================================

// OF match ID table
static const struct of_device_id simpleaes_match_ids[] = {
	{ .compatible = "org-simple-simpleaes" },
	{}
};
MODULE_DEVICE_TABLE(of, simpleaes_match_ids);

// Platform driver
static struct platform_driver simpleaes_driver = {
    .probe = SimpleAES_probe,
    .remove = SimpleAES_remove,
    .driver =
        {
            .name = SIMPLEAES_DEVICE_NAME,
            .of_match_table = simpleaes_match_ids,
        },
};

module_platform_driver(simpleaes_driver);
