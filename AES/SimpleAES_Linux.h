#ifndef ORG_SIMPLE_SIMPLEAES_H
#define ORG_SIMPLE_SIMPLEAES_H

//==============================================================================
// General Macros
//==============================================================================

// Concatenation
#define CONCAT1(a, b) a##b
#define CONCAT2(a, b) CONCAT1(a, b)
#define CONCAT3(a, b) CONCAT2(a, b)
#define CONCAT(a, b)  CONCAT3(a, b)

// Error reporting
#define REPORT_EMERGENCY(dev, fmt, ...) \
	dev_emerg(dev, "%s:%d" fmt, __func, __LINE__, ##__VA__ARGS__)

#define REPORT_ERROR(dev, fmt, ...) \
	dev_err(dev, "%s:%d" fmt, __func, __LINE__, ##__VA__ARGS__)

#define REPORT_ALERT(dev, fmt, ...) \
	dev_alert(dev, "%s:%d" fmt, __func, __LINE__, ##__VA__ARGS__)

#define REPORT_CRITICAL(dev, fmt, ...) \
	dev_crit(dev, "%s:%d" fmt, __func, __LINE__, ##__VA__ARGS__)

#define REPORT_WARNING(dev, fmt, ...) \
	dev_warn(dev, "%s:%d" fmt, __func, __LINE__, ##__VA__ARGS__)

#define REPORT_NOTICE(dev, fmt, ...) \
	dev_notice(dev, "%s:%d" fmt, __func, __LINE__, ##__VA__ARGS__)

#define REPORT_INFO(dev, fmt, ...) \
	dev_info(dev, "%s:%d" fmt, __func, __LINE__, ##__VA__ARGS__)

#define REPORT_DEBUG(dev, fmt, ...) \
	dev_dbg(dev, "%s:%d" fmt, __func, __LINE__, ##__VA__ARGS__)

//==============================================================================
// SimpleAES Register File Specification
//==============================================================================

// CTRL (control register)
#define SIMPLEAES_CTRL_OFFSET 0x00

#define SIMPLEAES_CTRL_OP_Pos  0 // Operation field
#define SIMPLEAES_CTRL_OP_Mask (0x1ul << SIMPLEAES_CTRL_OP_Pos)

#define SIMPLEAES_CTRL_IE_Pos  1 // Interrupt enable field
#define SIMPLEAES_CTRL_IE_Mask (0x1ul << SIMPLEAES_CTRL_IE_Pos)

// STAT (status register)
#define SIMPLEAES_STAT_OFFSET 0x04

#define SIMPLEAES_STAT_BUSY_Pos	 0 // Busy field
#define SIMPLEAES_STAT_BUSY_Mask (0x1ul << SIMPLEAES_STAT_BUSY_Pos)

#define SIMPLEAES_STAT_IRQ_Pos	1 // interrupt pending field
#define SIMPLEAES_STAT_IRQ_Mask (0x1ul << SIMPLEAES_STAT_IRQ_Pos)

#define SIMPLEAES_STAT_ERR_Pos	2 // Error code field
#define SIMPLEAES_STAT_ERR_Mask (0x3ul << SIMPLEAES_STAT_ERR_Pos)

// IRQ (interrupt status register)
#define SIMPLEAES_IRQ_OFFSET 0x08

#define SIMPLEAES_IRQ_COMPLETE_Pos  0 // completion field
#define SIMPLEAES_IRQ_COMPLETE_Mask (0x1ul << SIMPLEAES_IRQ_COMPLETE_Pos)

#define SIMPLEAES_IRQ_ERR_Pos  1 // error field
#define SIMPLEAES_IRQ_ERR_Mask (0x1ul << SIMPLEAES_IRQ_ERR_Pos)

// KAR (key address register)
#define SIMPLEAES_KAR_OFFSET 0x0C

#define SIMPLEAES_KAR_ADDR_Pos	0 // error field
#define SIMPLEAES_KAR_ADDR_Mask (0xFFFFFFFFul << SIMPLEAES_KAR_ADDR_Pos)

// IAR (input address register)
#define SIMPLEAES_IAR_OFFSET 0x10

#define SIMPLEAES_IAR_ADDR_Pos	0 // error field
#define SIMPLEAES_IAR_ADDR_Mask (0xFFFFFFFFul << SIMPLEAES_IAR_ADDR_Pos)

// OAR (output address register)
#define SIMPLEAES_OAR_OFFSET 0x14

#define SIMPLEAES_OAR_ADDR_Pos	0 // error field
#define SIMPLEAES_OAR_ADDR_Mask (0xFFFFFFFFul << SIMPLEAES_OAR_ADDR_Pos)

//==============================================================================
//  SimpleAES Register File Macros
//==============================================================================

#define SIMPLEAES_MAKE_REG(reg) CONCAT(SIMPLEAES_, reg)

#define SIMPLEAES_MAKE_REG_OFFSET(reg) CONCAT(SIMPLEAES_MAKE_REG(reg), _OFFSET)

#define SIMPLEAES_MAKE_FIELD(reg, field) \
	CONCAT(CONCAT(SIMPLEAES_MAKE_REG(reg), _), field)

#define SIMPLEAES_MAKE_FIELD_POS(reg, field) \
	CONCAT(SIMPLEAES_MAKE_FIELD(reg, field), _Pos)

#define SIMPLEAES_MAKE_FIELD_MASK(reg, field) \
	CONCAT(SIMPLEAES_MAKE_FIELD(reg, field), _Mask)

#define SIMPLEAES_REG_WRITE(val, reg, base) \
	iowrite32(val, (base) + SIMPLEAES_MAKE_REG_OFFSET(reg))

#define SIMPLEAES_REG_READ(reg, base) \
	ioread32((base) + SIMPLEAES_MAKE_REG_OFFSET(reg))

#define SIMPLEAES_FIELD_WRITE(val, field, reg, base) \
	SIMPLEAES_REG_WRITE((SIMPLEAES_REG_READ(reg, base) & \
			     ~SIMPLEAES_MAKE_FIELD_MASK(reg, field)) | \
				    (val \
				     << SIMPLEAES_MAKE_FIELD_POS(reg, field)), \
			    reg, base)

#define SIMPLEAES_FIELD_READ(field, reg, base) \
	(SIMPLEAES_REG_READ(reg, base) & \
	 SIMPLEAES_MAKE_FIELD_MASK(reg, field)) >> \
		SIMPLEAES_MAKE_FIELD_POS(reg, field)

//==============================================================================
// Type Definitions
//==============================================================================

// Error types for SimpleAES
typedef enum {
	ERROR_OK,     // No Error
	ERROR_KEY,    // Key read error
	ERROR_INPUT,  // Input read error
	ERROR_OUTPUT, // Output write error
	ERROR_BUSY,   // Device is busy with previous operation
	ERROR_OTHER   // Other errors
} ORG_SIMPLE_Error;

// Operation Mode
typedef enum {
	ORG_SIMPLE_OPMODE_ENCRYPT = 0, // Encryption mode
	ORG_SIMPLE_OPMODE_DECRYPT = 1  // Decryption mode
} ORG_SIMPLE_OpMode;

// std.Result Variant Type
typedef enum { RESULT_OK, RESULT_ERR } ResultVariant;

// Result<Bool, Error>
typedef struct {
	ResultVariant variant;
	union {
		bool ok;
		ORG_SIMPLE_Error err;
	} value;
} Result_BoolError;

#define RESULT_BOOLERROR_OK(ok) \
	Result_BoolError \
	{ \
		.variant = RESULT_OK, .value.ok = (ok) \
	}

#define RESULT_BOOLERROR_ERR(e) \
	Result_BoolError \
	{ \
		.variant = RESULT_ERR, .value.err = (e) \
	}

// HwBuffer
typedef struct {
	void *virt_addr;
	void *bus_addr;
} HwBuffer;

// std.Notification<Error>
typedef struct {
	wait_queue_head_t wq;
	ORG_SIMPLE_Error data;
	bool flag;
} Notification_Error;

// SimpleAES Instance Data
typedef struct {
	// Notification ("irq notifications")
	Notification_Error notif;

	// Interrupt("simpleaes-irq")
	int irq_line;

	// Clock("simpleaes-clock")
	struct clock *axi_clock;

	// Regfile
	struct {
		void __iomem *ptr;
		struct spinlock_t lock;
	} regfile;

	// CDEV Interface
    struct file_operations f_ops;
	struct {
		dev_t devno;
        struct cdev cdev;
		struct class *class_ptr;
		struct device *device_ptr;
	} cdev;

	// Platform device
	struct platform_device *pdev_ptr;
} SimpleAES;

// IOCTL Encrypt/Decrypt Data
typedef struct {
	void *key_ptr;
	void *i_data_ptr;
	void *o_data_ptr;
} IOCTL_Data;

// =============================================================================
// Constant Definitions
// =============================================================================

#define SIMPLEAES_DEVICE_NAME "simpleaes"

// Key and Data Size
static const unsigned int ORG_SIMPLE_KD_SIZE = 128;

//==============================================================================
// IOCTL
//==============================================================================

#define IOCTL_MAGIC 'z'

#define IOCTL_ENCRYPT __IOWR(IOCTL_MAGIC, 1, IOCTL_Data *);
#define IOCTL_DECRYPT __IOWR(IOCTL_MAGIC, 2, IOCTL_Data *);

#endif // ORG_SIMPLE_SIMPLEAES_H
