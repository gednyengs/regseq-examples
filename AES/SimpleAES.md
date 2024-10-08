# SimpleAES Accelerator Specification using Regseq

In this example, we demonstrate how to use _Regseq_ to specify the software interface of the _SimpleAES_ accelerator.

## Regseq Background

_Regseq_ is a _C-like_ domain-specific language aiming to improve productivity and reduce sources of errors in capturing register sequences. Automation tools consume _Regseq_ specifications to produce a variety of artifacts including device drivers, verification and emulation collateral, documentation, etc.
To allow for different use cases of the specified register sequences, RegSeq provides primitives and abstractions that can be materialized for different target environments.

_Regseq_ provides abstractions for the following constructs:
- __memory management__
- __synchronization and concurrency__
- __asynchronous programming__
- __device low-level code__ (register manipulations)
- __interrupt handling__
- __data structure manipulations__ (lists, arrays, queues, etc.)
- __I/O bus abstractions__ (mmap, port-mapped, io-bus)
- __error handling__
- __standard services__ (DMA, string ops, timing and delays, logging, etc.)

## SimpleAES Accelerator

_SimpleAES_ performs encryption and decryption of 128-bit data with 128-bit keys according to AES standard.

### Hardware Interface

_SimpleAES_ has the following hardware interface:
- 1 AXI4 Data Interface  (for reading and writing data and keys)
- 1 AXI-Lite Interface (for accessing registers)
- 1 clock interface (clock and reset)
- 1 interrupt interface

### Register Space

| Offset | Name | Description | Reset Value |
|--------|------|-------------|-------------|
| 0h00 | CTRL | Control Register | 0h00 |
| 0h04 | STAT | Status Register | 0h00 |
| 0h08 | IRQ | Interrupt Status Register | 0h00 |
| 0h0C | KAR | Key Address Register | 0h00 |
| 0h10 | IAR | Input Address Register | 0h00 |
| 0h14 | OAR | Output Address Register | 0h00 |

#### CTRL (Control Register @ 0h00)

| Offset | Field Name | Description | Field Property |
|--------|------------|-------------|----------------|
| 0 | OP | Operation Field</br>0 = Encrypt </br>1 = Decrypt| R/W |
| 1 | IE | Interrupt Enable</br>0 = Disable IRQ</br>1 = Enable IRQ| R/W |
|31:2 | RESERVED | | |

#### STAT (Status Register @ 0h04)

| Offset | Field Name | Description | Field Property |
|--------|------------|-------------|----------------|
| 0 | BUSY | 0 = Ready</br>1 = Busy| RO (Read-Only) |
| 1 | IRQ | Interrupt Pending</br>0 = No IRQ</br>1 = IRQ Pending| RO |
| 3:2 | ERR | Error Code</br>2'b00 = No Error</br>2'b01 = Key Error<br/>2'b10 = Input Data Error</br>2'b11 = Output Data Error | RO |

#### IRQ (Interrupt Status Register @ 0h08)

| Offset | Field Name | Description | Field Property|
|--------|------------|-------------|---------------|
| 0 | COMPLETE | 0 = No Completion IRQ</br>1 = Op Completed| R-WOC (Read and Write 1 to Clear) |
| 1 | ERR | 0 = No Errors</br>1 = Error Detected (read status register for detailed error status) | R-WOC (Read and Write 1 to Clear) |

#### KAR (Key Address Register @ 0h0C)

| Offset | Field Name | Description | Field Property |
|--------|------------|-------------|----------------|
| 31:0 | ADDR | 32-bit address where to read key from | R/W |

#### IAR (Input Address Register @ 0h10)

| Offset | Field Name | Description | Field Property |
|--------|------------|-------------|----------------|
| 31:0 | ADDR | 32-bit address where to read input data from | R/W |


#### OAR (Output Address Register @ 0h14)

| Offset | Field Name | Description | Field Property |
|--------|------------|-------------|----------------|
| 31:0 | ADDR | 32-bit address where to write output data to</br>Operation starts when this register is written. Therefore, this must be the last written register when setting up an operation| R/W |

### SystemRDL Specification for Register File

```rdl
addrmap SimpleAES {

  name  = "SimpleAES";
  desc  = "Address map for SimpleAES accelerator";

  default addressing  = regalign;
  default regwidth    = 32;
  default accesswidth = 32;
  default alignment   = 4;

  default littleendian;
  default lsb0;

  default sw          = rw;
  default hw          = r;

  // ------------------------------------------------------------------------
  // Control Register
  //-------------------------------------------------------------------------
  reg {
    name = "CTRL";
    desc = "control register";

    field {
      desc = "Operation field";
    } OP[0:0] = 0x0;

    field {
      desc = "Interrupt enable field";
    } IE[1:1] = 0x00;

  } CTRL @ 0x00;

  // ------------------------------------------------------------------------
  // Status Register
  //-------------------------------------------------------------------------
  reg {
    name = "STAT";
    desc = "status register";

    field {
      desc = "Busy field";
    } BUSY[0:0] = 0x0;

    field {
      desc = "interrupt pending field";
    } IRQ[1:1] = 0x00;

    field {
      desc = "Error code field";
    } ERR[3:2] = 0x00;

  } STAT @ 0x04;

  // ------------------------------------------------------------------------
  // Interrupt Status Register
  //-------------------------------------------------------------------------
  reg {
    name = "IRQ";
    desc = "interrupt status register";

    field {
      desc = "completion field";
      hw = woset;
      sw = woclr;
    } COMPLETE[0:0] = 0x0;

    field {
      desc = "error field";
      hw = woset;
      sw = woclr;
    } ERR[1:1] = 0x00;

  } IRQ @ 0x08;

  // ------------------------------------------------------------------------
  // Key Address Register
  //-------------------------------------------------------------------------
  reg {
    name = "KAR";
    desc = "key address register";

    field {
      desc = "address";
    } ADDR[31:0] = 0x0;

  } KAR @ 0x0C;

  // ------------------------------------------------------------------------
  // Input Address Register
  //-------------------------------------------------------------------------
  reg {
    name = "IAR";
    desc = "input address register";

    field {
      desc = "address";
    } ADDR[31:0] = 0x0;

  } IAR @ 0x10;

  // ------------------------------------------------------------------------
  // Output Address Register
  //-------------------------------------------------------------------------
  reg {
    name = "OAR";
    desc = "output address register";

    field {
      desc = "address";
      swmod;
    } ADDR[31:0] = 0x0;

  } OAR @ 0x14;

};
```

## Regseq Specification

Two versions of _Regseq_ specifications for the _SimpleAES_ accelerator are given in files `SimpleAES_ver1.rseq` and `SimpleAES_ver2.rseq`

- A __notification channel__ is used to communicate between the interrupt handler and the process-mode driver code
    - Althouth _Regseq_ provides more primitive constructs (Mutex) to manage concurrency, it also provides higher-level constructs such as _notification channels_ to specify the same intent
- __Interrupt__, __Clock__, and __Regfile__ resources are specified
    - Unlike the Portable Stimulus Standard (PSS) DSL, _Regseq_ provides abstractions of common resources attached to a hardware component. Both these provided resource types and their abstracted APIs are materialized for different target environments by an automated tool
    - In this example, we assume the target envionment is ARM-based Linux kernel with device-tree support
- __Attributes/Annotations__ are used to convery additional meaning to the specification of some constructs
    - The `@handler` annotation is used to specify the interrupt handler associated with the `irq_line` interrupt resource
    - Similarly, the `@irq_handler` annotation is set on `IrqHandler` function, thus making it a concurrent interrupt execution context
        - This allows the backend tools to choose, for instance, interrupt-safe non-blocking calls within the elaborated function
    - In `SimpleAES_ver1.rseq`, both `Encrypt` and `Decrypt` functions are marked `@entry`
        - This annotation instructs the compiler to add those functions to the final interface presented to user-land code
- __Predefined traits__ are used to augment the specification with extra information
    - `SimpleAES_ver2.rseq` uses the `std.Command` trait to specify that one way to interact with the device is through a command interface
        - A _command handler_ function is overridden to specialize it for the SimpleAES accelerator
- __Data race elimination__:
    - Data races can easily occur in programs written in languages such as C and C++
    - _Regseq_ uses _region-based memory management_ and _Rust's ownership and borrowing_ concepts to eliminate data races as much as possible

## Linux Driver Generated

Files `SimpleAES_Linux.h` and `SimpleAES_Linux.c` provide an example materialization of the specification for Linux driver generation.
The code in those files should highlight:
- Correct usage of Linux API
- Correct choice of API functions based on execution context
- Automatic error handling
- Implementation of higher-level constructs such as _notification channels_
- etc.
