#ifndef _UART16550_H
#define _UART16550_H

#define	OPTION_COM1			1
#define OPTION_COM2			2
#define OPTION_BOTH			3

#define COM1_BASEPORT			0x3f8
#define COM2_BASEPORT			0x2f8
#define COM1_IRQ			4
#define COM2_IRQ			3

/* UART Registers */
#define THR				0x0
#define RBR				0x0
#define DLL				0x0
#define IER				0x1
#define DLH				0x1
#define IIR				0x2
#define FCR				0x2
#define LCR				0x3
#define MCR				0x4
#define LSR				0x5
#define MSR				0x6
#define SR				0x7

/* Writing to and reading from UART registers */
#define WRITE_TO_REG(value, port, reg)  outb(value, port + reg)
#define READ_FROM_REG(port, reg)        inb(port + reg)

#define UART16550_COM1_SELECTED		0x01
#define UART16550_COM2_SELECTED		0x02

#define MAX_NUMBER_DEVICES		2

#ifndef _UART16550_REGS_H



#define UART16550_BAUD_1200		96
#define UART16550_BAUD_2400		48
#define UART16550_BAUD_4800		24
#define UART16550_BAUD_9600		12
#define UART16550_BAUD_19200		6
#define UART16550_BAUD_38400		3
#define UART16550_BAUD_56000		2
#define UART16550_BAUD_115200		1

#define UART16550_LEN_5			0x00
#define UART16550_LEN_6			0x01
#define UART16550_LEN_7			0x02
#define UART16550_LEN_8			0x03

#define UART16550_STOP_1		0x00
#define UART16550_STOP_2		0x04

#define UART16550_PAR_NONE		0x00
#define UART16550_PAR_ODD		0x08
#define UART16550_PAR_EVEN		0x18
#define UART16550_PAR_STICK		0x20

#endif

#define	UART16550_IOCTL_SET_LINE	1

struct uart16550_line_info {
	unsigned char baud, len, par, stop;
};


#endif
