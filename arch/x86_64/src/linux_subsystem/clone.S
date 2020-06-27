#include <nuttx/config.h>
#include <arch/irq.h>
#include "up_internal.h"

	.file	"clone.S"

/**************************************************************************
 * Pre-processor Definitions
 **************************************************************************/

/**************************************************************************
 * Public Data
 **************************************************************************/

/****************************************************************************
 * Macros
 ****************************************************************************/

/**************************************************************************
 * Public Functions
 **************************************************************************/

	.text

/**************************************************************************
 * Name: up_fullcontextrestore
 *
 * Full C prototype:
 *  void up_fullcontextrestore(uint32_t *regs) noreturn_function;
 *
 **************************************************************************/

	.globl	fork_kickstart
	.type	fork_kickstart, @function
fork_kickstart:

    movq    $0, %rax
    movq    (8*1)(%rdi),  %rbx
    movq    (8*2)(%rdi),  %r10
    movq    (8*3)(%rdi),  %r12
    movq    (8*4)(%rdi),  %r13
    movq    (8*5)(%rdi),  %r14
    movq    (8*6)(%rdi),  %r15
    movq    (8*7)(%rdi),  %r9
    movq    (8*8)(%rdi),  %r8
    movq    (8*9)(%rdi),  %rdx
    movq    (8*10)(%rdi), %rsi

    movq    (8*12)(%rdi), %r11
    movq    (8*13)(%rdi), %rbp
    movq    (8*14)(%rdi), %rcx
    movq    (8*15)(%rdi), %rsp

    movq    (8*11)(%rdi), %rdi

    pushq   %r11
    popfq   

    pushq   %rcx
    retq

	.size fork_kickstart, . - fork_kickstart
	.end
