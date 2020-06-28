/****************************************************************************
 *  arch/x86/src/linux_subsystem/clone.S
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

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
