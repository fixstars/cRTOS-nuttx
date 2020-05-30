/****************************************************************************
 * arch/x86/src/intel64/intel64_head.S
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
#include <arch/arch.h>

    .file    "intel64_syscall.S"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * .text
 ****************************************************************************/

    .text
    .code64

/****************************************************************************
 * Public Symbols
 ****************************************************************************/

    .global syscall_entry
    .global enable_syscall
    .global get_kernel_stack_ptr

/****************************************************************************
 * Name: get_kernel_stack_ptr
 *
 * Description:
 *      The kernel stack of the process is at GS base register, read and return
 *
 ****************************************************************************/

    .type    get_kernel_stack_ptr, @function
get_kernel_stack_ptr:
    rdgsbase %rax
    ret
    .size    get_kernel_stack_ptr, . - get_kernel_stack_ptr

/****************************************************************************
 * Name: syscall_entry
 *
 * Description:
 *   This is the syscall_entry point. It saves the user reg and stack, sets up for
 *   kernel mode stacks, and dispatch the syscall.
 *
 ****************************************************************************/

    .type    syscall_entry, @function
syscall_entry:
    /* GS points to the kernel stack */

    /* write the user stack address to the kernel stack */
    movq   %rsp,     %gs:-8

    /* write the return address to the kernel stack */
    /* RCX is the userspace RIP */
    movq   %rcx,     %gs:-16

    /* switch to the kernel stack */
    rdgsbase %rsp

    /* Already placed ret and stack address on stack */
    leaq   -16(%rsp),  %rsp
    
    /* Maintain a traceable chain of frame pointer */
    pushq  %rbp
    mov    %rsp,     %rbp

    /* R11 is userspace RFLAGS */
    pushq  %r11

    /* syscall interface should preserve all registers */
    pushq  %rdi
    pushq  %rsi
    pushq  %rdx
    pushq  %r8
    pushq  %r9

    pushq  %r15
    pushq  %r14
    pushq  %r13
    pushq  %r12
    pushq  %r10
    pushq  %rbx
    pushq  %rax

    /* Arrange the arguments, syscall number is passed in on rax */
    /* 4th argument was passed using r10, change it to rcx */
    pushq  %r9
    mov    %r8,       %r9
    mov    %r10,      %r8
    mov    %rdx,      %rcx
    mov    %rsi,      %rdx
    mov    %rdi,      %rsi
    mov    %rax,      %rdi

    call    syscall_handler
    
    // Remove the parameter
    lea    8(%rsp),   %rsp

    // recover the values saved
    lea    8(%rsp),   %rsp // SKIP RAX, which is the return value
    popq   %rbx
    popq   %r10
    popq   %r12
    popq   %r13
    popq   %r14
    popq   %r15

    popq   %r9
    popq   %r8
    popq   %rdx

    popq   %rsi
    popq   %rdi
    popfq  // The RFLAGS, following instruction won't alter any flags
    popq   %rbp

    /* write the user stack address to the kernel stack */
    movq   %gs:-8,    %rsp

    /* write the return address to the kernel stack */
    /* RCX is the userspace RIP */
    movq   %gs:-16,   %rcx
    jmp    *%rcx

    .size    syscall_entry, . - syscall_entry

/****************************************************************************
 * Name: enable_syscall
 *
 * Description:
 *   Setup syscall related MSRs.
 *
 ****************************************************************************/

    .type    enable_syscall, @function
enable_syscall:
    pushq   %rax
    pushq   %rbx
    pushq   %rcx
    pushq   %rdx

    movl    $MSR_EFER,      %ecx
    rdmsr
    or      $EFER_SCE,      %eax
    wrmsr

    /* We don't do sysret, so user CS:SS is not set */
    xor     %rax,           %rax
    xor     %rdx,           %rdx
    or      $(X86_GDT_CODE_SEL_NUM * X86_GDT_ENTRY_SIZE), %rdx
    movl    $MSR_STAR,      %ecx
    wrmsr

    /* ensure EDX:EAX is used to load the 64bit address */
    movabs  $syscall_entry, %rax
    mov     %rax,           %rdx
    shrq    $32,            %rdx
    movl    $MSR_LSTAR,     %ecx
    wrmsr

    mov     $0,             %rax
    xor     %rdx,           %rdx
    movl    $MSR_FMASK,     %ecx
    wrmsr

    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    ret
    .size   enable_syscall, . - enable_syscall
