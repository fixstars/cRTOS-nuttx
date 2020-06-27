/****************************************************************************
 *  arch/x86_64/src/intel64/up_initialstate.c
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

#include <stdint.h>
#include <string.h>

#include <nuttx/arch.h>
#include <arch/arch.h>

#include "up_internal.h"
#include "up_arch.h"
#include "sched/sched.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Data
 ****************************************************************************/

/****************************************************************************
 * Public Data
 ****************************************************************************/

struct vma_s g_vm_full_map = {
    .va_start = 0x0,
    .va_end = 0x40000000, // start of kheap
    .pa_start = 0x0,
    ._backing = "",
    .proto = 3,
    .next = NULL
};

struct vma_s g_vm_empty_map = {
    .va_start = 0x0,
    .va_end = 0x40000000, // start of kheap
    .pa_start = 0x0,
    ._backing = "",
    .proto = 0,
    .next = NULL
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: up_initial_state
 *
 * Description:
 *   A new thread is being started and a new TCB has been created. This
 *   function is called to initialize the processor specific portions of the
 *   new TCB.
 *
 *   This function must setup the intial architecture registers and/or stack
 *   so that execution will begin at tcb->start on the next context switch.
 *
 ****************************************************************************/

void up_initial_state(struct tcb_s *tcb)
{
  struct xcptcontext *xcp = &tcb->xcp;

  /* Initialize the initial exception register context structure */

  memset(xcp, 0, sizeof(struct xcptcontext));

  /* set the FCW to 1f80 */

  xcp->regs[1]      = (uint64_t)0x0000037f00000000;

  /* set the MXCSR to 1f80 */

  xcp->regs[3]      = (uint64_t)0x0000000000001f80;

#ifdef CONFIG_CRTOS

  /* set page table to share space with current process */

  struct tcb_s *rtcb = this_task();

  /* Check for some special cases:  (1) rtcb may be NULL only during
   * early boot-up phases, and (2) what if a irq spawns a task?.
   */

  if (rtcb != NULL && !up_interrupt_context())
    {
      if(rtcb->xcp.is_linux)
        {
          xcp->vma = NULL;
          xcp->pda = NULL;
          xcp->pd1 = NULL;

          xcp->is_linux = 1;
          xcp->linux_sock = rtcb->xcp.linux_sock;
          xcp->linux_tcb  = rtcb->xcp.linux_tcb;
          xcp->linux_pid  = rtcb->xcp.linux_pid;

          nxsem_init(&xcp->rsc_lock, 1, 0);
          nxsem_set_protocol(&xcp->rsc_lock, SEM_PRIO_NONE);

          xcp->rsc_pollfd = NULL;

          xcp->fd[0] = rtcb->xcp.fd[0];
          xcp->fd[1] = rtcb->xcp.fd[1];
          xcp->fd[2] = rtcb->xcp.fd[2];

          xcp->signal_stack_flag = 2; // TUX_SS_DISABLE
        }
      else
        {
          xcp->is_linux = 0;
          xcp->vma = &g_vm_empty_map;
          xcp->pda = &g_vm_empty_map;
          xcp->pd1 = NULL;
        }
    }
  else
    {
      xcp->is_linux = 0;
      xcp->vma = &g_vm_empty_map;
      xcp->pda = &g_vm_empty_map;
      xcp->pd1 = NULL;
    }

#endif

  /* Save the initial stack pointer... the value of the stackpointer before
   * the "interrupt occurs."
   */

  xcp->regs[REG_RSP]      = (uint64_t)tcb->adj_stack_ptr;
  xcp->regs[REG_RBP]      = (uint64_t)tcb->adj_stack_ptr;

  /* Save the task entry point */

  xcp->regs[REG_RIP]     = (uint64_t)tcb->start;

  /* Set up the segment registers... assume the same segment as the caller.
   * That is not a good assumption in the long run.
   */

  xcp->regs[REG_DS]      = up_getds();
  xcp->regs[REG_CS]      = up_getcs();
  xcp->regs[REG_SS]      = up_getss();
  xcp->regs[REG_ES]      = up_getes();

  /* Aux GS and FS are set to be 0 */

  /* used by some libc for TLS and segment reference */

  xcp->regs[REG_GS]      = 0;
  xcp->regs[REG_FS]      = 0;

  /* Set supervisor- or user-mode, depending on how NuttX is configured and
   * what kind of thread is being started.  Disable FIQs in any event
   *
   * If the kernel build is not selected, then all threads run in
   * supervisor-mode.
   */

#ifdef CONFIG_BUILD_KERNEL
#  error "Missing logic for the CONFIG_BUILD_KERNEL build"
#endif

  /* Enable or disable interrupts, based on user configuration.  If the IF
   * bit is set, maskable interrupts will be enabled.
   */

#ifndef CONFIG_SUPPRESS_INTERRUPTS
  xcp->regs[REG_RFLAGS]  = X86_64_RFLAGS_IF;
#endif
}

