/****************************************************************************
 * arch/x86_64/src/intel64/up_schedulesigaction.c
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
#include <sched.h>
#include <debug.h>

#include <nuttx/irq.h>
#include <nuttx/arch.h>

#include "sched/sched.h"
#include "up_internal.h"
#include "up_arch.h"

#ifdef CONFIG_CRTOS
#include "tux.h"
#endif

#ifndef CONFIG_DISABLE_SIGNALS

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Data
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: up_schedule_sigaction
 *
 * Description:
 *   This function is called by the OS when one or more signal handling
 *   actions have been queued for execution.  The architecture specific code
 *   must configure things so that the 'sigdeliver' callback is executed on
 *   the thread specified by 'tcb' as soon as possible.
 *
 *   This function may be called from interrupt handling logic.
 *
 *   This operation should not cause the task to be unblocked nor should it
 *   cause any immediate execution of sigdeliver. Typically, a few cases need
 *   to be considered:
 *
 *   (1) This function may be called from an interrupt handler. During
 *       interrupt processing, all xcptcontext structures should be valid for
 *       all tasks.  That structure should be modified to invoke sigdeliver()
 *       either on return from (this) interrupt or on some subsequent context
 *       switch to the recipient task.
 *   (2) If not in an interrupt handler and the tcb is NOT the currently
 *       executing task, then again just modify the saved xcptcontext
 *       structure for the recipient task so it will invoke sigdeliver when
 *       that task is later resumed.
 *   (3) If not in an interrupt handler and the tcb IS the currently
 *       executing task -- just call the signal handler now.
 *
 ****************************************************************************/

#ifndef CONFIG_CRTOS

void up_schedule_sigaction(struct tcb_s *tcb, sig_deliver_t sigdeliver)
{
  irqstate_t flags;

  sinfo("tcb=0x%p sigdeliver=0x%p\n", tcb, sigdeliver);
  sinfo("rtcb=0x%p g_current_regs=0x%p\n", this_task(), g_current_regs);

  /* Make sure that interrupts are disabled */

  flags = enter_critical_section();

  /* Refuse to handle nested signal actions */

  if (!tcb->xcp.sigdeliver)
    {
      /* First, handle some special cases when the signal is being delivered
       * to the currently executing task.
       */

      if (tcb == this_task())
        {
          /* CASE 1:  We are not in an interrupt handler and a task is
           * signalling itself for some reason.
           */

          if (!g_current_regs)
            {
              /* In this case just deliver the signal with a function call now. */

              sigdeliver(tcb);
            }

          /* CASE 2:  We are in an interrupt handler AND the interrupted task
           * is the same as the one that must receive the signal, then we will
           * have to modify the return state as well as the state in the TCB.
           *
           * Hmmm... there looks like a latent bug here: The following logic
           * would fail in the strange case where we are in an interrupt
           * handler, the thread is signalling itself, but a context switch to
           * another task has occurred so that g_current_regs does not refer to
           * the thread of this_task()!
           */

          else
            {
              /* Save the return lr and cpsr and one scratch register. These
               * will be restored by the signal trampoline after the signals
               * have been delivered.
               */

              tcb->xcp.sigdeliver       = sigdeliver;
              tcb->xcp.saved_rip        = g_current_regs[REG_RIP];
              tcb->xcp.saved_rsp        = tcb->xcp.regs[REG_RSP];
              tcb->xcp.saved_rflags     = g_current_regs[REG_RFLAGS];

              /* Then set up to vector to the trampoline with interrupts
               * disabled
               */

              g_current_regs[REG_RIP]     = (uint64_t)up_sigdeliver;
              g_current_regs[REG_RFLAGS]  = 0;

              /* And make sure that the saved context in the TCB
               * is the same as the interrupt return context.
               */

              up_savestate(tcb->xcp.regs);
            }
        }

      /* Otherwise, we are (1) signaling a task is not running
       * from an interrupt handler or (2) we are not in an
       * interrupt handler and the running task is signalling
       * some non-running task.
       */

      else
        {
          /* Save the return lr and cpsr and one scratch register
           * These will be restored by the signal trampoline after
           * the signals have been delivered.
           */

          tcb->xcp.sigdeliver       = sigdeliver;
          tcb->xcp.saved_rip        = tcb->xcp.regs[REG_RIP];
          tcb->xcp.saved_rsp        = tcb->xcp.regs[REG_RSP];
          tcb->xcp.saved_rflags     = tcb->xcp.regs[REG_RFLAGS];

          /* Then set up to vector to the trampoline with interrupts
           * disabled
           */

          tcb->xcp.regs[REG_RIP]    = (uint64_t)up_sigdeliver;
          tcb->xcp.regs[REG_RFLAGS]  = 0;
        }
    }

  leave_critical_section(flags);
}

#else

void up_schedule_sigaction(struct tcb_s *tcb, sig_deliver_t sigdeliver)
{
  irqstate_t flags;
  uint64_t curr_rsp, new_rsp, kstack;

  sinfo("tcb=0x%p sigdeliver=0x%p\n", tcb, sigdeliver);

  /* Make sure that interrupts are disabled */

  flags = enter_critical_section();

  /* Refuse to handle nested signal actions */

  if (!tcb->xcp.sigdeliver)
    {
      /* First, handle some special cases when the signal is being delivered
       * to the currently executing task.
       */

      if (tcb == this_task())
        {
          /* CASE 1:  We are not in an interrupt handler and a task is
           * signalling itself for some reason.
           */

          if (!g_current_regs)
            {
              /* In this case just deliver the signal with a function call now. */

              if (tcb->xcp.is_linux)
                {

                /* possible BUG,
                 * if the compiler use rsp to address local varible,
                 * we are doomed */

                asm volatile("mov %%rsp, %0":"=m"(curr_rsp));

                /* 1. move to the user stack */
                /* 2. if currently in kernel stack, we need to prevent an overwrite */
                /* 3. if signal stack is set use it instead */
                /* 4. nested signal will break this implementation */

                kstack = (uint64_t)tcb->adj_stack_ptr;

                if ((curr_rsp < kstack) &&
                    (curr_rsp > kstack - tcb->adj_stack_size))
                  {

                    /* Cannot Nest! */

                    if (tcb->xcp.saved_kstack)
                        PANIC();

                    /* Currently on the kstack, shrink the kstack */

                    tcb->xcp.saved_rsp = curr_rsp;
                    tcb->xcp.saved_kstack = kstack;

                    /* Update the kernel stack,
                     * also update GS BASE,
                     * which is the cache of kernel stack
                     */

                    /* XXX: modifying adj_stack_ptr might cause
                     * exit in signal handler to crash ? */

                    tcb->adj_stack_ptr = (void*)(curr_rsp - 8);
                    write_gsbase((uintptr_t)tcb->adj_stack_ptr);

                    if (tcb->xcp.signal_stack_flag & TUX_SS_DISABLE)
                      {
                        /* SS_DISABLE, not using signal stack
                         * Read out the user stack address
                         */

                        new_rsp = *((uint64_t*)kstack - 1) - 8;
                      }
                    else
                      {
                        /* Using signal stack */

                        tcb->xcp.signal_stack_flag |= 1;

                        new_rsp =
                          (tcb->xcp.signal_stack + tcb->xcp.signal_stack_size) & (-0x10);
                      }

                    asm volatile("mov %%rsp, %%r12   \t\n\
                                  mov %0, %%rsp    \t\n\
                                  mov %1, %%rdi    \t\n\
                                  call *%2  \t\n\
                                  mov %%r12, %%rsp"::"g"(new_rsp), "g"(tcb), "g"(sigdeliver):"r12","rdi");

                    /* End use signal stack */

                    if (tcb->xcp.signal_stack_flag & 1)
                        tcb->xcp.signal_stack_flag = 0;


                    /* Restore the kernel stack,
                     * also update GS BASE,
                     * which is the cache of kernel stack */

                    tcb->adj_stack_ptr = (void*)tcb->xcp.saved_kstack;
                    write_gsbase((uintptr_t)tcb->adj_stack_ptr);
                    tcb->xcp.saved_rsp = 0;
                    tcb->xcp.saved_kstack = 0;
                  }
                else
                  {
                    if (tcb->xcp.signal_stack_flag & TUX_SS_DISABLE)
                      {
                        /* SS_DISABLE, not using signal stack */

                        sigdeliver(tcb);
                      }
                    else
                      {
                        /* Using signal stack */

                        new_rsp =
                          (tcb->xcp.signal_stack + tcb->xcp.signal_stack_size) & (-0x10);

                        tcb->xcp.signal_stack_flag |= 1;
                        asm volatile("mov %%rsp, %%r12   \t\n\
                                      mov %0, %%rsp    \t\n\
                                      mov %1, %%rdi    \t\n\
                                      call *%2  \t\n\
                                      mov %%r12, %%rsp"::"g"(new_rsp), "g"(tcb), "g"(sigdeliver):"r12","rdi");
                        tcb->xcp.signal_stack_flag = 0;
                    }
                  }
                }
              else
                {
                  /* Task is not Linux task */

                  sigdeliver(tcb);
                }
            }

          /* CASE 2:  We are in an interrupt handler AND the interrupted task
           * is the same as the one that must receive the signal, then we will
           * have to modify the return state as well as the state in the TCB.
           *
           * Hmmm... there looks like a latent bug here: The following logic
           * would fail in the strange case where we are in an interrupt
           * handler, the thread is signalling itself, but a context switch to
           * another task has occurred so that g_current_regs does not refer to
           * the thread of this_task()!
           */

          else
            {
              /* Save the return lr and cpsr and one scratch register. These
               * will be restored by the signal trampoline after the signals
               * have been delivered.
               */

              tcb->xcp.sigdeliver       = sigdeliver;
              tcb->xcp.saved_rip        = g_current_regs[REG_RIP];
              tcb->xcp.saved_rsp        = 0;
              tcb->xcp.saved_rflags     = g_current_regs[REG_RFLAGS];

              if (tcb->xcp.is_linux)
                {

                  /* 1. move to the user stack */
                  /* 2. if currently in kernel stack, we need to prevent an overwrite */
                  /* 3. if signal stack is set use it instead */

                  kstack = (uint64_t)tcb->adj_stack_ptr;
                  curr_rsp = g_current_regs[REG_RSP];

                  if ((g_current_regs[REG_RSP] < kstack) &&
                      (g_current_regs[REG_RSP] > kstack - tcb->adj_stack_size))
                    {
                      /* On kernel stack, save it and modify it */
                      /* XXX: modifying adj_stack_ptr might cause
                       * exit in signal handler to crash ? */

                      tcb->xcp.saved_rsp = curr_rsp;
                      tcb->xcp.saved_kstack = kstack;

                      tcb->adj_stack_ptr = (void*)(curr_rsp - 8);
                      write_gsbase((uintptr_t)tcb->adj_stack_ptr);

                      /* Read out the user stack address */

                      g_current_regs[REG_RSP] = *((uint64_t*)kstack - 1) - 8;
                    }

                  if (!(tcb->xcp.signal_stack_flag & TUX_SS_DISABLE))
                    {
                      /* !SS_DISABLE, use signal stack */
                      tcb->xcp.saved_rsp = curr_rsp;

                      tcb->xcp.signal_stack_flag |= 1;
                      g_current_regs[REG_RSP] =
                        (tcb->xcp.signal_stack + tcb->xcp.signal_stack_size) & (-0x10);
                    }
                }

              /* Then set up to vector to the trampoline with interrupts
               * disabled
               */

              g_current_regs[REG_RIP]     = (uint64_t)up_sigdeliver;
              g_current_regs[REG_RFLAGS]  = 0;

              /* And make sure that the saved context in the TCB
               * is the same as the interrupt return context.
               */

              up_savestate(tcb->xcp.regs);
            }
        }

      /* Otherwise, we are (1) signaling a task is not running
       * from an interrupt handler or (2) we are not in an
       * interrupt handler and the running task is signalling
       * some non-running task.
       */

      else
        {
          /* Save the return lr and cpsr and one scratch register
           * These will be restored by the signal trampoline after
           * the signals have been delivered.
           */

          tcb->xcp.sigdeliver       = sigdeliver;
          tcb->xcp.saved_rip        = tcb->xcp.regs[REG_RIP];
          tcb->xcp.saved_rsp        = 0;
          tcb->xcp.saved_rflags     = tcb->xcp.regs[REG_RFLAGS];

          if (tcb->xcp.is_linux)
            {

              /* move to the user stack */
              /* if in kernel stack, we need to prevent an overwrite*/
              kstack = (uint64_t)tcb->adj_stack_ptr;
              curr_rsp = tcb->xcp.regs[REG_RSP];

              if ((tcb->xcp.regs[REG_RSP] < kstack) &&
                  (tcb->xcp.regs[REG_RSP] > kstack - tcb->adj_stack_size) &&
                  tcb->xcp.is_linux)
                {
                  /* On kernel stack, save it and modify it */
                  /* XXX: modifying adj_stack_ptr might cause
                   * exit in signal handler to crash ? */

                  /* preserve the values */

                  tcb->xcp.saved_rsp = curr_rsp;
                  tcb->xcp.saved_kstack = kstack;

                  /* Move to User Stack */

                  tcb->xcp.regs[REG_RSP] = *((uint64_t*)kstack - 1) - 8;

                  /* move the kstack starting point to somewhere unused */
                  /* No need to update the GS cache, CTX will do that */

                  tcb->adj_stack_ptr = (void*)(curr_rsp - 8);
                }

              if (!(tcb->xcp.signal_stack_flag & TUX_SS_DISABLE))
                {
                  /* !SS_DISABLE, use signal stack */

                  tcb->xcp.saved_rsp = curr_rsp;

                  tcb->xcp.signal_stack_flag |= 1;
                  tcb->xcp.regs[REG_RSP] =  (tcb->xcp.signal_stack + tcb->xcp.signal_stack_size) & (-0x10);
                }
            }

          /* Then set up to vector to the trampoline with interrupts
           * disabled
           */

          tcb->xcp.regs[REG_RIP]    = (uint64_t)up_sigdeliver;
          tcb->xcp.regs[REG_RFLAGS]  = 0;
        }
    }

  leave_critical_section(flags);
}

#endif /* !COFNIG_CRTOS */

#endif /* !CONFIG_DISABLE_SIGNALS */
