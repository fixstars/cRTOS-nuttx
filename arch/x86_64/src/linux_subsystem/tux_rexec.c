/****************************************************************************
 *  arch/x86_64/src/linux_subsystem/tux_rexec.c
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

#include <sys/mman.h>
#include <stdint.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <debug.h>
#include <sched.h>

#include <nuttx/sched.h>
#include <nuttx/arch.h>
#include <nuttx/mm/gran.h>
#include <arch/irq.h>
#include <arch/io.h>

#include "tux.h"
#include "sched/sched.h"

/****************************************************************************
 * Pre-processor definitions
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/

void rexec_trampoline(const char *path, char **argv, char **envp)
{
  _info("Entering rExec Trampoline: %s\n", path);

  /* Currently on the kernel stack; */

  _tux_exec((char *)path, argv, envp);

  /* We should never end up here */

  exit(0xff);
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

long rexec(const char *path, int policy, int priority,
           char *argv[], char *envp[], uint64_t shadow_tcb)
{
  struct task_tcb_s *tcb;
  uintptr_t kstack;
  uint64_t ret;
  uint64_t i;
  int argc;
  int envc;
  int sock = open("/dev/shadow0", O_RDWR);

  /* First try to create a new task */

  _info("Remote exec: %s, with priority: %d\n", path, priority);

  /* Allocate a TCB for the new task. */

  tcb = (FAR struct task_tcb_s *)kmm_zalloc(sizeof(struct task_tcb_s));
  if (!tcb)
    {
      return -ENOMEM;
    }

  /* First try to create a new task */

  _info("New TCB: 0x%016llx\n", tcb);

  /* Setup a 8k kernel stack */

  kstack = (uintptr_t)kmm_zalloc(TUX_KSTACK_SIZE);

  _info("kstack range: %llx - %llx\n", kstack, kstack + TUX_KSTACK_SIZE);

  /* Initialize the task
   * The addresses are the virtual address of new task
   * the trampoline will be using the kernel stack,
   * and switch to the user stack for us
   */

  ret = task_init((FAR struct tcb_s *)tcb,
                  argv[0] ? argv[0] : path, priority,
                  (void *)kstack, TUX_KSTACK_SIZE,
                  (main_t)rexec_trampoline, NULL);
  if (ret < 0)
    {
      berr("task_init() failed: %d\n", ret);
      goto errout_with_tcb;
    }

  /* Set policy */

  /* The nuttx SCHED_FIFO/SCHED_RR has the same numbering */

  tcb->cmn.flags &= ~TCB_FLAG_POLICY_MASK;
  if (policy == SCHED_FIFO)
      tcb->cmn.flags |= TCB_FLAG_SCHED_FIFO;

  if (policy == SCHED_RR)
      tcb->cmn.flags |= TCB_FLAG_SCHED_RR;

  /* We have no memory map */

  tcb->cmn.xcp.vma = NULL;
  tcb->cmn.xcp.pda = NULL;

  /* We have to copy the path, argv, envp on to kheap
   * Other wise they will be freed by the cRTOS loader daemon
   */

  void *ppath = strdup(path);

  for (i = 0; argv[i] != NULL; i++)
      ;

  argc = i;

  char **aargv = kmm_zalloc(sizeof(char *) * (argc + 1));
  for (i = 0; argv[i] != NULL; i++)
    {
      aargv[i] = strdup(argv[i]);
    }

  aargv[i] = NULL;

  for (i = 0; envp[i] != NULL; i++)
      ;
  envc = i;

  char **eenvp = kmm_zalloc(sizeof(char *) * (envc + 1));
  for (i = 0; envp[i] != NULL; i++)
    {
      eenvp[i] = strdup(envp[i]);
    }

  eenvp[i] = NULL;

  /* Call the trampoline function to provide synchronized mapping */

  tcb->cmn.xcp.regs[REG_RDI] = (uint64_t)ppath;
  tcb->cmn.xcp.regs[REG_RSI] = (uint64_t)aargv;
  tcb->cmn.xcp.regs[REG_RDX] = (uint64_t)eenvp;

  /* This is necessary to circumvent the nuttx trampoline */

  tcb->cmn.xcp.regs[REG_RIP] = (uint64_t)rexec_trampoline;

  /* setup some Linux handlers */

  tcb->cmn.xcp.is_linux = 2;
  tcb->cmn.xcp.linux_sock = sock;

  _info("LINUX SOCK: %d\n", tcb->cmn.xcp.linux_sock);

  tcb->cmn.xcp.linux_tcb = ~((unsigned long long)0xffff << 48) & shadow_tcb;
  tcb->cmn.xcp.linux_pid = (0xffff & (shadow_tcb >> 48));
  tcb->cmn.xcp.linux_tid = tcb->cmn.xcp.linux_pid;

  _info("LINUX TCB %lx, PID %lx\n",
        tcb->cmn.xcp.linux_tcb, tcb->cmn.xcp.linux_pid);

  insert_proc_node(tcb->cmn.pid, tcb->cmn.xcp.linux_pid);

  nxsem_init(&tcb->cmn.xcp.rsc_lock, 1, 0);
  nxsem_set_protocol(&tcb->cmn.xcp.rsc_lock, SEM_PRIO_NONE);

  tcb->cmn.xcp.pd1 = tux_mm_new_pd1();

  tcb->cmn.xcp.fd[0] = 0;
  tcb->cmn.xcp.fd[1] = 1;
  tcb->cmn.xcp.fd[2] = 2;

  tcb->cmn.xcp.signal_stack_flag = TUX_SS_DISABLE;

  _info("activate: new task=%d\n", tcb->cmn.pid);

  /* Then activate the task at the provided priority */

  ret = task_activate((FAR struct tcb_s *)tcb);
  if (ret < 0)
    {
      berr("task_activate() failed: %d\n", ret);
      goto errout_with_tcbinit;
    }

  return OK;

errout_with_tcbinit:
  tcb->cmn.stack_alloc_ptr = NULL;
  nxsched_release_tcb(&tcb->cmn, TCB_FLAG_TTYPE_TASK);
  return ret;

errout_with_tcb:
  kmm_free(tcb);
  return ret;
}
