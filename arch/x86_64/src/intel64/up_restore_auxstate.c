/****************************************************************************
 * arch/x86_64/src/intel64/up_restore_auxstate.c
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

#include <debug.h>

#include <nuttx/arch.h>
#include <nuttx/sched.h>

#include <arch/arch.h>
#include <arch/irq.h>
#include <arch/io.h>

#include "up_internal.h"

#ifdef CONFIG_CRTOS
#include "tux.h"
#endif

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: up_restore_auxstate
 *
 * Description:
 *   This function performs some additional action required to complete the
 *   CTX on intel64 processor.
 *
 ****************************************************************************/

void up_restore_auxstate(struct tcb_s *rtcb)
{
#ifdef CONFIG_CRTOS
  if (rtcb->xcp.pd1 != NULL)
    {
      pdpt[0] = (uintptr_t)rtcb->xcp.pd1 | X86_PAGE_PRESENT | X86_PAGE_WR;
    }
  else
    {
      pdpt[0] = (uintptr_t)&pd_low | X86_PAGE_PRESENT | X86_PAGE_WR;
    }
#endif

  /* Set PCID, avoid TLB flush */

  set_pcid(rtcb->pid);

#ifdef CONFIG_CRTOS

  /* The kernel stack cache, GS BASE */

  write_gsbase((uintptr_t)rtcb->adj_stack_ptr);

  /* If user space set the FS BASE, recover it */
  if(rtcb->xcp.fs_base_set)
    {
      write_fsbase(rtcb->xcp.fs_base);
    }
  else
    {
      write_fsbase(0);
    }

  shadow_set_global_prio(rtcb->sched_priority);
#endif
}
