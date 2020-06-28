/****************************************************************************
 *  arch/x86_64/src/linux_subsystem/tux_set_tid_address.c
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

#include <nuttx/arch.h>
#include <nuttx/sched.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

/****************************************************************************
 * Private Functions
 ****************************************************************************/

int* _tux_set_tid_address(struct tcb_s *rtcb, int* tidptr)
{
  int* orig_val;
  irqstate_t flags;

  flags = enter_critical_section();

  orig_val = rtcb->xcp.clear_child_tid;
  rtcb->xcp.clear_child_tid = tidptr;

  leave_critical_section(flags);
  return orig_val;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

long tux_set_tid_address(unsigned long nbr, int* tidptr)
{
  struct tcb_s *rtcb = this_task();
  _tux_set_tid_address(rtcb, tidptr);
  return rtcb->xcp.linux_tid;
}

void tux_set_tid_callback(void)
{
  struct tcb_s *rtcb = this_task();
  if (rtcb->xcp.clear_child_tid != NULL)
    {
      /* According to man pages */
      *(rtcb->xcp.clear_child_tid) = 0;
      tux_futex(0, rtcb->xcp.clear_child_tid, FUTEX_WAKE, 1, 0, 0, 0);
    }
}
