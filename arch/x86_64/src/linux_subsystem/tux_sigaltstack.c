/****************************************************************************
 *  arch/x86_64/src/linux_subsystem/tux_sigaltstack.c
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
#include <string.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"
#include <sched/sched.h>
#include <group/group.h>
#include <task/task.h>

/****************************************************************************
 * Public Functions
 ****************************************************************************/

long tux_sigaltstack(unsigned long nbr, stack_t* ss, stack_t* oss)
{
    struct tcb_s* tcb = this_task();
    int ret;

    ret = 0;

    if (!ss && !oss)
        return -EINVAL;

    /* write the current setting back */
    if (oss)
      {
        memset(oss, 0, sizeof(stack_t));
        oss->ss_flags |= tcb->xcp.signal_stack_flag;
        oss->ss_size = tcb->xcp.signal_stack_size;
        oss->ss_sp = (void*)tcb->xcp.signal_stack;
      }

    if (ss)
      {
        if(ss->ss_flags == TUX_SS_DISABLE)
          {
            if (tcb->xcp.signal_stack_flag != TUX_SS_ONSTACK)
              {
                tcb->xcp.signal_stack_flag = TUX_SS_DISABLE;
                tcb->xcp.signal_stack_size = 0;
                tcb->xcp.signal_stack = 0;
              }
            else
              {
                ret = -EPERM;
              }
          }
        else if(ss->ss_flags == 0)
          {
            tcb->xcp.signal_stack_flag = 0;
            tcb->xcp.signal_stack_size = ss->ss_size;
            tcb->xcp.signal_stack = (uint64_t)ss->ss_sp;
          }
        else
          {
            ret = -EINVAL;
          }
      }

    return ret;
}
