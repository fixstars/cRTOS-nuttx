/****************************************************************************
 *  arch/x86_64/src/linux_subsystem/tux_prctl.c
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
 * Pre-processor definitions
 ****************************************************************************/

#define ARCH_SET_FS 0x1002
#define ARCH_GET_FS 0x1003

/****************************************************************************
 * Public Functions
 ****************************************************************************/

long tux_arch_prctl(unsigned long nbr, int code, unsigned long addr)
{
  struct tcb_s *rtcb = this_task();
  int ret = 0;

  switch(code)
    {
      case ARCH_GET_FS:
          *(unsigned long *)addr = read_fsbase();
          break;
      case ARCH_SET_FS:
          rtcb->xcp.fs_base_set = 1;
          rtcb->xcp.fs_base = addr;
          write_fsbase(addr);
          break;
      default:
          ret = -1;
          break;
    }

  return ret;
}

