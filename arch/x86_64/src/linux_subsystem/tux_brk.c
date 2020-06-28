/****************************************************************************
 *  arch/x86_64/src/linux_subsystem/tux_brk.c
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

#include <semaphore.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

/****************************************************************************
 * Public Functions
 ****************************************************************************/

void *tux_brk(unsigned long nbr, void *brk)
{
  struct tcb_s *rtcb = this_task();

  if((brk > rtcb->xcp.__min_brk))
    {
      rtcb->xcp.__brk = brk;
      if(rtcb->xcp.__brk >= rtcb->xcp.__min_brk + 0x200000)
          rtcb->xcp.__brk = rtcb->xcp.__min_brk + 0x200000;
    }
  return rtcb->xcp.__brk;
}

