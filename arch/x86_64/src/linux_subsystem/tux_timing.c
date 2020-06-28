/****************************************************************************
 *  arch/x86_64/src/linux_subsystem/tux_timing.c
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

#include <sys/time.h>
#include <nuttx/arch.h>
#include <nuttx/sched.h>

#include <time.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

/****************************************************************************
 * Public Functions
 ****************************************************************************/

long tux_nanosleep(unsigned long nbr,
                   const struct timespec *rqtp, struct timespec *rmtp)
{
  return nanosleep(rqtp, rmtp);
}

long tux_gettimeofday(unsigned long nbr,
                      struct timeval *tv, struct timezone *tz)
{
  return gettimeofday(tv, tz);
}
