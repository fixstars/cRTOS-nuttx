/****************************************************************************
 *  arch/x86_64/src/intel64/intel64_syscall_handlers.c
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
#include <nuttx/compiler.h>

#include <nuttx/arch.h>
#include <nuttx/board.h>
#include <syscall.h>

#include "sched/sched.h"
#include "up_internal.h"

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: syscall_handler
 *
 * Description:
 *   syscall fast calling interface will go here
 *
 ****************************************************************************/

#if defined(CONFIG_LIB_SYSCALL) && !defined(CONFIG_CRTOS)

uint64_t __attribute__ ((noinline))
syscall_handler(unsigned long nbr,
                uintptr_t parm1, uintptr_t parm2, uintptr_t parm3,
                uintptr_t parm4, uintptr_t parm5, uintptr_t parm6)
{
  uint64_t ret;

  svcinfo("SYSCALL Entry nbr: %llu\n", nbr);
  svcinfo("SYSCALL Task: %d SRC: %016llx\n",
          this_task()->pid, __builtin_return_address(1));
  svcinfo("SYSCALL JMP: %016llx\n", g_stublookup[nbr]);
  svcinfo("  PARAM: %016llx %016llx %016llx\n", parm1,  parm2,  parm3);
  svcinfo("       : %016llx %016llx %016llx\n", parm4,  parm5,  parm6);

  /* Verify that the SYS call number is within range */

  DEBUGASSERT(nbr >= CONFIG_SYS_RESERVED);

  /* Call syscall from table. */

  nbr -= CONFIG_SYS_RESERVED;
  ret = ((uint64_t (*)(unsigned long, \
                       uintptr_t, uintptr_t, uintptr_t, \
                       uintptr_t, uintptr_t, uintptr_t)) \
                       (g_stublookup[nbr])) \
                       (nbr, parm1, parm2, parm3, parm4, parm5, parm6);

  svcinfo("END SYSCALL %d Task: %d ret:%llx\n", nbr, this_task()->pid, ret);

  return ret;
}

#elif defined(CONFIG_LIB_SYSCALL) && defined(CONFIG_CRTOS)

uint64_t __attribute__ ((noinline))
syscall_handler(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  uint64_t ret;

  svcinfo("SYSCALL Entry nbr: %llu\n", nbr);
  svcinfo("SYSCALL Task: %d SRC: %016llx\n",
           this_task()->pid, __builtin_return_address(1));
  svcinfo("SYSCALL JMP: %016llx\n", g_stublookup[nbr]);
  svcinfo("  PARAM: %016llx %016llx %016llx\n",
          parm1,  parm2,  parm3);
  svcinfo("       : %016llx %016llx %016llx\n",
          parm4,  parm5,  parm6);
  if (nbr < CONFIG_SYS_RESERVED)
    {
      /* Invork Linux subsystem */

      ret = linux_interface(nbr, parm1, parm2, parm3, parm4, parm5, parm6);
    }
  else
    {
      /* Verify that the SYS call number is within range */

      DEBUGASSERT(nbr >= CONFIG_SYS_RESERVED);

      /* Call syscall from table. */

      nbr -= CONFIG_SYS_RESERVED;
      ret = ((uint64_t (*)(unsigned long, \
                           uintptr_t, uintptr_t, uintptr_t, \
                           uintptr_t, uintptr_t, uintptr_t)) \
                           (g_stublookup[nbr])) \
                           (nbr, parm1, parm2, parm3, parm4, parm5, parm6);
    }

  svcinfo("END SYSCALL %d Task: %d ret:%llx\n", nbr, this_task()->pid, ret);

  return ret;
}

#else

uint64_t syscall_handler(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  return 0;
}

#endif
