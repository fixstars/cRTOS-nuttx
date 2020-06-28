/****************************************************************************
 *  arch/x86_64/src/linux_subsystem/tux_proc.c
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
#include <nuttx/wqueue.h>
#include <sys/wait.h>

/****************************************************************************
 * Pre-processor definitions
 ****************************************************************************/

#define TUX_PROC_HT_SIZE 256

/****************************************************************************
 * Private Types
 ****************************************************************************/

struct proc_node {
    int lpid;
    int rpid;
    int retain;
    struct proc_node* next;
};

/****************************************************************************
 * Private Data
 ****************************************************************************/

struct proc_node* tux_proc_hashtable[TUX_PROC_HT_SIZE];
struct work_s tux_proc_deletework;

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int insert_proc_node(int lpid, int rpid)
{
  struct proc_node **ptr= &tux_proc_hashtable[rpid % TUX_PROC_HT_SIZE];
  while (*ptr != NULL)
    {
      if ((*ptr)->rpid == rpid)
        {
          if ((*ptr)->retain != 0)
            {
              return -EEXIST;
            }
          else
            {
              (*ptr)->retain = 1;
              (*ptr)->lpid = lpid;
              (*ptr)->rpid = rpid;
              return 0;
            }
        }
      ptr = &((*ptr)->next);
    }

  *ptr = kmm_zalloc(sizeof(struct proc_node));
  if (!*ptr)
      return -ENOMEM;

  (*ptr)->lpid = lpid;
  (*ptr)->rpid = rpid;
  (*ptr)->retain = 1;
  (*ptr)->next = NULL;

  return 0;
}

void print_proc_nodes(void)
{
  struct proc_node **ptr;
  int i;

  for (i = 0; i < TUX_PROC_HT_SIZE; i++)
    {
      if (!tux_proc_hashtable[i])
          continue;

      svcinfo("head: %llx\n", tux_proc_hashtable[i]);

      ptr = &tux_proc_hashtable[i];
      while (*ptr != NULL)
        {
          svcinfo("on: %llx\n", *ptr);
          ptr = &((*ptr)->next);
        }
    }
}


void _delete_proc_nodes(void* arg) {
  struct proc_node **ptr;
  struct proc_node *to_free;
  int i;

  for (i = 0; i < TUX_PROC_HT_SIZE; i++)
    {
      if (!tux_proc_hashtable[i])
          continue;

      ptr = &tux_proc_hashtable[i];
      while (*ptr != NULL)
        {
          if ((*ptr)->retain == 0)
            {
              to_free = *ptr;
              *ptr = (*ptr)->next;
              kmm_free(to_free);
            }

          /* necessary additional check
           * *ptr might become NULL when removing the last node */
          if (*ptr)
              ptr = &((*ptr)->next);
        }
    }
}

int delete_proc_node(int rpid)
{
  struct proc_node **ptr= &tux_proc_hashtable[rpid % TUX_PROC_HT_SIZE];
  while (*ptr != NULL)
    {
      if ((*ptr)->rpid == rpid)
        {
          (*ptr)->retain = 0;
          work_queue(LPWORK,
                     &tux_proc_deletework, _delete_proc_nodes, NULL, 0);
          return 0;
        };
      ptr = &((*ptr)->next);
    }

  return -EEXIST;
}

long get_nuttx_pid(int rpid)
{
  struct proc_node **ptr= &tux_proc_hashtable[rpid % TUX_PROC_HT_SIZE];
  while (*ptr != NULL)
    {
      if ((*ptr)->rpid == rpid)
        {
          return (*ptr)->lpid;
        };
      ptr = &((*ptr)->next);
    }

  return -EEXIST;
}

long get_linux_pid(int lpid)
{
  struct tcb_s *rtcb;

  if (lpid == 0)
      lpid = this_task()->pid;

  rtcb = nxsched_get_tcb(lpid);

  return rtcb->xcp.linux_pid;
}

long search_linux_pid(int lpid)
{
  struct proc_node **ptr;
  int i;

  if (lpid == 0)
      lpid = this_task()->pid;

  for (i = 0; i < TUX_PROC_HT_SIZE; i++)
    {
      if (!tux_proc_hashtable[i])
          continue;

      ptr = &tux_proc_hashtable[i];
      while(*ptr != NULL)
        {
          if((*ptr)->lpid == lpid)
            {
              return (*ptr)->rpid;
            }
          ptr = &((*ptr)->next);
        }
    }

  return -EEXIST;
}

long tux_getppid(unsigned long nbr)
{
  struct task_group_s *pgrp;
  struct task_group_s *ppgrp;
  struct tcb_s *tcb;
  gid_t pgid;

  tcb = nxsched_get_tcb(this_task()->pid);
  if (!tcb)
      return -EEXIST;

  DEBUGASSERT(tcb->group);
  pgrp = tcb->group;

  pgid = pgrp->tg_pgrpid;

  ppgrp = group_findby_grpid(pgid);
  if (!ppgrp)
    return -ESRCH;

  return ppgrp->tg_task;
};

long tux_pidhook(unsigned long nbr,
                 int pid, uintptr_t param2, uintptr_t param3,
                 uintptr_t param4, uintptr_t param5, uintptr_t param6)
{
  int lpid;
  if(pid > 0)
    {
      lpid = get_nuttx_pid(pid);
      if (lpid < 0)
          return tux_delegate(nbr, pid, param2, param3, param4, param5, param6);
      else
          return tux_local(nbr, lpid, param2, param3, param4, param5, param6);
    }
  else
    {
      lpid = pid;
      return tux_local(nbr, lpid, param2, param3, param4, param5, param6);
    }
}

long tux_waithook(unsigned long nbr,
                  uintptr_t param1, uintptr_t param2, uintptr_t param3,
                  uintptr_t param4, uintptr_t param5, uintptr_t param6)
{
  /* waitid and wait4 return the pid exited
   * We need to hook it and return the linux pid to fake it
   * The problem here is that tcb is already freed
   * We do the reserve lookup by searching in the pid mapping table
   * The Entry is delayed to be freed in LP WQ
   * This make any task running lower or equal priority against LP WG
   * Might not get the right pid
   */

  /* Also, the flags are not identical in the 2 systems,
   * We need to translate them.
   * However, the option is arg3 in wait4 and arg4 in waitid
   * We need to do some switching here
   */

  uintptr_t *options;
  uintptr_t tux_options;

 /* SYS_wait4 */

  if (nbr == 61)
    {
      options = &param3;
      tux_options = *options;
      *options = 0;
      if ((tux_options) & TUX_WNOHANG) {
          *options |= WNOHANG;
        }
      if ((tux_options) & TUX_WUNTRACED)
        {
          *options |= WUNTRACED;
        }
    }
  else if (nbr == 247)
    {
      options = (uintptr_t*)&param4;
    }

  svcinfo("FLAGS: %llx\n", param3);

  long pid =
    tux_pidhook(nbr, param1, param2, param3, param4, param5, param6);
  if (pid > 0)
      pid = search_linux_pid(pid); /* This is a O(n) search might be slow */

  /* For wait4, the status flags are not identical too, translate them
   * The LSB is the cause of exist, mutxed with signal
   * LSB & 0x7f == 0,    child exited
   * LSB & 0x7f == 0x7f, child stopped
   * LSB         < 0,    child terminated by signal, signal number is LSB & 0x7f
   * The MSB is the exit code, identical to Nuttx
   *
   * Nuttx only properly implemented normal exit
   * We only ends up here with child exited, so just mock up the LSB as 0
   */

  /* SYS_wait4 */
  int32_t *status;
  if (nbr == 61)
    {
      status = (int32_t*)param2;
      (*status) &= 0xff00;
    }

  if (pid >= 0)
      return pid;
  else
      return -EALREADY;
}

long tux_getpid(unsigned long nbr)
{
  return this_task()->xcp.linux_pid;
}

long tux_gettid(unsigned long nbr)
{
  return this_task()->xcp.linux_tid;
}

long tux_sched_getaffinity(unsigned long nbr,
                           long pid, unsigned int len,
                           unsigned long *mask)
{
  TUX_CPU_ZERO_S(len, mask);
  TUX_CPU_SET_S(0, len, mask);
  return 0;
}
