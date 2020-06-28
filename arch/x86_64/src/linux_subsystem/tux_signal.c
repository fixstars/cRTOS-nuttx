/****************************************************************************
 *  arch/x86_64/src/linux_subsystem/tux_signal.c
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
#include <nuttx/kmalloc.h>
#include <nuttx/sched.h>

#include <errno.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

#include <arch/irq.h>
#include <sys/mman.h>

/****************************************************************************
 * Private Data
 ****************************************************************************/

uint8_t signal_translation_table[32] = {
    SIGHUP,     /* Hangup (POSIX).  */
    SIGINT,     /* Interrupt (ANSI).  */
    SIGQUIT,    /* Quit (POSIX).  */
    SIGILL,     /* Illegal instruction (ANSI).  */
    SIGTRAP,    /* Trace trap (POSIX).  */
    SIGABRT,    /* Abort (ANSI).  */
    SIGIOT,     /* IOT trap (4.2 BSD).  */
    SIGBUS,     /* BUS error (4.2 BSD).  */
    SIGFPE,     /* Floating-point exception (ANSI).  */
    SIGKILL,    /* Kill, unblockable (POSIX).  */
    SIGUSR1,    /* User-defined signal 1 (POSIX).  */
    SIGSEGV,    /* Segmentation violation (ANSI).  */
    SIGUSR2,    /* User-defined signal 2 (POSIX).  */
    SIGPIPE,    /* Broken pipe (POSIX).  */
    SIGALRM,    /* Alarm clock (POSIX).  */
    SIGTERM,    /* Termination (ANSI).  */
    SIGSTKFLT,  /* Stack fault.  */
    SIGCHLD,    /* Child status has changed (POSIX).  */
    SIGCONT,    /* Continue (POSIX).  */
    SIGSTOP,    /* Stop, unblockable (POSIX).  */
    SIGTSTP,    /* Keyboard stop (POSIX).  */
    SIGTTIN,    /* Background read from tty (POSIX).  */
    SIGTTOU,    /* Background write to tty (POSIX).  */
    SIGURG,     /* Urgent condition on socket (4.2 BSD).  */
    SIGXCPU,    /* CPU limit exceeded (4.2 BSD).  */
    SIGXFSZ,    /* File size limit exceeded (4.2 BSD).  */
    SIGVTALRM,  /* Virtual alarm clock (4.2 BSD).  */
    SIGPROF,    /* Profiling alarm clock (4.2 BSD).  */
    SIGWINCH,   /* Window size change (4.3 BSD, Sun).  */
    SIGIO,      /* I/O now possible (4.2 BSD).  */
    SIGPWR,     /* Power failure restart (System V).  */
    SIGSYS,     /* Bad system call.  */
    SIGUNUSED,
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

long tux_rt_sigaction(unsigned long nbr,
                      int sig,
                      const struct tux_sigaction* act,
                      struct tux_sigaction* old_act, uint64_t set_size)
{
  int ret;

  struct sigaction lact;
  struct sigaction lold_act;

  if (set_size != sizeof(((struct tux_sigaction*)0)->sa_mask))
      return -EINVAL;

  if (act)
    {
      translate_from_tux_sigaction(&lact, act);
      ret = sigaction(sig, &lact, &lold_act);
    }
  else
    {
      ret = sigaction(sig, NULL, &lold_act);
    }


  if (!ret && old_act)
      translate_to_tux_sigaction(old_act, &lold_act);

  if (ret < 0)
      ret = -errno;
  return ret;
};

