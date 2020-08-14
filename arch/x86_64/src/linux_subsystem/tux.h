/****************************************************************************
 *  arch/x86_64/src/linux_subsystem/tux.h
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

#ifndef __LINUX_SUBSYSTEM_TUX_H
#define __LINUX_SUBSYSTEM_TUX_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <unistd.h>
#include <fcntl.h>
#include <features.h>

#include <nuttx/config.h>
#include <nuttx/compiler.h>
#include <nuttx/mm/gran.h>

#include "up_internal.h"

#include <sys/time.h>
#include <sched/sched.h>

#include <arch/io.h>

#include "tux_gpl.h"

/****************************************************************************
 * Pre-processor definitions
 ****************************************************************************/

/* Configurations */

#define MEM_1GB                   0x40000000
#define TUX_KSTACK_SIZE           (PAGE_SIZE * 2)

/****************************************************************************
 * Public Variables
 ****************************************************************************/

extern GRAN_HANDLE tux_mm_hnd;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static inline uint64_t set_msr(unsigned long nbr){
  uint32_t bitset = *((volatile uint32_t*)0xfb503280 + 4);
  bitset |= (1 << 1);
  *((volatile uint32_t*)0xfb503280 + 4) = bitset;
  return 0;
}

static inline uint64_t unset_msr(unsigned long nbr){
  uint32_t bitset = *((volatile uint32_t*)0xfb503280 + 4);
  bitset &= ~(1 << 1);
  *((volatile uint32_t*)0xfb503280 + 4) = bitset;
  return 0;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

static inline uint64_t* temp_map(uintptr_t start, uintptr_t end)
{
  svcinfo("Temp map %llx - %llx\n", start, end);

  return (uint64_t*)(start + 0x100000000);
}

static inline void *virt_to_phys(void *vaddr)
{
  struct tcb_s *tcb = this_task();
  struct vma_s *ptr;

  if((uintptr_t)vaddr > MEM_1GB)
      return (void *)-1;

  for(ptr = tcb->xcp.vma; ptr; ptr = ptr->next)
    {
      if(((uintptr_t)vaddr >= ptr->va_start) &&
         ((uintptr_t)vaddr < ptr->va_end && ptr->pa_start != 0xffffffff))
        {
          break;
        }
    }

  if(((uintptr_t)vaddr >= ptr->va_start) &&
     ((uintptr_t)vaddr < ptr->va_end && ptr->pa_start != 0xffffffff))
    {
      return (void*)(ptr->pa_start + (uintptr_t)vaddr - ptr->va_start);
    }
  return (void*) -1;
}

static inline long tux_success_stub(void)
{
  return 0;
}

static inline long tux_fail_stub(void)
{
  return -1;
}

static inline long
tux_no_impl(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
            uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
            uintptr_t parm6)
{
    _alert("Not implemented Linux syscall %d\n", nbr);
    PANIC();
    return -1;
}

static inline long tux_sched_get_priority_max(unsigned long nbr, uint64_t p)
{
  return sched_get_priority_max(p);
};

static inline long tux_sched_get_priority_min(unsigned long nbr, uint64_t p)
{
  return sched_get_priority_min(p);
};

/****************************************************************************
 * Public Function Prototypes
 ****************************************************************************/

void shadow_set_global_prio(uint64_t prio);
void up_check_tasks(void);

int  insert_proc_node(int lpid, int rpid);
int  delete_proc_node(int rpid);
long get_nuttx_pid(int rpid);
long get_linux_pid(int lpid);
long search_linux_pid(int lpid);
long tux_getppid(unsigned long nbr);

void tux_errno_sanitaizer(int *ret);

void     tux_mm_init            (void);
uint64_t *tux_mm_new_pd1        (void);
void     tux_mm_del_pd1         (uint64_t *);

int     *_tux_set_tid_address   (struct tcb_s *rtcb, int* tidptr);
void     tux_set_tid_callback   (void);

void     tux_abnormal_termination(int signo);

typedef long (*syscall_t)(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6);


long tux_syscall          (unsigned long, uintptr_t, uintptr_t,
                           uintptr_t, uintptr_t, uintptr_t,
                           uintptr_t);

long tux_local            (unsigned long, uintptr_t, uintptr_t,
                           uintptr_t, uintptr_t, uintptr_t,
                           uintptr_t);

long tux_delegate         (unsigned long, uintptr_t, uintptr_t,
                           uintptr_t, uintptr_t, uintptr_t,
                           uintptr_t);

long tux_file_delegate    (unsigned long, uintptr_t, uintptr_t,
                           uintptr_t, uintptr_t, uintptr_t,
                           uintptr_t);

long tux_poll_delegate    (unsigned long, uintptr_t, uintptr_t,
                           uintptr_t, uintptr_t, uintptr_t,
                           uintptr_t);

long tux_open_delegate    (unsigned long, uintptr_t, uintptr_t,
                           uintptr_t, uintptr_t, uintptr_t,
                           uintptr_t);

long tux_dup2_delegate    (unsigned long, uintptr_t, uintptr_t,
                           uintptr_t, uintptr_t, uintptr_t,
                           uintptr_t);

long     tux_nanosleep          (unsigned long, const struct timespec *, struct timespec *);
long     tux_gettimeofday       (unsigned long, struct timeval *, struct timezone *);

long     tux_clone              (unsigned long, unsigned long, void *,
                                 void *, void *, unsigned long);
long     tux_fork               (unsigned long);
long     tux_vfork              (unsigned long);

void    *tux_mmap               (unsigned long, void*, long, int, int, int, off_t);
long     tux_munmap             (unsigned long, void*, size_t);
void    *tux_mremap             (unsigned long, void *, size_t, size_t, int, void *);

long     tux_shmget             (unsigned long, uint32_t, uint32_t, uint32_t);
long     tux_shmctl             (unsigned long, int, uint32_t, struct shmid_ds*);
void    *tux_shmat              (unsigned long, int, void*, int);
long     tux_shmdt              (unsigned long, void*);

long     tux_semget             (unsigned long, uint32_t, int, uint32_t);
long     tux_semctl             (unsigned long, int, int, int, union semun);
long     tux_semop              (unsigned long, int, struct sembuf *, unsigned int);
long     tux_semtimedop         (unsigned long, int, struct sembuf *, unsigned int, const struct timespec*);

long     tux_getrlimit          (unsigned long, int, struct rlimit *);

long     tux_set_tid_address    (unsigned long, int*);

void    *tux_brk                (unsigned long, void*);

long     tux_arch_prctl         (unsigned long, int, unsigned long);
long     tux_futex              (unsigned long, int32_t*, int, uint32_t, uintptr_t, int32_t*, uint32_t);

long     tux_rt_sigaction       (unsigned long, int, const struct tux_sigaction *, struct tux_sigaction *, uint64_t);
long     tux_rt_sigprocmask     (unsigned long, int, const sigset_t *, sigset_t *);
long     tux_rt_sigtimedwait    (unsigned long, const sigset_t*, tux_siginfo_t *, const struct timespec *, size_t);
long     tux_alarm              (unsigned long, unsigned int);
long     tux_pause              (unsigned long);

long     tux_select             (unsigned long, int, struct tux_fd_set *, struct tux_fd_set *, struct tux_fd_set *, struct timeval *);

long     tux_poll               (unsigned long, struct tux_pollfd *, tux_nfds_t, int);

long     tux_getpid             (unsigned long);
long     tux_gettid             (unsigned long);
long     tux_getppid            (unsigned long);
long     tux_pidhook            (unsigned long, int, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
long     tux_waithook           (unsigned long, int32_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

long     tux_exec               (unsigned long, const char *, char *[], char *[]);
long     _tux_exec              (char *, char *[], char *[]);

long     tux_sigaltstack        (unsigned long, stack_t *, stack_t *);

long     tux_sched_getaffinity  (unsigned long, long, unsigned int, unsigned long *);

long     tux_exit               (unsigned long, uintptr_t, uintptr_t,
                                 uintptr_t, uintptr_t, uintptr_t,
                                 uintptr_t);

static inline long tux_pipe     (unsigned long nbr, int pipefd[2], int flags)
{
  int ret = pipe(pipefd);
  pipefd[0] += CONFIG_TUX_FD_RESERVE;
  pipefd[1] += CONFIG_TUX_FD_RESERVE;
  return ret;
};

static inline long tux_getcpu   (unsigned long nbr, unsigned *cpu, unsigned *node)
{
  if(node)
      *node = 0;
  if(cpu)
      *cpu = 0;
  return 0;
};

#endif//__LINUX_SUBSYSTEM_TUX_H
