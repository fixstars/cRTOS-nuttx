/****************************************************************************
 *  arch/x86_64/src/linux_subsystem/tux.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
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

/****************************************************************************
 * Pre-processor definitions
 ****************************************************************************/

/* Configurations */

#define MEM_1GB                   0x40000000
#define TUX_KSTACK_SIZE           (PAGE_SIZE * 2)

/* CLONE */

#define TUX_CSIGNAL               0x000000ff /* Signal mask to be sent at exit.  */
#define TUX_CLONE_VM              0x00000100 /* Set if VM shared between processes.  */
#define TUX_CLONE_FS              0x00000200 /* Set if fs info shared between processes.  */
#define TUX_CLONE_FILES           0x00000400 /* Set if open files shared between processes.  */
#define TUX_CLONE_SIGHAND         0x00000800 /* Set if signal handlers shared.  */
#define TUX_CLONE_THREAD          0x00010000 /* Set to add to same thread group.  */
#define TUX_CLONE_SETTLS          0x00080000 /* Set TLS info.  */
#define TUX_CLONE_PARENT_SETTID   0x00100000 /* Store TID in userlevel buffer before MM copy.  */
#define TUX_CLONE_CHILD_CLEARTID  0x00200000 /* Register exit futex and memory location to clear.  */
#define TUX_CLONE_CHILD_SETTID    0x01000000 /* Store TID in userlevel buffer in the child.  */

/* MMAP */

#define TUX_MAP_SHARED            0x01       /* Share changes */
#define TUX_MAP_PRIVATE           0x02       /* Changes are private */
#define TUX_MAP_SHARED_VALIDATE   0x03       /* share + validate extension flags */
#define TUX_MAP_TYPE              0x0f       /* Mask for type of mapping */
#define TUX_MAP_FIXED             0x10       /* Interpret addr exactly */
#define TUX_MAP_ANONYMOUS         0x20       /* don't use a file */
#define TUX_MAP_GROWSDOWN         0x00100    /* Stack-like segment.  */
#define TUX_MAP_DENYWRITE         0x00800    /* ETXTBSY */
#define TUX_MAP_EXECUTABLE        0x01000    /* Mark it as an executable.  */
#define TUX_MAP_LOCKED            0x02000    /* Lock the mapping.  */
#define TUX_MAP_NORESERVE         0x04000    /* Don't check for reservations.  */
#define TUX_MAP_POPULATE          0x08000    /* Populate (prefault) pagetables.  */
#define TUX_MAP_NONBLOCK          0x10000    /* Do not block on IO.  */
#define TUX_MAP_STACK             0x20000    /* Allocation is for a stack.  */
#define TUX_MAP_HUGETLB           0x40000    /* Create huge page mapping.  */

#define TUX_MREMAP_MAYMOVE        1
#define TUX_MREMAP_FIXED          2

#define TUX_PROT_READ             0x1        /* page can be read */
#define TUX_PROT_WRITE            0x2        /* page can be written */
#define TUX_PROT_EXEC             0x4        /* page can be executed */
#define TUX_PROT_SEM              0x8        /* page may be used for atomic ops */
#define TUX_PROT_NONE             0x0        /* page can not be accessed */

/* FUTEX */

#define FUTEX_WAIT                0x0
#define FUTEX_WAKE                0x1
#define FUTEX_WAKE_OP             0x5
#define FUTEX_REQUEUE               3
#define FUTEX_CMP_REQUEUE           4
#define FUTEX_WAIT_BITSET           9
#define FUTEX_WAKE_BITSET          10
#define FUTEX_PRIVATE_FLAG       0x80
#define FUTEX_CLOCK_REALTIME      256

#define FUTEX_OP_SET                0        /* uaddr2 = oparg; */
#define FUTEX_OP_ADD                1        /* uaddr2 += oparg; */
#define FUTEX_OP_OR                 2        /* uaddr2 |= oparg; */
#define FUTEX_OP_ANDN               3        /* uaddr2 &= ~oparg; */
#define FUTEX_OP_XOR                4        /* uaddr2 ^= oparg; */

#define FUTEX_OP_ARG_SHIFT          8        /* Use (1 << oparg) as operand */

#define FUTEX_GET_OP(x)             ((x >> 28) & 0xf)
#define FUTEX_GET_OPARG(x)          ((int32_t)((x >> 12) & 0xfff) << 20 >> 20)

#define FUTEX_OP_CMP_EQ             0        /* if (oldval == cmparg) wake */
#define FUTEX_OP_CMP_NE             1        /* if (oldval != cmparg) wake */
#define FUTEX_OP_CMP_LT             2        /* if (oldval < cmparg) wake */
#define FUTEX_OP_CMP_LE             3        /* if (oldval <= cmparg) wake */
#define FUTEX_OP_CMP_GT             4        /* if (oldval > cmparg) wake */
#define FUTEX_OP_CMP_GE             5        /* if (oldval >= cmparg) wake */

#define FUTEX_GET_CMP(x)            ((x >> 24) & 0xf)
#define FUTEX_GET_CMPARG(x)         ((int32_t)(x & 0xfff) << 20 >> 20)

/* Open */

#define TUX_O_ACCMODE        00000003
#define TUX_O_RDONLY         00000000
#define TUX_O_WRONLY         00000001
#define TUX_O_RDWR           00000002
#define TUX_O_CREAT          00000100
#define TUX_O_EXCL           00000200
#define TUX_O_NOCTTY         00000400
#define TUX_O_TRUNC          00001000
#define TUX_O_APPEND         00002000
#define TUX_O_NONBLOCK       00004000
#define TUX_O_DSYNC          00010000
#define TUX_O_DIRECT         00040000
#define TUX_O_LARGEFILE      00100000
#define TUX_O_DIRECTORY      00200000
#define TUX_O_NOFOLLOW       00400000
#define TUX_O_NOATIME        01000000
#define TUX_O_CLOEXEC        02000000
#define TUX__O_SYNC          04000000
#define TUX_O_SYNC           (TUX__O_SYNC|TUX_O_DSYNC)
#define TUX_O_PATH           010000000
#define TUX__O_TMPFILE       020000000
#define TUX_O_TMPFILE        (TUX__O_TMPFILE | TUX_O_DIRECTORY)
#define TUX_O_TMPFILE_MASK   (TUX__O_TMPFILE | TUX_O_DIRECTORY | TUX_O_CREAT)
#define TUX_O_NDELAY         O_NONBLOCK

/* POLL / SELECT */

#define TUX_FD_SETSIZE      1024
#define TUX_NFDBITS         (8 * (int) sizeof (long int))
#define TUX_FD_ELT(d)       ((d) / TUX_NFDBITS)
#define TUX_FD_MASK(d)      ((long int) (1UL << ((d) % TUX_NFDBITS)))

#define TUX_POLLIN          0x001       /* There is data to read.  */
#define TUX_POLLPRI         0x002       /* There is urgent data to read.  */
#define TUX_POLLOUT         0x004       /* Writing now will not block.  */

#define TUX_POLLRDNORM      0x040       /* Normal data may be read.  */
#define TUX_POLLRDBAND      0x080       /* Priority data may be read.  */
#define TUX_POLLWRNORM      0x100       /* Writing now will not block.  */
#define TUX_POLLWRBAND      0x200       /* Priority data may be written.  */

#define TUX_POLLMSG         0x400
#define TUX_POLLREMOVE      0x1000
#define TUX_POLLRDHUP       0x2000

#define TUX_POLLERR         0x008        /* Error condition.  */
#define TUX_POLLHUP         0x010        /* Hung up.  */
#define TUX_POLLNVAL        0x020        /* Invalid polling request.  */

#define TUX_IPC_CREAT       01000        /* create key if key does not exist. */
#define TUX_IPC_EXCL        02000        /* fail if key exists.  */

#define TUX_IPC_RMID            0        /* remove resource */
#define TUX_IPC_SET             1        /* set ipc_perm options */
#define TUX_IPC_STAT            2        /* get ipc_perm options */
#define TUX_IPC_INFO            3        /* see ipcs */

#define TUX_SHM_LOCK           11

#define TUX_SEM_GETVAL         12        /* get semval */
#define TUX_SEM_GETALL         13        /* get all semval's */
#define TUX_SEM_SETVAL         16        /* set semval */
#define TUX_SEM_SETALL         17        /* set all semval's */

#define TUX_SEM_UNDO       0x1000        /* undo the operation on exit */

#define TUX_WNOHANG             1        /* Don't block waiting.  */
#define TUX_WUNTRACED           2        /* Report status of stopped children.  */
#define TUX_WSTOPPED            2        /* Report stopped child (same as WUNTRACED). */
#define TUX_WEXITED             4        /* Report dead child.  */
#define TUX_WCONTINUED          8        /* Report continued child.  */
#define TUX_WNOWAIT    0x01000000        /* Don't reap, just poll status.  */

/* CPU MASK */

typedef unsigned long tux_cpu_mask;
# define TUX_NCPUBITS           (8 * sizeof (tux_cpu_mask))
# define TUX_CPUELT(cpu)        ((cpu) / TUX_NCPUBITS)
# define TUX_CPUMASK(cpu)       ((tux_cpu_mask) 1 << ((cpu) % TUX_NCPUBITS))

#if __GNUC_PREREQ (2, 91)
# define TUX_CPU_ZERO_S(setsize, cpusetp) \
  do __builtin_memset (cpusetp, '\0', setsize); while (0)
#else
# define TUX_CPU_ZERO_S(setsize, cpusetp) \
  do { \
    size_t __i; \
    size_t __imax = (setsize) / sizeof (tux_cpu_mask); \
    tux_cpu_mask *__bits = (cpusetp); \
    for (__i = 0; __i < __imax; ++__i) \
      __bits[__i] = 0; \
  } while (0)
#endif

#define TUX_CPU_SET_S(cpu, setsize, cpusetp) \
  (__extension__ \
   ({ size_t __cpu = (cpu); \
      __cpu / 8 < (setsize) \
      ? (((tux_cpu_mask *) ((cpusetp)))[TUX_CPUELT (__cpu)] \
         |= TUX_CPUMASK (__cpu)) \
      : 0; }))
#define TUX_CPU_CLR_S(cpu, setsize, cpusetp) \
  (__extension__ \
   ({ size_t __cpu = (cpu); \
      __cpu / 8 < (setsize) \
      ? (((tux_cpu_mask *) ((cpusetp)))[TUX_CPUELT (__cpu)] \
         &= ~TUX_CPUMASK (__cpu)) \
      : 0; }))

# define __SI_MAX_SIZE     128
#  define __SI_PAD_SIZE    ((__SI_MAX_SIZE / sizeof (int)) - 4)

/****************************************************************************
 * Public Types
 ****************************************************************************/

/* RLIMIT */

struct rlimit
{
  unsigned long rlim_cur;  /* Soft limit */
  unsigned long rlim_max;  /* Hard limit (ceiling for rlim_cur) */
};

/* POLL / SELECT */

struct tux_fd_set
{
  long int __fds_bits[TUX_FD_SETSIZE / TUX_NFDBITS];
};

typedef unsigned long int tux_nfds_t;
struct tux_pollfd
{
  int fd;                        /* File descriptor to poll.  */
  short int events;              /* Types of events poller cares about.  */
  short int revents;             /* Types of events that actually occurred.  */
};

/* SYS-V IPC */

struct ipc_perm {
  uint32_t       __key;     /* Key supplied to shmget(2) */
  uint64_t       uid;       /* Effective UID of owner */
  uint64_t       gid;       /* Effective GID of owner */
  uint64_t       cuid;      /* Effective UID of creator */
  uint64_t       cgid;      /* Effective GID of creator */
  unsigned short mode;      /* Permissions + SHM_DEST and
                               SHM_LOCKED flags */
  unsigned short __seq;     /* Sequence number */
};

struct shmid_ds
{
  struct ipc_perm shm_perm; /* operation permission struct */
  uint64_t shm_segsz;       /* size of segment in bytes */
  uint64_t shm_atime;       /* time of last shmat() */
  uint64_t shm_dtime;       /* time of last shmdt() */
  uint64_t shm_ctime;       /* time of last change by shmctl() */
  uint32_t shm_cpid;        /* pid of creator */
  uint32_t shm_lpid;        /* pid of last shmop */
  uint64_t shm_nattch;      /* number of current attaches */
  uint64_t __glibc_reserved4;
  uint64_t __glibc_reserved5;
};

struct semid_ds
{
  struct ipc_perm sem_perm; /* operation permission struct */
  uint64_t sem_otime;       /* last semop() time */
  uint64_t __glibc_reserved1;
  uint64_t sem_ctime;       /* last time changed by semctl() */
  uint64_t __glibc_reserved2;
  uint64_t sem_nsems;       /* number of semaphores in set */
  uint64_t __glibc_reserved3;
  uint64_t __glibc_reserved4;
};

union semun
{
    int val;                /* value for SETVAL */
    struct semid_ds *buf;   /* buffer for IPC_STAT & IPC_SET */
    unsigned short *array;  /* array for GETALL & SETALL */
    struct seminfo *__buf;  /* buffer for IPC_INFO */
    void *__pad;
};

struct sembuf
{
  unsigned short int sem_num; /* semaphore number */
  short int sem_op;           /* semaphore operation */
  short int sem_flg;          /* operation flag */
};

/* SIGNAL STACK */

enum
{
  TUX_SS_ONSTACK = 1,
#define TUX_SS_ONSTACK        TUX_SS_ONSTACK
  TUX_SS_DISABLE
#define TUX_SS_DISABLE        TUX_SS_DISABLE
};

typedef struct sigaltstack
{
    void *ss_sp;
    int ss_flags;
    size_t ss_size;
} stack_t;

/* SIGACTION / SIGNAL */

struct tux_sigaction
{
  uintptr_t  __sigaction_handler;
  unsigned long sa_mask;
  unsigned long sa_flags;
  void (*sa_restorer) (void);
};

typedef union tux_sigval
{
  int sival_int;
  void *sival_ptr;
} tux_sigval_t;

typedef struct
{
  int si_signo; /* Signal number.  */
  int si_errno; /* If non-zero, an errno value associated with
                   this signal, as defined in <errno.h>.  */
  int si_code;  /* Signal code.  */

  union
    {
  int _pad[__SI_PAD_SIZE];

  /* kill(). */

  struct
    {
      int32_t si_pid;  /* Sending process ID.  */
      uint32_t si_uid; /* Real user ID of sending process.  */
    } _kill;

  /* POSIX.1b timers. */
  struct
    {
      int si_tid;             /* Timer ID.  */
      int si_overrun;         /* Overrun count.  */
      tux_sigval_t si_sigval; /* Signal value.  */
    } _timer;

  /* POSIX.1b signals. */
  struct
    {
      int32_t si_pid;         /* Sending process ID.  */
      uint32_t si_uid;        /* Real user ID of sending process.  */
      tux_sigval_t si_sigval; /* Signal value.  */
    } _rt;

  /* SIGCHLD. */
  struct
    {
      int32_t si_pid;         /* Which child.  */
      uint32_t si_uid;        /* Real user ID of sending process.  */
      int si_status;          /* Exit value or signal.  */
      unsigned long si_utime;
      unsigned long si_stime;
    } _sigchld;

  /* SIGILL, SIGFPE, SIGSEGV, SIGBUS. */
  struct
    {
      void *si_addr;          /* Faulting insn/memory ref.  */
      short int si_addr_lsb;  /* Valid LSB of the reported address.  */
      struct
        {
          void *_lower;
          void *_upper;
        } si_addr_bnd;
    } _sigfault;

  /* SIGPOLL. */
  struct
    {
      long int si_band;       /* Band event for SIGPOLL.  */
      int si_fd;
    } _sigpoll;

  /* SIGSYS. */
  struct
      {
        void *_call_addr;     /* Calling user insn.  */
        int _syscall;         /* Triggering system call number.  */
        unsigned int _arch;   /* AUDIT_ARCH_* of syscall.  */
      } _sigsys;
    } _sifields;
} tux_siginfo_t;

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

static inline uint64_t* temp_map_at_0xc0000000(uintptr_t start, uintptr_t end)
{
  uintptr_t k;
  uintptr_t lsb = start & ~HUGE_PAGE_MASK;
  start &= HUGE_PAGE_MASK;

  svcinfo("Temp map %llx - %llx at 0xc0000000\n", start, end);

  /* Temporary map the new pdas at high memory 0xc000000 ~ */

  for(k = start; k < end; k += HUGE_PAGE_SIZE)
    {
      pd[((0xc0000000 + k - start) >> 21) & 0x7ffffff]
          = k | X86_PAGE_PRESENT | X86_PAGE_WR |
                X86_PAGE_WRTHR | X86_PAGE_NOCACHE | X86_PAGE_GLOBAL;
    }

  up_invalid_TLB(start, end);

  return (uint64_t *)(0xc0000000 + lsb);
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


long tux_syscall(unsigned long, uintptr_t, uintptr_t,
                 uintptr_t, uintptr_t, uintptr_t,
                 uintptr_t);

long tux_local(unsigned long, uintptr_t, uintptr_t,
               uintptr_t, uintptr_t, uintptr_t,
               uintptr_t);

long tux_delegate(unsigned long, uintptr_t, uintptr_t,
                  uintptr_t, uintptr_t, uintptr_t,
                  uintptr_t);

long tux_file_delegate(unsigned long, uintptr_t, uintptr_t,
                       uintptr_t, uintptr_t, uintptr_t,
                       uintptr_t);

long tux_poll_delegate(unsigned long, uintptr_t, uintptr_t,
                       uintptr_t, uintptr_t, uintptr_t,
                       uintptr_t);

long tux_open_delegate(unsigned long, uintptr_t, uintptr_t,
                       uintptr_t, uintptr_t, uintptr_t,
                       uintptr_t);

long tux_dup2_delegate(unsigned long, uintptr_t, uintptr_t,
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
long     tux_waithook           (unsigned long, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

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
