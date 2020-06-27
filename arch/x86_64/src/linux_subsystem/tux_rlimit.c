#include "tux.h"

/* Kinds of resource limit.  */
enum __rlimit_resource
{
  /* Per-process CPU limit, in seconds.  */
  RLIMIT_CPU = 0,
  /* Largest file that can be created, in bytes.  */
  RLIMIT_FSIZE = 1,
  /* Maximum size of data segment, in bytes.  */
  RLIMIT_DATA = 2,
  /* Maximum size of stack segment, in bytes.  */
  RLIMIT_STACK = 3,
  /* Largest core file that can be created, in bytes.  */
  RLIMIT_CORE = 4,
  /* Largest resident set size, in bytes.
     This affects swapping; processes that are exceeding their
     resident set size will be more likely to have physical memory
     taken from them.  */
  __RLIMIT_RSS = 5,
  /* Number of open files.  */
  RLIMIT_NOFILE = 7,
  __RLIMIT_OFILE = RLIMIT_NOFILE, /* BSD name for same.  */
  /* Address space limit.  */
  RLIMIT_AS = 9,
  /* Number of processes.  */
  __RLIMIT_NPROC = 6,
  /* Locked-in-memory address space.  */
  __RLIMIT_MEMLOCK = 8,
  /* Maximum number of file locks.  */
  __RLIMIT_LOCKS = 10,
  /* Maximum number of pending signals.  */
  __RLIMIT_SIGPENDING = 11,
  /* Maximum bytes in POSIX message queues.  */
  __RLIMIT_MSGQUEUE = 12,
  /* Maximum nice priority allowed to raise to.
     Nice levels 19 .. -20 correspond to 0 .. 39
     values of this resource limit.  */
  __RLIMIT_NICE = 13,
  /* Maximum realtime priority allowed for non-priviledged
     processes.  */
  __RLIMIT_RTPRIO = 14,
  /* Maximum CPU time in µs that a process scheduled under a real-time
     scheduling policy may consume without making a blocking system
     call before being forcibly descheduled.  */
  __RLIMIT_RTTIME = 15,
  __RLIMIT_NLIMITS = 16,
  __RLIM_NLIMITS = __RLIMIT_NLIMITS
};

long tux_getrlimit(unsigned long nbr, int resource, struct rlimit *rlim){
  switch(resource){
    case RLIMIT_STACK:
      rlim->rlim_cur = 0x800000;
      rlim->rlim_max = 0x800000;
      return 0;
    default:
      return -1;
  }
}


