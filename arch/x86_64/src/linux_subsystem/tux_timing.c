#include <sys/time.h>
#include <nuttx/arch.h>
#include <nuttx/sched.h>

#include <time.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

long tux_nanosleep(unsigned long nbr, const struct timespec *rqtp, struct timespec *rmtp){
  return nanosleep(rqtp, rmtp);
}

long tux_gettimeofday(unsigned long nbr, struct timeval *tv, struct timezone *tz){
  return gettimeofday(tv, tz);
}
