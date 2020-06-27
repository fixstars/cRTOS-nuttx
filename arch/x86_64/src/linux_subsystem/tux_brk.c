#include <nuttx/arch.h>
#include <nuttx/sched.h>

#include <semaphore.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

void* tux_brk(unsigned long nbr, void* brk){
  struct tcb_s *rtcb = this_task();
  if((brk > rtcb->xcp.__min_brk))
  {
    rtcb->xcp.__brk = brk;
    if(rtcb->xcp.__brk >= rtcb->xcp.__min_brk + 0x200000)
      rtcb->xcp.__brk = rtcb->xcp.__min_brk + 0x200000;
  }
  return rtcb->xcp.__brk;
}

