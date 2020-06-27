#include <nuttx/arch.h>
#include <nuttx/sched.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

int* _tux_set_tid_address(struct tcb_s *rtcb, int* tidptr){
  int* orig_val;
  irqstate_t flags;

  flags = enter_critical_section();

  orig_val = rtcb->xcp.clear_child_tid;
  rtcb->xcp.clear_child_tid = tidptr;

  leave_critical_section(flags);
  return orig_val;
}

long tux_set_tid_address(unsigned long nbr, int* tidptr){
  struct tcb_s *rtcb = this_task();
  _tux_set_tid_address(rtcb, tidptr);
  return rtcb->xcp.linux_tid;
}

void tux_set_tid_callback(void){
  struct tcb_s *rtcb = this_task();
  if(rtcb->xcp.clear_child_tid != NULL)
  {
    // According to man pages
    *(rtcb->xcp.clear_child_tid) = 0;
    tux_futex(0, rtcb->xcp.clear_child_tid, FUTEX_WAKE, 1, 0, 0, 0);
  }
}
