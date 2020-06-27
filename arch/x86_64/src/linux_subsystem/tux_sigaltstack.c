#include <nuttx/arch.h>
#include <string.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"
#include <sched/sched.h>
#include <group/group.h>
#include <task/task.h>

long tux_sigaltstack(unsigned long nbr, stack_t* ss, stack_t* oss) {
    struct tcb_s* tcb = this_task();
    int ret;

    ret = 0;

    if(!ss && !oss) return -EINVAL;

    // write the current setting back
    if(oss) {
        memset(oss, 0, sizeof(stack_t));
        oss->ss_flags |= tcb->xcp.signal_stack_flag;
        oss->ss_size = tcb->xcp.signal_stack_size;
        oss->ss_sp = (void*)tcb->xcp.signal_stack;
    }

    if(ss) {
        if(ss->ss_flags == TUX_SS_DISABLE) {
            if(tcb->xcp.signal_stack_flag != TUX_SS_ONSTACK) {
                tcb->xcp.signal_stack_flag = TUX_SS_DISABLE;
                tcb->xcp.signal_stack_size = 0;
                tcb->xcp.signal_stack = 0;
            } else {
                ret = -EPERM;
            }
        } else if(ss->ss_flags == 0) {
            tcb->xcp.signal_stack_flag = 0;
            tcb->xcp.signal_stack_size = ss->ss_size;
            tcb->xcp.signal_stack = (uint64_t)ss->ss_sp;
        } else{
            ret = -EINVAL;
        }
    }

    return ret;
}
