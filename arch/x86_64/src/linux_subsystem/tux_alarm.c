#include <nuttx/arch.h>
#include <nuttx/kmalloc.h>
#include <nuttx/sched.h>
#include <nuttx/signal.h>

#include <errno.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"
#include "group/group.h"

#include <arch/irq.h>
#include <sys/mman.h>
#include <string.h>

static inline void translate_from_tux_sigaction(struct sigaction *out, const struct tux_sigaction *in){
    memcpy(out, in, sizeof(struct sigaction)); // Copy the function pointer.
    out->sa_flags = in->sa_flags;
    out->sa_mask = in->sa_mask;
}

static inline void translate_to_tux_sigaction(struct tux_sigaction *out, const struct sigaction *in){
    memcpy(out, in, sizeof(struct sigaction)); // Copy the function pointer.
    out->sa_flags = in->sa_flags;
    out->sa_mask = in->sa_mask;
}

long tux_alarm(unsigned long nbr, unsigned int second){
    int ret = 0;
    struct itimerspec ti;
    struct itimerspec tip;
    ti.it_interval.tv_sec = 0;
    ti.it_interval.tv_nsec = 0;

    ti.it_value.tv_sec = second;
    ti.it_value.tv_nsec = 0;

    if(second == 0){
        ti.it_value.tv_sec = 0;
        ret = timer_settime(this_task()->xcp.alarm_timer, 0, &ti, &tip);
        if(!ret)
            ret = tip.it_value.tv_sec;
    }else{
        if(!(this_task()->xcp.alarm_timer))
            ret = timer_create(CLOCK_REALTIME, NULL, &(this_task()->xcp.alarm_timer));
        if(!ret)
            ret = timer_settime(this_task()->xcp.alarm_timer, 0, &ti, NULL);
        else
            _info("Timer Create Failed %d\n", ret);
        if(!ret)
            ret = tip.it_value.tv_sec;
        else
            _info("Timer set Failed\n");
    }

    if(ret < 0) ret = -errno;
    return ret;
};

long tux_rt_sigaction(unsigned long nbr, int sig, const struct tux_sigaction* act, struct tux_sigaction* old_act, uint64_t set_size){
    int ret;

    struct sigaction lact;
    struct sigaction lold_act;

    if(set_size != sizeof(((struct tux_sigaction*)0)->sa_mask)) return -EINVAL;

    if(act) {
        translate_from_tux_sigaction(&lact, act);
        ret = sigaction(sig, &lact, &lold_act);
    } else {
        ret = sigaction(sig, NULL, &lold_act);
    }


    if(!ret && old_act)
        translate_to_tux_sigaction(old_act, &lold_act);

    if(ret < 0) ret = -errno;
    return ret;
};

long tux_rt_sigprocmask(unsigned long nbr, int how, const sigset_t *set, sigset_t *oset){
    int ret;
    sigset_t lset = (*set << 1);
    sigset_t loset;

    how += 1;

    ret = nxsig_procmask(how, &lset, &loset);

    *oset = (loset >> 1);

    return ret;
};

long tux_pause(unsigned long nbr){
    return pause();
};

long tux_rt_sigtimedwait(unsigned long nbr, const sigset_t* uthese, tux_siginfo_t *uinfo, const struct timespec *uts, size_t sigsetsize) {
    int ret;
    sigset_t luthese = (*uthese << 1);
    siginfo_t luinfo;

    ret = nxsig_timedwait(&luthese, &luinfo, uts);
    if(ret != -1) {
        // decode uinfo
        memset(uinfo, 0, sizeof(*uinfo));

        uinfo->si_signo = luinfo.si_signo;
        uinfo->si_code = luinfo.si_code;
        uinfo->si_errno = luinfo.si_errno;

        if(ret == SIGCHLD) {
            uinfo->_sifields._sigchld.si_pid = luinfo.si_pid;
            uinfo->_sifields._sigchld.si_status = luinfo.si_status;
        }

        // XXX: other signals have the siginfo unfilled
    }

    return ret;
}

void tux_abnormal_termination(int signo) {
  struct tcb_s *rtcb = (struct tcb_s *)this_task();

  _info("abnormal 2 of %d\n", rtcb->pid);

  /* Careful:  In the multi-threaded task, the signal may be handled on a
   * child pthread.
   */

  /* Kill of of the children of the task.  This will not kill the currently
   * running task/pthread (this_task).  It will kill the main thread of the
   * task group if the this_task is a
   * pthread.
   */

  group_kill_children((FAR struct task_tcb_s *)rtcb);

  /* Exit to terminate the task (note that exit() vs. _exit() is used. */
  /* Hack the unused parameter of exit call to make the exit procedure
   * skip signaling and wait for the shadow process to end, because on SIGKILL
   * the shadow process is already gone. */
  if(signo == 9)
      tux_syscall(60, 255, 0, 0, 0, 0xdeadbeef, 0xabcedf);
  else
      tux_syscall(60, 255, 0, 0, 0, 0, 0);
}
