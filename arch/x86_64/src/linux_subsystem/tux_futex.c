#include <nuttx/arch.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

#define FUTEX_HT_SIZE 256

struct futex_q{
  sem_t sem;
  uint64_t key;
  uint32_t bitmask;
};

struct futex_q futex_hash_table[FUTEX_HT_SIZE];

long tux_futex(unsigned long nbr, int32_t* uaddr, int opcode, uint32_t val, uintptr_t val2, int32_t* uaddr2, uint32_t val3){
  struct tcb_s *tcb = this_task();
  int32_t* paddr = virt_to_phys(uaddr);
  int32_t* paddr2 = virt_to_phys(uaddr2);
  uint32_t s_head = (uint64_t)paddr % FUTEX_HT_SIZE;
  uint32_t s_head2 = (uint64_t)paddr2 % FUTEX_HT_SIZE;
  uint32_t hv = s_head;
  uint32_t hv2 = s_head2;
  const struct timespec *timeout = (const struct timespec *)val2;
  struct timespec now;
  int ret;
  irqstate_t flags;

  if(paddr == (void*)-1) return -1;

  // XXX: At the mean time only per process futex
  /*if(!(opcode & FUTEX_PRIVATE_FLAG)) return -1;*/

  // Discard the private flag
  opcode &= ~FUTEX_PRIVATE_FLAG;

  switch(opcode){
    case FUTEX_WAIT:
      svcinfo("T: %d LT: %d FUTEX_WAIT at %llx -> %llx\n", tcb->pid, tcb->xcp.linux_pid, uaddr, paddr);

      flags = enter_critical_section();

      while((futex_hash_table[hv].key != 0) && (futex_hash_table[hv].key != ((uint64_t)paddr))){
          hv++;
          hv %= FUTEX_HT_SIZE;
          if(hv == s_head) {
            leave_critical_section(flags);
            return -1; // Out of free futex
          }
      }

      if(*uaddr == val){
        if(futex_hash_table[hv].key == 0) sem_init(&(futex_hash_table[hv].sem), 0, 0);

        futex_hash_table[hv].key = (uint64_t)paddr;
        futex_hash_table[hv].bitmask = 0;

        ret = 0;
        if(timeout) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            now.tv_nsec += timeout->tv_nsec;
            now.tv_sec += timeout->tv_sec;
            if(now.tv_nsec >= NSEC_PER_SEC) {
                now.tv_nsec -= NSEC_PER_SEC;
                now.tv_sec++;
            }

            ret = nxsem_timedwait(&(futex_hash_table[hv].sem), &now);
        } else {
            nxsem_wait(&(futex_hash_table[hv].sem));
        }
      }

      leave_critical_section(flags);

      tux_errno_sanitaizer(&ret);
      return ret; // Either not blocked or waken

      break;
    case FUTEX_WAKE:
      svcinfo("T: %d LT: %d FUTEX_WAKE at %llx -> %llx\n", tcb->pid, tcb->xcp.linux_pid, uaddr, paddr);
      while(futex_hash_table[hv].key != ((uint64_t)paddr)){
          hv++;
          hv %= FUTEX_HT_SIZE;
          if(hv == s_head) {
            svcinfo("No such key: %llx\n", paddr);
            return 0; // ? No such key, wake no one
          }
      }

      int svalue;
      sem_getvalue(&(futex_hash_table[hv].sem), &svalue);
      val = val > -svalue ? -svalue : val;
      ret = val;
      for(;val > 0; val--){
        nxsem_post(&(futex_hash_table[hv].sem));
      }

      flags = enter_critical_section();
      sem_getvalue(&(futex_hash_table[hv].sem), &svalue);
      if(svalue == 0) {
          nxsem_destroy(&(futex_hash_table[hv].sem));
          futex_hash_table[hv].key = 0;
          futex_hash_table[hv].bitmask = 0;
      }
      leave_critical_section(flags);

      return ret;

      break;
    case FUTEX_WAIT_BITSET:
    case FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME:
      svcinfo("T: %d LT: %d FUTEX_WAIT_BITSET 0x%lx at %llx -> %llx\n", tcb->pid, tcb->xcp.linux_pid, val3, uaddr, paddr);

      flags = enter_critical_section();

      while((futex_hash_table[hv].key != 0) && (futex_hash_table[hv].key != ((uint64_t)paddr)) && (futex_hash_table[hv].bitmask != val3)){
          hv++;
          hv %= FUTEX_HT_SIZE;
          if(hv == s_head) {
            leave_critical_section(flags);
            return -1; // Out of free futex
          }
      }

      if(*uaddr == val){
        if(futex_hash_table[hv].key == 0) sem_init(&(futex_hash_table[hv].sem), 0, 0);

        futex_hash_table[hv].key = (uint64_t)paddr;
        futex_hash_table[hv].bitmask = val3;

        if(timeout && !(opcode & FUTEX_CLOCK_REALTIME)) {
            clock_gettime(CLOCK_MONOTONIC, &now);
            now.tv_nsec += timeout->tv_nsec;
            now.tv_sec += timeout->tv_sec;
            if(now.tv_nsec >= NSEC_PER_SEC) {
                now.tv_nsec -= NSEC_PER_SEC;
                now.tv_sec++;
            }
        }else{
            now.tv_nsec = timeout->tv_nsec;
            now.tv_sec = timeout->tv_sec + 120;
        }

        ret = 0;
        if(timeout){
            ret = nxsem_timedwait(&(futex_hash_table[hv].sem), &now);
        } else {
            nxsem_wait(&(futex_hash_table[hv].sem));
        }
      }

      leave_critical_section(flags);

      tux_errno_sanitaizer(&ret);
      return ret; // Either not blocked or waken

      break;
    case FUTEX_WAKE_BITSET:
    case FUTEX_WAKE_BITSET | FUTEX_CLOCK_REALTIME:
      svcinfo("T: %d LT: %d FUTEX_WAKE_BITSET 0x%lx at %llx -> %llx\n", tcb->pid, tcb->xcp.linux_pid, val3, uaddr, paddr);

      ret = 0;
      for(int i = 0; i < FUTEX_HT_SIZE; i++) {
          if(futex_hash_table[hv].key == ((uint64_t)paddr) && (futex_hash_table[hv].bitmask & val3)) {
              /* wake this */
              int svalue;
              sem_getvalue(&(futex_hash_table[hv].sem), &svalue);
              val = val > -svalue ? -svalue : val;
              ret += val;
              for(;val > 0; val--){
                nxsem_post(&(futex_hash_table[hv].sem));
              }

              flags = enter_critical_section();
              sem_getvalue(&(futex_hash_table[hv].sem), &svalue);
              if(svalue == 0) {
                  nxsem_destroy(&(futex_hash_table[hv].sem));
                  futex_hash_table[hv].key = 0;
                  futex_hash_table[hv].bitmask = 0;
              }
              leave_critical_section(flags);
          }
      }

      return ret;

      break;
    case FUTEX_CMP_REQUEUE:

      flags = enter_critical_section();

      if(*uaddr != val3) {
        ret = -EAGAIN;
        leave_critical_section(flags);
      } else {
        while(futex_hash_table[hv].key != ((uint64_t)paddr)) {
          hv++;
          hv %= FUTEX_HT_SIZE;
          if(hv == s_head) {
            svcinfo("No such key: %llx\n", paddr);
            leave_critical_section(flags);
            return 0; // ? No such key, wake no one
          }
        }

        while((futex_hash_table[hv2].key != 0) && (futex_hash_table[hv2].key != ((uint64_t)paddr2))){
          hv2++;
          hv2 %= FUTEX_HT_SIZE;
          if(hv2 == s_head2) {
            leave_critical_section(flags);
            return -ENOMEM; // Out of free futex
          }
        }

        /* wake val threads */
        int svalue;
        sem_getvalue(&(futex_hash_table[hv].sem), &svalue);
        val = val > -svalue ? -svalue : val;
        for(;val > 0; val--){
          nxsem_post(&(futex_hash_table[hv].sem));
        }

        /* Requeue val2 threads */
        sem_getvalue(&(futex_hash_table[hv].sem), &svalue);
        val2 = val2 > -svalue ? -svalue : val2;

        if(futex_hash_table[hv2].key == 0) {
          sem_init(&(futex_hash_table[hv2].sem), 0, 0);
          futex_hash_table[hv2].key = (uint64_t)paddr2;
          futex_hash_table[hv2].bitmask = 0;
        }

        /* HACK: Move the task to wait on another semaphore */
        struct tcb_s *stcb;
        for (stcb = (FAR struct tcb_s *)g_waitingforsemaphore.head;
             (stcb && stcb->waitsem == &(futex_hash_table[hv].sem) && val2 > 0);
             stcb = stcb->flink, val2--) {

            futex_hash_table[hv].sem.semcount++;
            futex_hash_table[hv2].sem.semcount--;
            stcb->waitsem = &(futex_hash_table[hv2].sem);

            /* maybe a good time to biist the priority for PI to work properly*/
            /*nxsem_boostholderprio(FAR struct semholder_s *pholder,*/
        }
      }

      leave_critical_section(flags);

      ret = 0;

      tux_errno_sanitaizer(&ret);
      return ret;
      break;
    case FUTEX_WAKE_OP:
      svcinfo("T: %d FUTEX_WAKE_OP at %llx -> %llx and %llx -> %llx\n", tcb->xcp.linux_pid, uaddr, paddr, uaddr2, paddr2);

      int32_t oparg = FUTEX_GET_OPARG(val3);
      if(FUTEX_GET_OP(val3) & FUTEX_OP_ARG_SHIFT)
          if(oparg < 0 || oparg > 31)
              oparg &= 31;
          oparg <<= 1;

      svcinfo("op: 0x%x, arg: 0x%x\n", FUTEX_GET_OP(val3), oparg);
      svcinfo("cmp: 0x%x, arg: 0x%x\n", FUTEX_GET_CMP(val3), FUTEX_GET_CMPARG(val3));

      flags = enter_critical_section();

      int32_t oldval = *(int *) uaddr2;
      switch(FUTEX_GET_OP(val3)) {
          case FUTEX_OP_SET:
              *(volatile int *) uaddr2 = oparg;
              break;
          case FUTEX_OP_ADD:
              *(volatile int *) uaddr2 += oparg;
              break;
          case FUTEX_OP_OR:
              *(volatile int *) uaddr2 |= oparg;
              break;
          case FUTEX_OP_ANDN:
              *(volatile int *) uaddr2 &= ~oparg;
              break;
          case FUTEX_OP_XOR:
              *(volatile int *) uaddr2 ^= oparg;
              break;
      }

      ret = tux_futex(nbr, uaddr, FUTEX_WAKE, val, 0, 0, 0);

      int cmpflag = 0;
      switch(FUTEX_GET_CMP(val3)) {
          case FUTEX_OP_CMP_EQ:
              cmpflag = (oldval == FUTEX_GET_CMPARG(val3));
              break;
          case FUTEX_OP_CMP_NE:
              cmpflag = (oldval != FUTEX_GET_CMPARG(val3));
              break;
          case FUTEX_OP_CMP_LT:
              cmpflag = (oldval < FUTEX_GET_CMPARG(val3));
              break;
          case FUTEX_OP_CMP_LE:
              cmpflag = (oldval <= FUTEX_GET_CMPARG(val3));
              break;
          case FUTEX_OP_CMP_GT:
              cmpflag = (oldval > FUTEX_GET_CMPARG(val3));
              break;
          case FUTEX_OP_CMP_GE:
              cmpflag = (oldval >= FUTEX_GET_CMPARG(val3));
              break;
      }
      if(cmpflag)
          ret += tux_futex(nbr, uaddr2, FUTEX_WAKE, val2, 0, 0, 0);
      leave_critical_section(flags);

      return ret;

      break;
    default:
      _alert("Futex got unfriendly opcode: %d\n", opcode);
      PANIC();
    }
}

