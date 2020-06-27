#include <nuttx/arch.h>
#include <string.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

#define SHM_HT_SIZE 256

struct shm_q{
  struct shmid_ds info;
  uintptr_t addr;
  int flag;
};

struct shm_q shm_hash_table[SHM_HT_SIZE];

long tux_shmget(unsigned long nbr, uint32_t key, uint32_t size, uint32_t flags){
  struct tcb_s *tcb = this_task();
  uint32_t s_head = (uint64_t)key % SHM_HT_SIZE;
  uint32_t hv = s_head;
  int exist;
  int ret;
  irqstate_t irqflags;

  irqflags = enter_critical_section();

  exist = 1;
  while(!(shm_hash_table[hv].addr) || (shm_hash_table[hv].info.shm_perm.__key != key)){
      hv++;
      hv %= SHM_HT_SIZE;
      if(hv == s_head){
          exist = 0;
        break;
      }
  }

  if(exist && (flags & TUX_IPC_EXCL) && (flags & TUX_IPC_CREAT)) return -EEXIST;

  if(!exist)
      while((shm_hash_table[hv].addr)){
          hv++;
          hv %= SHM_HT_SIZE;
          if(hv == s_head) return -ENOMEM; // Out of free shm
      }

  if(shm_hash_table[hv].info.shm_perm.mode == 0){

      size = (size + ~PAGE_MASK) & PAGE_MASK;
      shm_hash_table[hv].addr = kmm_zalloc(size);
      if (shm_hash_table[hv].addr == 0) return -ENOMEM;

      memset(&shm_hash_table[hv].info, 0, sizeof(struct shmid_ds));

      shm_hash_table[hv].info.shm_perm.__key = key;
      shm_hash_table[hv].info.shm_perm.mode  = 0777;

      shm_hash_table[hv].info.shm_segsz      = size;
      shm_hash_table[hv].info.shm_cpid       = tcb->pid;
      shm_hash_table[hv].info.shm_nattch    = 0;
  }

  shm_hash_table[hv].info.shm_lpid       = tcb->pid;

  leave_critical_section(irqflags);

  svcinfo("%d SHM addr: 0x%llx\n", hv, shm_hash_table[hv].addr);

  return hv;
}


long tux_shmctl(unsigned long nbr, int hv, uint32_t cmd, struct shmid_ds* buf){
    if(!(shm_hash_table[hv].addr)) {
        svcinfo("No Such key!\n");
        return -EINVAL;
    }

    if(cmd == TUX_IPC_SET) {
        return 0; // Silent return without error
    }

    if(cmd != TUX_IPC_STAT && cmd != TUX_SHM_LOCK && cmd != TUX_IPC_RMID) {
        svcinfo("Only IPC_STAT, IPC_RMID and SHM_LOCK is supported!\n");
        return -EINVAL;
    }
    if(cmd == TUX_SHM_LOCK) {
        return 0; // Sliently handle SHM_LOCK
    } else if(cmd == TUX_IPC_RMID) {
        shm_hash_table[hv].flag = 1;
        if(shm_hash_table[hv].info.shm_nattch == 0 && shm_hash_table[hv].flag == 1){
            memset(&shm_hash_table[hv].info, 0, sizeof(struct shmid_ds));
            kmm_free((void*)shm_hash_table[hv].addr);
            shm_hash_table[hv].addr = NULL;
        }
    } else {
        memcpy(buf, &shm_hash_table[hv].info, sizeof(struct shmid_ds));

        shm_hash_table[hv].info.shm_lpid = this_task()->pid;
    }

    return 0;
}

void *tux_shmat(unsigned long nbr, int hv, void* addr, int flags){
    if(!(shm_hash_table[hv].addr)){
        svcinfo("SHMAT: Non-exist hv: 0x%x\n", hv);
        return (void*)-EINVAL;
    }
    if(addr){
        svcinfo("SHMAT: fix address not supported\n");
        return (void*)-EINVAL;
    }

    shm_hash_table[hv].info.shm_nattch += 1;
    shm_hash_table[hv].info.shm_lpid = this_task()->pid;

    return (void*)shm_hash_table[hv].addr;
}

long tux_shmdt(unsigned long nbr, void* addr){
    uint32_t hv = 0;
    irqstate_t irqflags;

    irqflags = enter_critical_section();

    while((shm_hash_table[hv].addr != (uintptr_t)addr)){
        hv++;
        hv %= SHM_HT_SIZE;
        if(hv == 0) return -EINVAL; // Out of free shm
    }

    shm_hash_table[hv].info.shm_nattch -= 1;
    shm_hash_table[hv].info.shm_lpid = this_task()->pid;

    if(shm_hash_table[hv].info.shm_nattch == 0 && shm_hash_table[hv].flag == 1){
        memset(&shm_hash_table[hv].info, 0, sizeof(struct shmid_ds));
        kmm_free((void*)shm_hash_table[hv].addr);
        shm_hash_table[hv].addr = NULL;
    }


    return 0;
}
