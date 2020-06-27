#include <string.h>
#include <nuttx/arch.h>
#include <nuttx/kmalloc.h>
#include <nuttx/sched.h>

#include <errno.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"

#include <arch/irq.h>
#include <sys/mman.h>

static inline void* new_memory_block(uint64_t size, void** virt) {
    irqstate_t flags;
    void* ret;

    ret = gran_alloc(tux_mm_hnd, size);
    *virt = temp_map((uintptr_t)ret, (uintptr_t)ret + size);
    memset(*virt, 0, size);
    return ret;
}

extern void fork_kickstart(void*);

void clone_trampoline(void* regs, uint32_t* ctid) {
    uint64_t regs_on_stack[16];
    svcinfo("Entering Clone Trampoline\n");

    struct tcb_s *rtcb = this_task();
    struct vma_s *ptr;

    // Don't have to read the return value of remote fork, it is ignored
    // Nuttx task always knows its Linux endpoint
    // However, Linux task only knows the Nuttx endpoint after the first call is issued from the RT-process
    /*uint64_t dummy;*/
    /*read(rtcb->xcp.linux_sock, &dummy, sizeof(dummy));*/

    for(ptr = rtcb->xcp.vma; ptr; ptr = ptr->next){
        tux_delegate(9, (((uint64_t)ptr->pa_start) << 32) | (uint64_t)(ptr->va_start), VMA_SIZE(ptr),
                     0, TUX_MAP_ANONYMOUS, 0, 0);
    }

    if(ctid) {
        *ctid = this_task()->xcp.linux_tid;
    }

    // Move the regs onto the stack and free the memory
    memcpy(regs_on_stack, regs, sizeof(uint64_t) * 16);
    kmm_free(regs);

    // Call a stub to jump to the actual entry point
    // It loads the same registers as the original task
    fork_kickstart(regs_on_stack);

    _exit(255); // We should never end up here
}

long tux_fork(unsigned long nbr) {
    return tux_clone(56, SIGCHLD, NULL, NULL, NULL, 0);
}

long tux_vfork(unsigned long nbr) {
    return tux_clone(56, SIGCHLD, NULL, NULL, NULL, 0);
}

long tux_clone(unsigned long nbr, unsigned long flags, void *child_stack,
              void *ptid, void *ctid,
              unsigned long tls){

  irqstate_t irqflags;
  int ret;
  struct task_tcb_s *tcb;
  struct tcb_s *rtcb = this_task();
  void* stack;
  struct vma_s *ptr, *ptr2, *pptr, *pda_ptr;
  uint64_t i, j;
  void* virt_mem;
  uint64_t *regs;

  tcb = (FAR struct task_tcb_s *)kmm_zalloc(sizeof(struct task_tcb_s));
  if (!tcb)
    return -1;

  stack = kmm_zalloc(0x8000); //Kernel stack
  if(!stack)
    return -1;

  ret = task_init((FAR struct tcb_s *)tcb, "clone_thread", rtcb->init_priority,
                  (uint32_t*)stack, 0x8000, NULL, NULL);
  if (ret < 0)
  {
    ret = -get_errno();
    berr("task_init() failed: %d\n", ret);
    goto errout_with_tcb;
  }

  /* Check the flags */
  /* XXX: Ignore CLONE_FS */
  /* XXX: Ignore CLONE_FILES */
  /* XXX: Ignore CLONE_SIGHAND */
  /* Ignore CLONE_VSEM, not sure how to properly handle this */

  if(flags & TUX_CLONE_SETTLS){
    tcb->cmn.xcp.fs_base_set = 1;
    tcb->cmn.xcp.fs_base = (uint64_t)tls;
  }


  /* Clone the VM */
  if(flags & TUX_CLONE_VM){
    tcb->cmn.xcp.vma = rtcb->xcp.vma;
    tcb->cmn.xcp.pda = rtcb->xcp.pda;
    tcb->cmn.xcp.pd1 = rtcb->xcp.pd1;

    /* manual set the stack pointer */
    tcb->cmn.xcp.regs[REG_RSP] = (uint64_t)child_stack;

    /* manual set the instruction pointer */
    tcb->cmn.xcp.regs[REG_RIP] = *((uint64_t*)(get_kernel_stack_ptr()) - 2); // Directly leaves the syscall


    /* attach to the parent thread group */
    ret = group_bind(tcb);
    if (ret < 0) {
        _err("group_join() failed: %d\n", ret);
        ret = -ENOMEM;
        goto errout_with_tcbinit;
    }

    ret = group_join(tcb);
    if (ret < 0){
        _err("group_join() failed: %d\n", ret);
        ret = -ENOMEM;
        goto errout_with_tcbinit;
    }

    uint64_t tid_slot = tux_delegate(56, 0, 0, 0, 0, 0, 0);
    tcb->cmn.xcp.linux_tid = tid_slot >> 48;
    tcb->cmn.xcp.linux_tcb = tid_slot & ~(0xffffULL << 48);

    /*add_remote_on_exit((struct tcb_s*)tcb, tux_on_exit, NULL);*/

    insert_proc_node(tcb->cmn.pid, tcb->cmn.xcp.linux_tid);

    if(flags & TUX_CLONE_CHILD_SETTID){
      *(uint32_t*)(ctid) = tcb->cmn.xcp.linux_tid;
    }

    if(flags & TUX_CLONE_CHILD_CLEARTID){
      _tux_set_tid_address((struct tcb_s*)tcb, (int*)(ctid));
    }

  }else{

    /* copy our mapped memory, including stack, to the new process */

    struct vma_s* mapping = NULL;
    struct vma_s* curr;

    for(ptr = rtcb->xcp.vma; ptr; ptr = ptr->next){
        if(ptr->pa_start != 0xffffffff) {
            curr = kmm_zalloc(sizeof(struct vma_s));
            curr->next = mapping;
            mapping = curr;
        }
    }

    tcb->cmn.xcp.vma = mapping;

    svcinfo("Copy mappings\n");
    for(ptr = rtcb->xcp.vma, curr = tcb->cmn.xcp.vma; ptr; ptr = ptr->next){
        if(ptr->pa_start == 0xffffffff){
            continue;
        }

        curr->va_start = ptr->va_start;
        curr->va_end = ptr->va_end;
        curr->proto = ptr->proto;

        curr->_backing = kmm_zalloc(strlen(ptr->_backing) + 1);
        strcpy(curr->_backing, ptr->_backing);

        curr->pa_start = (uintptr_t)new_memory_block(VMA_SIZE(ptr), &virt_mem);
        memcpy(virt_mem, (void*)ptr->va_start, VMA_SIZE(ptr));

        svcinfo("Mapping: %llx - %llx: %llx %s\n", ptr->va_start, ptr->va_end, curr->pa_start, curr->_backing);

        curr = curr->next;
    }

    svcinfo("Create new page table\n");

    tcb->cmn.xcp.pd1 = tux_mm_new_pd1();

    svcinfo("Copy pdas\n");
    tcb->cmn.xcp.pda = pda_ptr = kmm_zalloc(sizeof(struct vma_s));

    for(ptr = tcb->cmn.xcp.vma; ptr;){
        // Scan hole with continuous addressing and same proto
        for(pptr = ptr, ptr2 = ptr->next; ptr2 && (((pptr->va_end + HUGE_PAGE_SIZE - 1) & HUGE_PAGE_MASK) >= (ptr2->va_start & HUGE_PAGE_MASK)) && (pptr->proto == ptr2->proto); pptr = ptr2, ptr2 = ptr2->next){
            svcinfo("Boundary: %llx and %llx\n", ((pptr->va_end + HUGE_PAGE_SIZE - 1) & HUGE_PAGE_MASK), (ptr2->va_start & HUGE_PAGE_MASK));
            svcinfo("Merge: %llx - %llx and %llx - %llx\n", pptr->va_start, pptr->va_end, ptr2->va_start, ptr2->va_end);

        }

        svcinfo("PDA Mapping: %llx - %llx\n", ptr->va_start, pptr->va_end);

        pda_ptr->va_start = ptr->va_start & HUGE_PAGE_MASK;
        pda_ptr->va_end = (pptr->va_end + HUGE_PAGE_SIZE - 1) & HUGE_PAGE_MASK; //Align up
        pda_ptr->proto = ptr->proto; // All proto are the same
        pda_ptr->_backing = "";

        pda_ptr->pa_start = (uintptr_t)new_memory_block(VMA_SIZE(pda_ptr) / HUGE_PAGE_SIZE * PAGE_SIZE, &virt_mem);
        do{
            for(i = ptr->va_start; i < ptr->va_end; i += PAGE_SIZE){
                ((uint64_t*)(virt_mem))[((i - pda_ptr->va_start) >> 12) & 0x3ffff] = (ptr->pa_start + i - ptr->va_start) | ptr->proto;
            }
            ptr = ptr->next;
        }while(ptr != pptr->next);

        irqflags = enter_critical_section();
        uint64_t* tmp_pd = temp_map((uintptr_t)tcb->cmn.xcp.pd1, (uintptr_t)tcb->cmn.xcp.pd1 + PAGE_SIZE);

        // Map it via page directories
        for(j = pda_ptr->va_start; j < pda_ptr->va_end; j += HUGE_PAGE_SIZE) {
        tmp_pd[(j >> 21) & 0x7ffffff] = (((j - pda_ptr->va_start) >> 9) + pda_ptr->pa_start) | pda_ptr->proto;
        }
        leave_critical_section(irqflags);

        if(ptr){
            pda_ptr->next = kmm_zalloc(sizeof(struct vma_s));
            pda_ptr = pda_ptr->next;
        }
    }

    svcinfo("All mapped\n");

    // set brk
    tcb->cmn.xcp.__min_brk = rtcb->xcp.__min_brk;
    tcb->cmn.xcp.__brk = rtcb->xcp.__brk;

    if(!(flags & TUX_CLONE_SETTLS)) {
        tcb->cmn.xcp.fs_base_set = rtcb->xcp.fs_base_set;
        tcb->cmn.xcp.fs_base = rtcb->xcp.fs_base;
    }

    tcb->cmn.xcp.linux_tcb = tux_delegate(57, 0, 0, 0, 0, 0, 0); // Get a new shadow process
    tcb->cmn.xcp.linux_pid = (0xffff & (tcb->cmn.xcp.linux_tcb >> 48));
    tcb->cmn.xcp.linux_tid = tcb->cmn.xcp.linux_pid;
    tcb->cmn.xcp.linux_tcb &= ~(0xffffULL << 48);

    tcb->cmn.xcp.is_linux = 2; /* This is the head of threads, responsible to scrap the addrenv */

    /* Inherit signal stack */
    tcb->cmn.xcp.signal_stack_flag = rtcb->xcp.signal_stack_flag;
    tcb->cmn.xcp.signal_stack = rtcb->xcp.signal_stack;

    insert_proc_node(tcb->cmn.pid, tcb->cmn.xcp.linux_pid);

    /*add_remote_on_exit((struct tcb_s*)tcb, tux_on_exit, NULL);*/

    /* manual set the instruction pointer */
    regs = kmm_zalloc(sizeof(uint64_t) * 16);
    memcpy(regs, (uint64_t*)(get_kernel_stack_ptr()) - 16, sizeof(uint64_t) * 16);
    tcb->cmn.xcp.regs[REG_RDI] = (uintptr_t)regs;
    tcb->cmn.xcp.regs[REG_RSI] = 0;
    tcb->cmn.xcp.regs[REG_RIP] = (uintptr_t)clone_trampoline; // We need to manage the memory mapping
    /* stack is the new kernel stack */

    /* Let the trampoline handle it */
    if(flags & TUX_CLONE_CHILD_SETTID){
         tcb->cmn.xcp.regs[REG_RSI] = (uintptr_t)ctid;
    }
  }

  /* set it after copying the memory to child */
  if(flags & TUX_CLONE_PARENT_SETTID){
    *(uint32_t*)(ptid) = tcb->cmn.xcp.linux_tid;
  }

  svcinfo("Cloned a task(0x%llx)<%d> with RIP=0x%llx, RSP=0x%llx, kstack=0x%llx\n",
          tcb,
          tcb->cmn.pid,
          tcb->cmn.xcp.regs[REG_RIP],
          tcb->cmn.xcp.regs[REG_RSP],
          stack);

  /* clone return 0 to child */
  tcb->cmn.xcp.regs[REG_RAX] = 0;

  sinfo("activate: new task=%d\n", tcb->cmn.pid);
  /* Then activate the task at the provided priority */
  ret = task_activate((FAR struct tcb_s *)tcb);
  if (ret < 0)
  {
    ret = -get_errno();
    berr("task_activate() failed: %d\n", ret);
    goto errout_with_tcbinit;
  }

  return tcb->cmn.xcp.linux_tid;

errout_with_tcbinit:
    nxsched_release_tcb(&tcb->cmn, TCB_FLAG_TTYPE_TASK);
    return -1;

errout_with_tcb:
    kmm_free(tcb);
    kmm_free(stack);
    return -1;
}

