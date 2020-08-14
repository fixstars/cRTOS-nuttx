/****************************************************************************
 *  arch/x86/src/common/up_releasestack.c
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <sched.h>
#include <debug.h>

#include <nuttx/arch.h>
#include <nuttx/kmalloc.h>

#include "up_internal.h"
#include "arch/io.h"
#include "arch/irq.h"

#ifdef CONFIG_CRTOS
#include "tux.h"
#endif

/****************************************************************************
 * Private Types
 ****************************************************************************/

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: up_release_stack
 *
 * Description:
 *   A task has been stopped. Free all stack related resources retained in
 *   the defunct TCB.
 *
 * Input Parameters:
 *   - dtcb:  The TCB containing information about the stack to be released
 *   - ttype:  The thread type.  This may be one of following (defined in
 *     include/nuttx/sched.h):
 *
 *       TCB_FLAG_TTYPE_TASK     Normal user task
 *       TCB_FLAG_TTYPE_PTHREAD  User pthread
 *       TCB_FLAG_TTYPE_KERNEL   Kernel thread
 *
 *     This thread type is normally available in the flags field of the TCB,
 *     however, there are certain error recovery contexts where the TCB may
 *     not be fully initialized when up_release_stack is called.
 *
 *     If CONFIG_BUILD_KERNEL is defined, then this thread type may affect
 *     how the stack is freed.  For example, kernel thread stacks may have
 *     been allocated from protected kernel memory.  Stacks for user tasks
 *     and threads must have come from memory that is accessible to user
 *     code.
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/

void up_release_stack(FAR struct tcb_s *dtcb, uint8_t ttype)
{
  /* Is there a stack allocated? */

  if (dtcb->stack_alloc_ptr)
    {
#ifdef CONFIG_MM_KERNEL_HEAP
      /* Use the kernel allocator if this is a kernel thread */

      if (ttype == TCB_FLAG_TTYPE_KERNEL)
        {
          kmm_free(dtcb->stack_alloc_ptr);
        }
      else
#endif
        {
          /* Use the user-space allocator if this is a task or pthread */

          kumm_free(dtcb->stack_alloc_ptr);
        }

      /* Mark the stack freed */

      dtcb->stack_alloc_ptr = NULL;
    }

  /* The size of the allocated stack is now zero */

  dtcb->adj_stack_size = 0;

#ifdef CONFIG_CRTOS
  struct vma_s* ptr;
  struct vma_s* tptr;

  /* Clean up the mmaped virtual memories */

  if (dtcb->xcp.is_linux == 2)
    {

    for (ptr = dtcb->xcp.vma; ptr;)
      {
        if (ptr == &g_vm_full_map)
          continue;

        if (ptr->pa_start != 0xffffffff) {
            gran_free(tux_mm_hnd, (void*)(ptr->pa_start),
                      ptr->va_end - ptr->va_start);
        }

#ifdef CONFIG_DEBUG_SYSCALL_INFO
        if (ptr->_backing[0] != '[')
            kmm_free(ptr->_backing);
#endif
        tptr = ptr;
        ptr = ptr->next;
        kmm_free(tptr);
      }

    for(ptr = dtcb->xcp.pda; ptr;)
      {
        if(ptr == &g_vm_full_map)
            continue;
        gran_free(tux_mm_hnd, (void*)(ptr->pa_start),
                  VMA_SIZE(ptr) / HUGE_PAGE_SIZE * PAGE_SIZE);
        tptr = ptr;
        ptr = ptr->next;
        kmm_free(tptr);
      }

    tux_mm_del_pd1(dtcb->xcp.pd1);

    }

  /* Existence not checked, delete function will handle such case */
  timer_delete(dtcb->xcp.alarm_timer);
#endif
}
