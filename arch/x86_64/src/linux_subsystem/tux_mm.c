/****************************************************************************
 *  arch/x86_64/src/linux_subsystem/tux_mm.c
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
#include <nuttx/compiler.h>

#include <nuttx/arch.h>
#include <nuttx/sched.h>
#include <nuttx/kmalloc.h>
#include <nuttx/mm/gran.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "up_internal.h"
#include "arch/io.h"
#include "tux.h"
#include "sched/sched.h"

/****************************************************************************
 * Public Data
 ****************************************************************************/

GRAN_HANDLE tux_mm_hnd;

/****************************************************************************
 * Private Data
 ****************************************************************************/

struct graninfo_s granib;
struct graninfo_s grania;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

void print_mapping(void)
{
  struct tcb_s *tcb = this_task();
  struct vma_s *ptr;
  uint64_t p = 0;

  _alert("Current Map: \n");
  for (ptr = tcb->xcp.vma; ptr && p < 512; ptr = ptr->next, p++)
    {
      if(ptr == &g_vm_full_map) continue;
      _alert("0x%08llx - 0x%08llx : backed by 0x%08llx 0x%08llx %s\n",
             ptr->va_start, ptr->va_end, ptr->pa_start,
             ptr->pa_start + VMA_SIZE(ptr), ptr->_backing);
    }

  p = 0;
  _alert("Current PDAS: \n");
  for (ptr = tcb->xcp.pda; ptr && p < 64; ptr = ptr->next, p++)
    {
      if(ptr == &g_vm_full_map) continue;
      _alert("0x%08llx - 0x%08llx : 0x%08llx 0x%08llx\n",
             ptr->va_start, ptr->va_end, ptr->pa_start,
             ptr->pa_start + VMA_SIZE(ptr));
    }

  gran_info(tux_mm_hnd, &grania);
  _alert("GRANDULE  BEFORE AFTER\n");
  _alert("======== ======== ========\n");
  _alert("nfree    %8x %8x\n", granib.nfree, grania.nfree);
  _alert("mxfree   %8x %8x\n", granib.mxfree, grania.mxfree);
  granib = grania;
}

char *retrive_path(int fd, off_t offset)
{
#ifdef CONFIG_DEBUG_SYSCALL
  char proc_fs_path[64] = "/proc/self/fd/";
  char tmp[64];
  memset(tmp, 0, 64);

  uint64_t t = fd;
  int k = 0;
  while (t)
    {
      tmp[k++] = (t % 10) + '0';
      t /= 10;
    }
  k--;

  int l = 14;
  while (k >= 0)
    {
      proc_fs_path[l++] = tmp[k--];
    }
  proc_fs_path[l] = 0;

  char *file_path = kmm_zalloc(128);

  l = tux_delegate(89,
                   (uintptr_t)proc_fs_path,
                   (uintptr_t)file_path, 127, 0, 0, 0);
  if (l == -1)
    {
      return "[File: Resolve failed]";
    }

  if (l < 120)
    {
      t = offset;
      k = 0;
      tmp[0] = (t >> 28) & 0xf;
      tmp[1] = (t >> 24) & 0xf;
      tmp[2] = (t >> 20) & 0xf;
      tmp[3] = (t >> 16) & 0xf;
      tmp[4] = (t >> 12) & 0xf;
      tmp[5] = (t >> 8) & 0xf;
      tmp[6] = (t >> 4) & 0xf;
      tmp[7] = (t >> 0) & 0xf;
      for (k = 0; k < 8; k++)
        {
          if(tmp[k] <= 9)
              tmp[k] += '0';
          else
              tmp[k] += 'a' - 10;
        }

      file_path[l++] = ' ';
      file_path[l++] = ':';
      file_path[l++] = ' ';
      file_path[l++] = '0';
      file_path[l++] = 'x';

      for (k = 0; k < 8; k++)
        {
          file_path[l++] = tmp[k];
        }
    }
  file_path[l] = 0;

  return file_path;
#else
  return "[File]";
#endif
}

void revoke_vma(struct vma_s *vma)
{
  struct tcb_s *tcb = this_task();
  struct vma_s *ptr;
  struct vma_s **pptr;

  if (vma == NULL)
      return;

  for (pptr = &tcb->xcp.vma, ptr = tcb->xcp.vma;
       ptr;
       pptr = &(ptr->next), ptr = ptr->next)
    {
      if (ptr == vma)
        {
          *pptr = ptr->next;
          kmm_free(ptr);
        }
    }

  return;
}

void get_free_vma(struct vma_s *ret, uint64_t size)
{
  struct tcb_s *tcb = this_task();
  struct vma_s *ptr;
  struct vma_s *pptr;
  if(!ret)
      return;

  ret->next = NULL;

  if (tcb->xcp.vma == NULL)
    {
      tcb->xcp.vma = ret;
      ret->va_start = PAGE_SIZE;
    }
  else if (tcb->xcp.vma->next == NULL)
    {
      tcb->xcp.vma->next = ret;
      ret->va_start = tcb->xcp.vma->va_end;
    }
  else
    {
      for (pptr = tcb->xcp.vma, ptr = tcb->xcp.vma->next;
           ptr;
           pptr = ptr, ptr = ptr->next)
        {
          if (ptr->va_start - pptr->va_end >= size)
            {
              // Find a large enough hole
              ret->next = ptr;
              break;
            }
        }

      pptr->next = ret;
      ret->va_start = pptr->va_end;
    }

  ret->va_end = ret->va_start + size;
  return;
}

void make_vma_free(struct vma_s *ret)
{
  struct tcb_s *tcb = this_task();
  struct vma_s *ptr;
  struct vma_s **pptr;
  uint64_t prev_end = 0;
  int linked = 0;

  ret->next = NULL;

  for (prev_end = 0, pptr = &tcb->xcp.vma, ptr = tcb->xcp.vma;
       ptr;
       prev_end = ptr->va_end, pptr = &(ptr->next), ptr = ptr->next)
    {
      if (ptr == &g_vm_full_map)
          continue;
      if (ptr == ret)
        continue;

      if (ret->va_start <= ptr->va_start && ret->va_end >= ptr->va_end)
        {
          /* Whole covered, remove this mapping */

          *pptr = ret;
          ret->next = ptr->next;

          svcinfo("removing covered\n");

          gran_free(tux_mm_hnd,
                    (void *)(ptr->pa_start), ptr->va_end - ptr->va_start);
          kmm_free(ptr);

          ptr = ret;

          linked = 1;
        }
      else if (ret->va_start > ptr->va_start && ret->va_start < ptr->va_end)
        {
          if (ret->va_end < ptr->va_end)
            {
              /* Break to 2 */
              svcinfo("Break2\n");
              struct vma_s *new_mapping = kmm_malloc(sizeof(struct vma_s));
              memcpy(new_mapping, ptr, sizeof(struct vma_s));
              ptr->va_end = ret->va_start;
              new_mapping->va_start = ret->va_end;
              new_mapping->pa_start += ret->va_end - ptr->va_start;
              ptr->next = ret;
              ret->next = new_mapping;

              gran_free(tux_mm_hnd,
                        (void *)(ptr->pa_start + ptr->va_end - ptr->va_start),
                        VMA_SIZE(ret));
              return;
            }
          else
            {
              /* Shrink End */
              svcinfo("Shrink End\n");
              gran_free(tux_mm_hnd,
                        (void *)(ptr->pa_start + ret->va_start - ptr->va_start),
                        ptr->va_end - ret->va_start);
              ptr->va_end = ret->va_start;
              ret->next = ptr->next;
              ptr->next = ret;

              linked = 1;
            }
        }
      else if (ret->va_end > ptr->va_start && ret->va_end <= ptr->va_end)
        {
          if (ret->va_start <= ptr->va_start)
            {

              /* Shrink Head */
              svcinfo("Shrink Head\n");
              gran_free(tux_mm_hnd,
                        (void *)(ptr->pa_start), ret->va_end - ptr->va_start);
              ptr->pa_start = ptr->pa_start + ret->va_end - ptr->va_start;
              ptr->va_start = ret->va_end;
              *pptr = ret;
              ret->next = ptr;
              /* In strictly increasing order, we end here */
              return;
            }
        }
      else if ((ret->va_start >= prev_end) && ret->va_end <= ptr->va_start)
        {
          /* Hole */
          *pptr = ret;
          ret->next = ptr;
          return;
        }
    }

  if(!linked)
      *pptr = ret;

  return;
}

long map_pages(struct vma_s *vma){
  struct tcb_s *tcb = this_task();
  uint64_t i, j;
  uint64_t prev_end;
  struct vma_s *pda;
  struct vma_s *ptr;
  struct vma_s **pptr;
  uint64_t *tmp_pd;

  if (vma->va_start >= MEM_1GB)
      return -1; /* Mapping out of bound */
  if (vma->va_end - vma->va_start > MEM_1GB)
      return -1; /* Mapping out of bound */

  svcinfo("Creating mapping %llx %llx\n", vma->va_start, vma->va_end);

  /* Search the pdas for insertion,
   * map the unmapped pd duriong the creation of new pda
   */
  svcinfo("Mapping: %llx - %llx\n", vma->va_start, vma->va_end);
  i = vma->va_start;
  for (prev_end = 0, pptr = &tcb->xcp.pda, ptr = tcb->xcp.pda;
       ptr;
       prev_end = ptr->va_end, pptr = &(ptr->next), ptr = ptr->next)
    {
      if (i < ptr->va_start && i >= prev_end)
        {
          /* Fall between 2 pda */
          svcinfo("%llx, Between: %llx, and %llx - %llx\n",
                  i, prev_end, ptr->va_start, ptr->va_end);

          pda = kmm_malloc(sizeof(struct vma_s));
          if(!pda) return -1;
          pda->proto = vma->proto;
          pda->_backing = vma->_backing;

          /* pda's size should cover sufficient size of the Hole
           * Scan the hole size;
           */
          pda->va_start = i & HUGE_PAGE_MASK;
          for (pda->va_end = i;
               pda->va_end < ptr->va_start && pda->va_end < vma->va_end;
               pda->va_end += PAGE_SIZE)
              ;

          pda->va_end = (pda->va_end + HUGE_PAGE_SIZE - 1) & HUGE_PAGE_MASK;

          pda->pa_start =
            (uintptr_t)gran_alloc(tux_mm_hnd,
                                  PAGE_SIZE * VMA_SIZE(pda) / HUGE_PAGE_SIZE);
          if (!pda->pa_start)
            {
              svcinfo("TUX: mmap failed to allocate"
                      " 0x%llx bytes for new pda\n",
                      PAGE_SIZE * VMA_SIZE(pda) / HUGE_PAGE_SIZE);
              return -1;
            }

          svcinfo("New pda: %llx - %llx %llx\n",
                  pda->va_start, pda->va_end, pda->pa_start);

          /* Temporary map the memory for writing */
          tmp_pd = temp_map(pda->pa_start,
                            pda->pa_start +
                              PAGE_SIZE * VMA_SIZE(pda) / HUGE_PAGE_SIZE);

          /* Clear the page directories */
          memset(tmp_pd, 0, PAGE_SIZE * VMA_SIZE(pda) / HUGE_PAGE_SIZE);

          /* Fill in the new mappings to page directories
           * Scan the hole size;
           */
          for(j = i; j < ptr->va_start && j < vma->va_end; j += PAGE_SIZE)
            tmp_pd[((j - pda->va_start) >> 12) & 0x3ffff] =
              (vma->pa_start + j - vma->va_start) | vma->proto;

          up_invalid_TLB(i, j);

          /* Link it to the pdas list */
          *pptr = pda;
          pda->next = ptr;

          /* Temporary map the memory for writing */
          tmp_pd =
            temp_map((uintptr_t)tcb->xcp.pd1,
                     (uintptr_t)tcb->xcp.pd1 + PAGE_SIZE);

          /* Map it via page directories */
          for (j = pda->va_start; j < pda->va_end; j += HUGE_PAGE_SIZE)
            tmp_pd[(j >> 21) & 0x7ffffff] =
              (((j - pda->va_start) >> 9) + pda->pa_start) | pda->proto;

          i = ptr->va_start < vma->va_end ? ptr->va_start : vma->va_end;
        }

      if (i >= ptr->va_start && i < ptr->va_end)
        {
          svcinfo("%llx Overlapping: %llx - %llx\n",
                  i, ptr->va_start, ptr->va_end);

          /* In this pda */

          /* Temporary map the memory for writing */
          tmp_pd = temp_map(ptr->pa_start,
                            ptr->pa_start +
                              PAGE_SIZE * VMA_SIZE(ptr) / HUGE_PAGE_SIZE);

          /* Map it via page directories */
          for(; i < ptr->va_end && i < vma->va_end; i += PAGE_SIZE)
              tmp_pd[((i - ptr->va_start) >> 12) & 0x3ffff] =
                (vma->pa_start + i - vma->va_start) | vma->proto;
        }

      if(i == vma->va_end)
          break;
    }

  if (i < vma->va_end)
    {
      svcinfo("Insert at End\n");

      /* Fall after all pdas */
      /* Preserving the starting addr */

      pda = kmm_malloc(sizeof(struct vma_s));
      if (!pda)
          return -1;
      pda->proto = vma->proto;
      pda->_backing = vma->_backing;

      /* pda's size should cover sufficient size of the Hole */

      pda->va_start = i & HUGE_PAGE_MASK;
      pda->va_end = (vma->va_end + HUGE_PAGE_SIZE - 1) & HUGE_PAGE_MASK;

      pda->pa_start =
        (uintptr_t)gran_alloc(tux_mm_hnd,
                              PAGE_SIZE * VMA_SIZE(pda) / HUGE_PAGE_SIZE);
      if (!pda->pa_start)
        {
          svcinfo("TUX: mmap failed to allocate 0x%llx bytes for new pda\n",
                  PAGE_SIZE * VMA_SIZE(pda) / HUGE_PAGE_SIZE);
          return -1;
        }

      svcinfo("New pda: %llx - %llx %llx\n",
              pda->va_start, pda->va_end, pda->pa_start);

      /* Temporary map the memory for writing */
      tmp_pd = temp_map(pda->pa_start, pda->pa_start + VMA_SIZE(pda));

      /* Clear the page directories */
      memset(tmp_pd, 0, PAGE_SIZE * VMA_SIZE(pda) / HUGE_PAGE_SIZE);

      /* Fill in the new mappings to page directories
       * Scan the hole size
       */
      for(j = i; j < vma->va_end; j += PAGE_SIZE)
        tmp_pd[((j - pda->va_start) >> 12) & 0x3ffff] =
          (vma->pa_start + j - vma->va_start) | vma->proto;

      up_invalid_TLB(i, j);

      /* Link it to the pdas list */
      *pptr = pda;
      pda->next = NULL;

      tmp_pd =
        temp_map((uintptr_t)tcb->xcp.pd1, (uintptr_t)tcb->xcp.pd1 + PAGE_SIZE);

      /* Map it via page directories */
      for(j = pda->va_start; j < pda->va_end; j += HUGE_PAGE_SIZE)
        tmp_pd[(j >> 21) & 0x7ffffff] =
          (((j - pda->va_start) >> 9) + pda->pa_start) | pda->proto;
    }

  svcinfo("TUX: mmap maped 0x%llx bytes at 0x%llx, backed by 0x%llx\n",
          vma->va_end - vma->va_start, vma->va_start, vma->pa_start);

  return OK;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

void tux_mm_init(void)
{
  /* 2^12 is 4KB, the PAGE_SIZE */

  tux_mm_hnd = gran_initialize((void *)CONFIG_TUX_USER_ADDR_START,
                               CONFIG_TUX_USER_ADDR_SIZE, 12, 12);
}

uint64_t *tux_mm_new_pd1(void)
{
  uintptr_t pd1 = (uintptr_t)gran_alloc(tux_mm_hnd, PAGE_SIZE);
  uint64_t *vpd1 = temp_map(pd1, pd1 + PAGE_SIZE);

  memset(vpd1, 0, PAGE_SIZE);

  return (uint64_t *)pd1;
}

void tux_mm_del_pd1(uint64_t *pd1)
{
  gran_free(tux_mm_hnd, pd1, PAGE_SIZE);
  return;
}

void *tux_mmap(unsigned long nbr,
               void *addr, long length, int prot,
               int flags, int fd, off_t offset)
{
  struct vma_s *vma;

  /* Round to page boundary */
  /* adjust length to accomdate change in size */
  length += (uintptr_t)addr - ((uintptr_t)addr & PAGE_MASK);
  addr = (void *)((uintptr_t)addr & PAGE_MASK);

  /* Calculate page to be mapped */
  uint64_t num_of_pages = (uint64_t)(length + PAGE_SIZE - 1) / PAGE_SIZE;

  svcinfo("TUX: mmap with flags: %x\n", flags);

  /* Nope, we don't reserve memory for applications */

  if (((flags & TUX_MAP_NORESERVE)) && (prot == 0))
      return (void *)-1;

  if (flags & ~(TUX_MAP_FIXED |
               TUX_MAP_SHARED |
               TUX_MAP_PRIVATE |
               TUX_MAP_ANONYMOUS |
               TUX_MAP_DENYWRITE |
               TUX_MAP_STACK))
      PANIC();

  svcinfo("TUX: mmap get vma\n");

  vma = kmm_malloc(sizeof(struct vma_s));
  if (!vma)
      return (void *)-1;

  // TODO: process proto
  vma->proto = 0x3;
  vma->_backing = "[Memory]";

  svcinfo("TUX: mmap get mem\n");
  /* Create backing memory
   * The allocated physical memory is non-accessible
   * from this process, must be mapped
   */
  vma->pa_start = (uintptr_t)gran_alloc(tux_mm_hnd, num_of_pages * PAGE_SIZE);
  if (!vma->pa_start)
    {
      svcinfo("TUX: mmap failed to allocate 0x%llx bytes\n",
              num_of_pages * PAGE_SIZE);
      kmm_free(vma);
      return (void *)-1;
    }

  svcinfo("TUX: mmap allocated 0x%llx bytes at 0x%llx\n",
          num_of_pages * PAGE_SIZE, vma->pa_start);

  if (!(flags & TUX_MAP_FIXED)) // Fixed mapping?
    {
      svcinfo("TUX: mmap trying to allocate 0x%llx bytes\n", length);

      // Free page_table entries
      get_free_vma(vma, num_of_pages * PAGE_SIZE);
      addr = (void *)vma->va_start;
    }
  else
    {
      svcinfo("TUX: mmap try to fix position at %llx\n", addr);

      /* Free page_table entries */
      vma->va_start = (uintptr_t)addr;
      vma->va_end = (uintptr_t)addr + num_of_pages * PAGE_SIZE;
      make_vma_free(vma);
    }

  if (map_pages(vma))
    {
      gran_free(tux_mm_hnd, (void *)(vma->pa_start), VMA_SIZE(vma));
      revoke_vma(vma);
      return (void *)-1;
    }

  /* Zero fill the newly mapped page via virtual memory */
  memset((void *)vma->va_start, 0, VMA_SIZE(vma));

  /* Trigger the shadow process to gain the same mapping */
  /* TODO: Pass proto */
  if (tux_delegate(9,
                   (((uint64_t)vma->pa_start) << 32) | (uint64_t)vma->va_start,
                   vma->va_end - vma->va_start,
                   0, TUX_MAP_ANONYMOUS, 0, 0) == -1)
    {
      return (void *)-1;
    }

  if (!(flags & TUX_MAP_ANONYMOUS))
    {
      /* get debug friendly name */
      vma->_backing = retrive_path(fd, offset);

      /* Tell shadow process to fill the file data */
      if (tux_delegate(nbr,
                       (uint64_t)addr, length, prot, flags, fd, offset) == -1)
        {
          revoke_vma(vma);
          return (void *)-1;
        }
    }

  return addr;
}

long tux_munmap(unsigned long nbr, void *addr, size_t length)
{
  struct vma_s *vma;

  /* Calculate page to be mapped */
  uint64_t num_of_pages = (uint64_t)(length + PAGE_SIZE - 1) / PAGE_SIZE;

  svcinfo("TUX: munmap %llx - %llx\n", addr, addr + num_of_pages * PAGE_SIZE);

  vma = kmm_malloc(sizeof(struct vma_s));
  if (!vma)
      return -1;

  vma->proto = 0x0;
  vma->_backing = "[None]";

  // Free page_table entries
  vma->va_start = (uintptr_t)addr;
  vma->va_end = (uintptr_t)addr + num_of_pages * PAGE_SIZE;
  vma->pa_start = 0xffffffff;

  make_vma_free(vma);
  map_pages(vma);

  /*print_mapping();*/

  return 0;
}

void *tux_mremap(unsigned long nbr,
                 void *old_address, size_t old_size,
                 size_t new_size, int flags, void *new_address)
{
  if (flags & TUX_MREMAP_FIXED)
      return (void *)-1;

  if (!(flags & TUX_MREMAP_MAYMOVE))
      return (void *)-1;

  // XXX: PROT and flags should be copied
  void *new = tux_mmap(nbr, NULL, new_size,
                       TUX_PROT_READ | TUX_PROT_WRITE,
                       TUX_MAP_SHARED | TUX_MAP_ANONYMOUS, 0, 0);

  if (new == (void *)-1)
      return (void *)-1;

  memcpy(new, old_address, old_size > new_size ? new_size : old_size);

  svcinfo("TUX: mremap %llx - %llx -> %llx - %llx\n",
          old_address, old_address + old_size,
          new, new + new_size);

  tux_munmap(nbr, old_address, old_size);

  return new;
}
