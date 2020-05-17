/****************************************************************************
 * arch/x86/src/intel64/up_map_region.c
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

#include <debug.h>
#include <nuttx/irq.h>

#include "up_arch.h"
#include "up_internal.h"

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: up_map_region_to
 *
 * Description:
 *   Map a memory region by MMU
 *
 ****************************************************************************/

int up_map_region_to(void *to_base, void *from_base, int size, int flags)
{
  uint64_t num_of_pages;
  uint64_t entry;
  int i;

  /* Round to page boundary */

  uint64_t tob = (uint64_t)to_base & PAGE_MASK;
  uint64_t fromb = (uint64_t)from_base & PAGE_MASK;

  /* Increase size if the base address is rounded off */

  size += (uint64_t)to_base - tob;
  num_of_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;

  if (tob > 0xffffffff)
    {
      return -1;  /* Only < 4GB can be mapped */
    }

  uint64_t tocurr = tob;
  uint64_t fromcurr = fromb;
  for (i = 0; i < num_of_pages; i++)
    {
      entry = (tocurr >> 12) & 0x7ffffff;

      pt[entry] = fromcurr | flags;
      tocurr += PAGE_SIZE;
      fromcurr += PAGE_SIZE;
    }

  return 0;
}

/****************************************************************************
 * Name: up_map_region
 *
 * Description:
 *   Map a memory region as 1:1 by MMU
 *
 ****************************************************************************/

int up_map_region(void *base, int size, int flags)
{
  return up_map_region_to(base, base, size, flags);
}
