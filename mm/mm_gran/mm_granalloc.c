/****************************************************************************
 * mm/mm_gran/mm_granalloc.c
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

#include <assert.h>

#include <nuttx/mm/gran.h>

#include "mm_gran/mm_gran.h"

#ifdef CONFIG_GRAN

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: gran_alloc
 *
 * Description:
 *   Allocate memory from the granule heap.
 *
 * Input Parameters:
 *   handle - The handle previously returned by gran_initialize
 *   size   - The size of the memory region to allocate.
 *
 * Returned Value:
 *   On success, a non-NULL pointer to the allocated memory is returned;
 *   NULL is returned on failure.
 *
 ****************************************************************************/

FAR void *gran_alloc(GRAN_HANDLE handle, size_t size)
{
  FAR struct gran_s *priv = (FAR struct gran_s *)handle;
  unsigned int ngranules;
  size_t       tmpmask;
  uint32_t     curr;
  uintptr_t    alloc;
  int          granidx, sgranidx;
  int          gatidx;
  int64_t      started_flag;
  int64_t      rgranules;
  uintptr_t    ret = 0;
  uint32_t     staging;

  DEBUGASSERT(priv != NULL);

  /* How many contiguous granules we we need to find? */
  tmpmask   = (1 << priv->log2gran) - 1;
  ngranules = (size + tmpmask) >> priv->log2gran;

  /* Get exclusive access to the GAT */
  ret = gran_enter_critical(priv);
  if (ret < 0)
    {
      return NULL;
    }

  staging = 0;
  started_flag = 0;

  for (granidx = 0; granidx < priv->ngranules; granidx++)
    {
      gatidx = granidx >> 5;
      curr = priv->gat[gatidx];

      if ((granidx % 32) == 0)
          staging |= curr; // Load the new part to MSB

      if (staging & 0x1)
        {
          // Marked, not free
          if (started_flag)
            {
              started_flag = 0;
            }
        } else {
          // Not marked, free
          if (!started_flag)
            {
              // Start here
              sgranidx = granidx;
              started_flag = 1;
              rgranules = ngranules - 1;
            }
          else
            {
              rgranules--;
            }
        }

      if(rgranules == 0 && started_flag)
        {
          // Fit, return this
          alloc = priv->heapstart + sgranidx * (1 << priv->log2gran);

          // We found a space is large enough
          gran_mark_allocated(priv, alloc, ngranules);

          gran_leave_critical(priv);

          return (void*)alloc;
        }

      // Next bit
      staging >>= 1;
    }

  gran_leave_critical(priv);
  // Exhausted, no free pages
  return NULL;
}

#endif /* CONFIG_GRAN */
