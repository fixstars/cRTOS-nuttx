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

#include <nuttx/fs/fs.h>

#include <sys/select.h>

#include <nuttx/arch.h>
#include <nuttx/sched.h>
#include <nuttx/board.h>
#include <nuttx/irq.h>
#include <arch/io.h>
#include <syscall.h>
#include <fcntl.h>
#include <semaphore.h>
#include <errno.h>
#include <poll.h>
#include <string.h>

#include "up_internal.h"
#include "sched/sched.h"

#include "tux.h"

/****************************************************************************
 * Private Functions
 ****************************************************************************/

struct tux_pollfd* make_pollfds(struct tux_fd_set *r,
                                struct tux_fd_set *w,
                                struct tux_fd_set *e,
                                int* rcount)
{
  int i, j;

  struct tux_fd_set clear_set;
  memset(&clear_set, 0, sizeof(clear_set));

  if (r == NULL)
      r = &clear_set;
  if (w == NULL)
      w = &clear_set;
  if (e == NULL)
      e = &clear_set;

  /* Count number FDs */
  int count = 0;

  /* Those set fits */
  for(i = 0; i < (CONFIG_TUX_FD_RESERVE + FD_SETSIZE) / TUX_NFDBITS; i++)
    {
      count += __builtin_popcount((r->__fds_bits[i] |
                                   w->__fds_bits[i] |
                                   e->__fds_bits[i]));
    }

  /* Remaining bits in the last set
   * Mask and popcount, make sure to preserve the size after masking
   */
  count +=
    __builtin_popcount(
      (typeof(r->__fds_bits[i]))
        ((r->__fds_bits[i] |
          w->__fds_bits[i] |
          e->__fds_bits[i]) &
         ((1ULL << ((CONFIG_TUX_FD_RESERVE + FD_SETSIZE) % TUX_NFDBITS)) - 1)));

  struct tux_pollfd* tux_fds = NULL;

  int k = 0;
  if (count)
    {
      tux_fds =
        (struct tux_pollfd*)kmm_malloc(sizeof(struct tux_pollfd) * (count));
      if (!tux_fds)
        {
          _err("Failed to allocate tux_fds!\n");
          return NULL;
        }

      memset(tux_fds, 0, sizeof(struct tux_pollfd) * (count));

      for (i = 0; i < (CONFIG_TUX_FD_RESERVE + FD_SETSIZE) / TUX_NFDBITS; i++)
        {
          for (j = 0; j < TUX_NFDBITS; j++)
            {
              if (((r->__fds_bits[i] |
                    w->__fds_bits[i] |
                    e->__fds_bits[i]) >> j) & 0x1)
                {
                  tux_fds[k].fd = i * TUX_NFDBITS + j;
                  if(r->__fds_bits[i] >> j)
                      tux_fds[k].events |= TUX_POLLIN;
                  if(w->__fds_bits[i] >> j)
                      tux_fds[k].events |= TUX_POLLOUT;
                  if(e->__fds_bits[i] >> j)
                      tux_fds[k].events |= TUX_POLLERR;
                  k++;
                }
            }
        }

    for (j = 0; j < (CONFIG_TUX_FD_RESERVE + FD_SETSIZE) % TUX_NFDBITS; j++)
      {
        if(((r->__fds_bits[i] |
             w->__fds_bits[i] |
             e->__fds_bits[i]) >> j) & 0x1)
          {
              tux_fds[k].fd = i * TUX_NFDBITS + j;
              if(r->__fds_bits[i] >> j)
                  tux_fds[k].events |= TUX_POLLIN;
              if(w->__fds_bits[i] >> j)
                  tux_fds[k].events |= TUX_POLLOUT;
              if(e->__fds_bits[i] >> j)
                  tux_fds[k].events |= TUX_POLLERR;
              k++;
          }
      }
  }

  DEBUGASSERT(k == count);

  *rcount = count;

  return tux_fds;
}

int recover_fdset(struct tux_fd_set* r,
                  struct tux_fd_set* w,
                  struct tux_fd_set* e,
                  struct tux_pollfd* in, int count)
{
  int i;

  int ret = 0;

  if (!in)
      return -EINVAL;

  struct tux_fd_set clear_set;
  memset(&clear_set, 0, sizeof(clear_set));

  if (r == NULL)
      r = &clear_set;
  if (w == NULL)
      w = &clear_set;
  if (e == NULL)
      e = &clear_set;

  for (i = 0; i < count; i++)
    {
      if (in[i].revents & TUX_POLLIN)
        {
          r->__fds_bits[(in[i].fd) / TUX_NFDBITS] |=
            1 << (in[i].fd) % TUX_NFDBITS;
          ret++;
        }
      else
        {
          r->__fds_bits[(in[i].fd) / TUX_NFDBITS] &=
            ~(1 << (in[i].fd) % TUX_NFDBITS);
        }

      if(in[i].revents & TUX_POLLOUT)
        {
          w->__fds_bits[(in[i].fd) / TUX_NFDBITS] |=
            1 << (in[i].fd) % TUX_NFDBITS;
          ret++;
        }
      else
        {
          w->__fds_bits[(in[i].fd) / TUX_NFDBITS] &=
            ~(1 << (in[i].fd) % TUX_NFDBITS);
        }

      if (in[i].revents & TUX_POLLERR)
        {
          e->__fds_bits[(in[i].fd) / TUX_NFDBITS] |=
            1 << (in[i].fd) % TUX_NFDBITS;
          ret++;
        }
      else
        {
          e->__fds_bits[(in[i].fd) / TUX_NFDBITS] &=
            ~(1 << (in[i].fd) % TUX_NFDBITS);
        }
    }

  return ret;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

long tux_select(unsigned long nbr,
                int fd,
                struct tux_fd_set *r,
                struct tux_fd_set *w,
                struct tux_fd_set *e,
                struct timeval *timeout)
{
  int ret;

  svcinfo("Select syscall %d, fd: %d\n", nbr, fd);

  int count;
  struct tux_pollfd* pfd = make_pollfds(r, w, e, &count);

  int msec;
  if (timeout)
    {
      msec = timeout->tv_sec * 1000 + timeout->tv_usec / 1000;
    }
  else
    {
      msec = -1;
    }

  ret = tux_poll(7, pfd, count, msec);

  svcinfo("poll ret: %d\n", ret);

  ret = recover_fdset(r, w, e, pfd, count);

  return ret;
}
