/****************************************************************************
 *  arch/x86_64/src/linux_subsystem/tux_sem.c
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

#include <nuttx/arch.h>
#include <string.h>

#include "tux.h"
#include "up_internal.h"
#include "sched/sched.h"
#include <nuttx/semaphore.h>

/****************************************************************************
 * Pre-processor definitions
 ****************************************************************************/

#define SEM_HT_SIZE 256

/****************************************************************************
 * Private Types
 ****************************************************************************/

struct sem_q{
  struct semid_ds info;
  sem_t *_sems;
};

/****************************************************************************
 * Private Data
 ****************************************************************************/

struct sem_q sem_hash_table[SEM_HT_SIZE];

/****************************************************************************
 * Public Functions
 ****************************************************************************/

long tux_semget(unsigned long nbr, uint32_t key, int nsems, uint32_t flags)
{
  uint32_t s_head = (uint64_t)key % SEM_HT_SIZE;
  uint32_t hv = s_head;
  int i;
  int exist = 1;
  irqstate_t irqflags;

  svcinfo("SEM %d FLAGS: %lx\n", key, flags);

  irqflags = enter_critical_section();

  while ((sem_hash_table[hv].info.sem_perm.__key != key))
    {
      hv++;
      hv %= SEM_HT_SIZE;
      if(hv == s_head)
        {
          exist = 0;
          break;
        }
    }

  if (exist && (flags & TUX_IPC_EXCL) && (flags & TUX_IPC_CREAT))
      return -EEXIST;

  if (!exist)
      while((sem_hash_table[hv].info.sem_perm.__key != 0))
        {
          hv++;
          hv %= SEM_HT_SIZE;
          if(hv == s_head)
              return -ENOMEM; // Out of free sem
        }

  svcinfo("SEM hv: %d\n", hv);

  if (sem_hash_table[hv].info.sem_perm.__key == 0)
    {
      sem_hash_table[hv]._sems = kmm_zalloc(sizeof(sem_t) * nsems);
      if (sem_hash_table[hv]._sems == 0) return -ENOMEM;
      for(i = 0; i < nsems; i++)
        {
          nxsem_init(&sem_hash_table[hv]._sems[i], 0, 0);
          nxsem_set_protocol(&sem_hash_table[hv]._sems[i], SEM_PRIO_NONE);
        }

      memset(&sem_hash_table[hv].info, 0, sizeof(struct semid_ds));

      sem_hash_table[hv].info.sem_perm.__key = key;
      sem_hash_table[hv].info.sem_perm.mode  = 0777;

      sem_hash_table[hv].info.sem_nsems = nsems;
    }

  leave_critical_section(irqflags);

  svcinfo("new sem: %d\n", hv);

  return hv;
}

long tux_semctl(unsigned long nbr,
                int hv, int semnum, int cmd, union semun arg)
{
    int ret;
    int i;
    int sval;

    if (!(sem_hash_table[hv].info.sem_perm.__key))
        return -EINVAL;

    switch (cmd)
      {
        case TUX_IPC_STAT:
            memcpy(arg.buf, &sem_hash_table[hv].info, sizeof(struct semid_ds));
            ret = 0;
            break;
        case TUX_IPC_SET:
            // Don;t brother doing anything
            ret = 0;
            break;

        case TUX_SEM_GETALL:
            for (i = 0; i < sem_hash_table[hv].info.sem_nsems; i++)
              {
                nxsem_get_value(&sem_hash_table[hv]._sems[i], &sval);
                arg.array[i] = sval;
              }
            ret = 0;
            break;

        case TUX_SEM_GETVAL:
            nxsem_get_value(&sem_hash_table[hv]._sems[semnum], &sval);
            arg.array[0] = sval;
            ret = 0;
            break;

        case TUX_SEM_SETALL:
            for (i = 0; i < sem_hash_table[hv].info.sem_nsems; i++)
              {
                svcinfo("sem buck set values for %d %llx -> %d\n",
                        hv, &sem_hash_table[hv]._sems[i], arg.array[i]);
                nxsem_reset(&sem_hash_table[hv]._sems[i], arg.array[i]);
              }
            ret = 0;
            break;

        case TUX_SEM_SETVAL:
            svcinfo("sem set values for %d, %llx -> %d\n",
                    hv, &sem_hash_table[hv]._sems[semnum], arg.val);
            nxsem_reset(&sem_hash_table[hv]._sems[semnum], arg.val);
            ret = 0;
            break;

        default:
            svcinfo("Unknown command\n");
            return -EINVAL;
      }

    return ret;
}

long tux_semtimedop(unsigned long nbr,
                    int hv, struct sembuf *tsops,
                    unsigned int nops, const struct timespec* timeout)
{
  int i, j;
  int ret = 0;
  int svalue;
  struct timespec abs_timeout;

  irqstate_t irqflags;

  if (!(sem_hash_table[hv].info.sem_perm.__key))
    {
      svcinfo("Invalid hv!\n");
      return -EINVAL;
    }

  clock_gettime(CLOCK_REALTIME, &abs_timeout);
  abs_timeout.tv_sec += timeout->tv_sec;
  abs_timeout.tv_nsec += timeout->tv_nsec;

  if (abs_timeout.tv_nsec > NSEC_PER_SEC)
    {
      abs_timeout.tv_nsec -= NSEC_PER_SEC;
      abs_timeout.tv_sec += 1;
    }

  irqflags = enter_critical_section();

  for(i = 0; i < nops; i++)
    {
      if(tsops[i].sem_flg & TUX_SEM_UNDO)
        {
          svcinfo("sem undo!\n");
          ret = -EINVAL;
          break;
        }

      if(tsops[i].sem_op == 0)
        {
          nxsem_get_value(&sem_hash_table[hv]._sems[tsops[i].sem_num],
                          &svalue);
          ret = 0;
          if(svalue < 0)
            {
              ret =
                nxsem_timedwait(&sem_hash_table[hv]._sems[tsops[i].sem_num],
                                &abs_timeout);
              nxsem_post(&sem_hash_table[hv]._sems[tsops[i].sem_num]);
            }
        }
      else if(tsops[i].sem_op > 0)
        {
          svcinfo("sem post %llx, %d\n",
                  &sem_hash_table[hv]._sems[tsops[i].sem_num],
                  tsops[i].sem_op);
          for (j = 0; j < tsops[i].sem_op; j++)
            {
              ret = nxsem_post(&sem_hash_table[hv]._sems[tsops[i].sem_num]);
              if (ret)
                {
                  if(ret == -ETIMEDOUT)
                      ret = -EAGAIN;
                  break;
                }
            }
        }
      else
        {
          svcinfo ("sem wait %llx, %d\n",
                   &sem_hash_table[hv]._sems[tsops[i].sem_num],
                   tsops[i].sem_op);
          for (j = 0; j > tsops[i].sem_op; j--)
            {
              ret =
                nxsem_timedwait(&sem_hash_table[hv]._sems[tsops[i].sem_num],
                                &abs_timeout);
              if (ret)
                {
                  if(ret == -ETIMEDOUT) ret = -EAGAIN;
                  svcinfo("err wait %d\n", ret);
                  break;
                }
            }
          break;
        }
      if(ret)
          break;
    }

  leave_critical_section(irqflags);
  return ret;
}


long tux_semop(unsigned long nbr,
               int hv, struct sembuf *tsops, unsigned int nops)
{
  int i, j;
  int ret;
  int svalue;
  irqstate_t irqflags;

  if (!(sem_hash_table[hv].info.sem_perm.__key))
      return -EINVAL;

  irqflags = enter_critical_section();

  for (i = 0; i < nops; i++)
    {
      if (tsops[i].sem_flg & TUX_SEM_UNDO)
        {
          ret = -EINVAL;
          break;
        }

      if (tsops[i].sem_op == 0)
        {
          nxsem_get_value(&sem_hash_table[hv]._sems[tsops[i].sem_num],
                          &svalue);
          ret = 0;
          if (svalue < 0)
            {
              ret = nxsem_wait(&sem_hash_table[hv]._sems[tsops[i].sem_num]);
              nxsem_post(&sem_hash_table[hv]._sems[tsops[i].sem_num]);
            }

        }
      else if (tsops[i].sem_op > 0)
        {
          for (j = 0; j < tsops[i].sem_op; j++)
            {
              svcinfo("sem post %llx, %d\n", &sem_hash_table[hv]._sems[tsops[i].sem_num], tsops[i].sem_op);
              ret = nxsem_post(&sem_hash_table[hv]._sems[tsops[i].sem_num]);
              if (ret)
                {
                  if (ret == -ETIMEDOUT)
                      ret = -EAGAIN;
                  break;
                }
            }
        }
      else
        {
          for (j = 0; j > tsops[i].sem_op; j--)
            {
              svcinfo("sem wait %llx, %d\n",
                      &sem_hash_table[hv]._sems[tsops[i].sem_num],
                      tsops[i].sem_op);
              ret = nxsem_wait(&sem_hash_table[hv]._sems[tsops[i].sem_num]);
              if (ret)
                {
                  if (ret == -ETIMEDOUT)
                      ret = -EAGAIN;
                  svcinfo("err wait! %d\n", ret);
                  break;
                }
            }
          break;
        }
      if(ret) break;
  }

  leave_critical_section(irqflags);

  return ret;
}
