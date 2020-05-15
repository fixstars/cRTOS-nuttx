/****************************************************************************
 * include/nuttx/virt/ivshmem.h
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

#ifndef __INCLUDE_NUTTX_VIRT_IVSHMEM_H
#define __INCLUDE_NUTTX_VIRT_IVSHMEM_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <stdbool.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define JH_IVSHMEM_VENDORID                       0x110A
#define JH_IVSHMEM_DEVICEID                       0x4106

#define JH_IVSHMEM_PROTOCOL_UNDEFINED             0x0000
#define JH_IVSHMEM_PROTOCOL_NET                   0x0001

#define JH_IVSHMEM_VND_LENGTH                     0x02
#define JH_IVSHMEM_VND_PCTL                       0x03
# define JH_IVSHMEM_VND_PCTL_1SHOT                (1 << 0)
#define JH_IVSHMEM_VND_ST_SIZE                    0x04
#define JH_IVSHMEM_VND_RW_SIZE                    0x08
#define JH_IVSHMEM_VND_IO_SIZE                    0x10
#define JH_IVSHMEM_VND_ADDR                       0x18

#define JH_IVSHMEM_VND_LENGTH_NO_ADDR             0x02

# define JH_IVSHMEM_INT_EN                       (1 << 0)

struct jh_ivshmem_regs_s
{
    uint32_t id;
    uint32_t max_peers;
    uint32_t int_control;
    uint32_t doorbell;
    uint32_t state;
};

#ifdef CONFIG_VIRT_JH_IVSHMEM
extern struct pci_dev_type_s pci_ivshmem;
#endif /* CONFIG_VIRT_JH_IVSHMEM */

#endif /* __INCLUDE_NUTTX_VIRT_IVSHMEM_H */
