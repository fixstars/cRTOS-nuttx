/*
 * boards/x86_64/intel64/qemu-intel64/src/qemu_pci_readwrite.h
 *
 * Copyright (c) ChungFan Yang @ Fixstars Corporation, 2020
 *                               <chungfan.yang@fixstars.com>
 *
 * The PCI Definitions and part of the access routines are taken from
 * Jailhouse inmate library
 *
 * Copyright (c) Siemens AG, 2014
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *
 * This work is licensed under the terms of the BSD license.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __INCLUDE_NUTTX_PCI_PCI_READWRITE_H
#define __INCLUDE_NUTTX_PCI_PCI_READWRITE_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <nuttx/config.h>

#include <assert.h>

#include <nuttx/pci/pci.h>

#include <nuttx/board.h>
#include <arch/board/board.h>

#include "up_arch.h"
#include "up_internal.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define PCI_REG_ADDR_PORT       0xcf8
#define PCI_REG_DATA_PORT       0xcfc

#define PCI_CONE                (1 << 31)

/****************************************************************************
 * Name: __qemu_pci_cfg_write
 *
 * Description:
 *  Write 8, 16, 32 bits data to PCI configuration space of device
 *  specified by dev
 *
 * Input Parameters:
 *   bfd    - Device private data
 *   val    - Value to be written
 *
 * Returned Value:
 *   0: success, <0: A negated errno
 *
 ****************************************************************************/

static inline int __qemu_pci_cfg_write(uint16_t bfd, uintptr_t addr,
                                       uint32_t val,
                                       unsigned int size)
{
  outl(PCI_CONE | ((uint32_t)bfd << 8) | (addr & 0xfc), PCI_REG_ADDR_PORT);

  DEBUGASSERT(size == 1 || size == 2 || size == 4);

  switch (size)
    {
      case 1:
        outb((uint8_t)(val), PCI_REG_DATA_PORT + (addr & 0x3));
        break;
      case 2:
        outw((uint16_t)(val), PCI_REG_DATA_PORT + (addr & 0x3));
        break;
      case 4:
        outl((uint32_t)(val), PCI_REG_DATA_PORT);
        break;
      default:
        return -EINVAL;
    }
  return OK;
}

/****************************************************************************
 * Name: __qemu_pci_cfg_write64
 *
 * Description:
 *  Write 64 bits data to PCI configuration space of device
 *  specified by dev
 *
 * Input Parameters:
 *   bfd    - Device private data
 *   val    - Value to be written
 *
 * Returned Value:
 *   0: success, <0: A negated errno
 *
 ****************************************************************************/

static inline int __qemu_pci_cfg_write64(uint16_t bfd, uintptr_t addr,
                                         uint64_t val)
{
  int ret;

  ret = __qemu_pci_cfg_write(bfd, addr + 4, val >> 32, 4);
  ret |= __qemu_pci_cfg_write(bfd, addr, (uint32_t)val, 4);

  return ret;
}

/****************************************************************************
 * Name: __qemu_pci_cfg_read
 *
 * Description:
 *  Read 8, 16, 32 bits data from PCI configuration space of device
 *  specified by dev
 *
 * Input Parameters:
 *   dev    - Device private data
 *   size   - The requested number of bytes to be read
 *
 * Returned Value:
 *    Value in configuration space
 *
 ****************************************************************************/

static inline uint32_t __qemu_pci_cfg_read(uint16_t bfd, uintptr_t addr,
                                           unsigned int size)
{
  DEBUGASSERT(size == 1 || size == 2 || size == 4);

  outl(PCI_CONE | ((uint32_t)bfd << 8) | (addr & 0xfc), PCI_REG_ADDR_PORT);

  switch (size)
    {
      case 1:
        return inb(PCI_REG_DATA_PORT + (addr & 0x3));
      case 2:
        return inw(PCI_REG_DATA_PORT + (addr & 0x3));
      case 4:
        return inl(PCI_REG_DATA_PORT);
    }

  return 0;
}

/****************************************************************************
 * Name: __qemu_pci_cfg_read
 *
 * Description:
 *  Read 64 bits data from PCI configuration space of device
 *  specified by dev
 *
 * Input Parameters:
 *   dev    - Device private data
 *
 * Returned Value:
 *    Value in configuration space
 *
 ****************************************************************************/

static inline uint64_t __qemu_pci_cfg_read64(uint16_t bfd,
                                             uintptr_t addr)
{
  int ret;

  ret = __qemu_pci_cfg_read(bfd, addr + 4, 4);
  ret |= __qemu_pci_cfg_read(bfd, addr, 4);

  return ret;
}

#endif /* __INCLUDE_NUTTX_PCI_PCI_READWRITE_H */
