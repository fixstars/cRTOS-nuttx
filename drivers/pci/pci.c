/****************************************************************************
 * nuttx/drivers/pci/pci.c
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
#include <errno.h>
#include <debug.h>

#include <nuttx/pci/pci.h>
#include <nuttx/virt/qemu_pci.h>
#include <nuttx/virt/ivshmem.h>
#include <nuttx/net/ivshmem_net.h>
#include <nuttx/serial/uart_mcs99xx.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Public Data
 ****************************************************************************/

struct pci_dev_type_s *pci_device_types[] =
{
#ifdef CONFIG_VIRT_QEMU_PCI_TEST
  &pci_type_qemu_pci_test,
#endif /* CONFIG_VIRT_QEMU_PCI_TEST */
#ifdef CONFIG_MCS99XX_UART
  &pci_mcs99xx,
#endif /* CONFIG_MCS99xx_UART */
#ifdef CONFIG_NET_IVSHMNET
  &pci_ivshmnet,
#endif /* CONFIG_NET_IVSHMNET */
#ifdef CONFIG_VIRT_SHADOW
  &pci_shadow,
#endif /* CONFIG_VIRT_SHADOW */
#ifdef CONFIG_VIRT_JH_IVSHMEM
  &pci_ivshmem,
#endif /* CONFIG_VIRT_JH_IVSHMEM */
  NULL,
};

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: pci_enumerate
 *
 * Description:
 *  Scan the PCI bus and enumerate the devices.
 *  Initialize any recognized devices, given in types.
 *
 * Input Parameters:
 *   bus    - PCI bus structure
 *   type   - List of pointers to devices types recognized, NULL terminated
 *
 * Returned Value:
 *   0: success, <0: A negated errno
 *
 ****************************************************************************/

int pci_enumerate(FAR struct pci_bus_s *bus,
                  FAR struct pci_dev_type_s **types)
{
  unsigned int bdf;
  uint16_t vid;
  uint16_t id;
  uint16_t rev;
  struct pci_dev_s tmp_dev;
  struct pci_dev_type_s tmp_type =
    {
      .name = "Unknown",
      .vendor = PCI_ID_ANY,
      .device = PCI_ID_ANY,
      .class_rev = PCI_ID_ANY,
      .probe = NULL,
    };

  if (!bus)
      return -EINVAL;
  if (!types)
      return -EINVAL;

  DEBUGASSERT(bus->ops->pci_cfg_read);

  for (bdf = 0; bdf < CONFIG_PCI_MAX_BDF; bdf++)
    {
      tmp_dev.bus = bus;
      tmp_dev.type = &tmp_type;
      tmp_dev.bdf = bdf;

      vid = bus->ops->pci_cfg_read(&tmp_dev, PCI_CFG_VENDOR_ID, 2);
      id = bus->ops->pci_cfg_read(&tmp_dev, PCI_CFG_DEVICE_ID, 2);
      rev = bus->ops->pci_cfg_read(&tmp_dev, PCI_CFG_REVERSION, 2);

      if (vid == PCI_ID_ANY)
        continue;

      pciinfo("[%02x:%02x.%x] Found %04x:%04x, class/reversion %08x\n",
              bdf >> 8, (bdf >> 3) & 0x1f, bdf & 0x3,
              vid, id, rev);

      for (int i = 0; types[i] != NULL; i++)
        {
          if (types[i]->vendor == PCI_ID_ANY ||
              types[i]->vendor == vid)
            {
              if (types[i]->device == PCI_ID_ANY ||
                  types[i]->device == id)
                {
                  if (types[i]->class_rev == PCI_ID_ANY ||
                      types[i]->class_rev == rev)
                    {
                      if (types[i]->probe)
                        {
                          pciinfo("[%02x:%02x.%x] %s\n",
                                  bdf >> 8, (bdf >> 3) & 0x1f, bdf & 0x3,
                                  types[i]->name);
                          types[i]->probe(bus, types[i], bdf);
                        }
                      else
                        {
                          pcierr("[%02x:%02x.%x] Error: Invalid \
                                  device probe function\n",
                                  bdf >> 8, (bdf >> 3) & 0x1f, bdf & 0x3);
                        }
                      break;
                    }
                }
            }
        }
    }

  return OK;
}

/****************************************************************************
 * Name: pci_initialize
 *
 * Description:
 *  Initialize the PCI bus and enumerate the devices with give devices
 *  type array
 *
 * Input Parameters:
 *   bus    - An PCI bus
 *   types  - A array of PCI device types
 *   num    - Number of device types
 *
 * Returned Value:
 *   OK if the driver was successfully register; A negated errno value is
 *   returned on any failure.
 *
 ****************************************************************************/

int pci_initialize(FAR struct pci_bus_s *bus)
{
  return pci_enumerate(bus, pci_device_types);
}

/****************************************************************************
 * Name: pci_enable_device
 *
 * Description:
 *  Enable device with MMIO
 *
 * Input Parameters:
 *   dev - device
 *
 * Return value:
 *   -EINVAL: error
 *   OK: OK
 *
 ****************************************************************************/

int pci_enable_device(FAR struct pci_dev_s *dev)
{
  uint16_t old_cmd;
  uint16_t cmd;

  DEBUGASSERT(dev->bus->ops->pci_cfg_read);
  DEBUGASSERT(dev->bus->ops->pci_cfg_write);

  old_cmd = dev->bus->ops->pci_cfg_read(dev, PCI_CFG_COMMAND, 2);

  cmd = old_cmd | (PCI_CMD_MASTER | PCI_CMD_MEM);

  dev->bus->ops->pci_cfg_write(dev, PCI_CFG_COMMAND, cmd, 2);

  pciinfo("%02x:%02x.%x, CMD: %x -> %x\n",
          dev->bdf >> 8, (dev->bdf >> 3) & 0x1f, dev->bdf & 0x3,
          old_cmd, cmd);

  return OK;
}

/****************************************************************************
 * Name: pci_find_cap
 *
 * Description:
 *  Search through the PCI device capability list to find given capability.
 *
 * Input Parameters:
 *   dev - Device
 *   cap - Bitmask of capability
 *
 * Returned Value:
 *   -1: Capability not supported
 *   other: the offset in PCI configuration space to the capability structure
 *
 ****************************************************************************/

int pci_find_cap(FAR struct pci_dev_s *dev, uint16_t cap)
{
  uint8_t pos = PCI_CFG_CAP_PTR - 1;
  uint16_t status;
  uint8_t rcap;

  DEBUGASSERT(dev->bus->ops->pci_cfg_read);

  status = dev->bus->ops->pci_cfg_read(dev, PCI_CFG_STATUS, 2);

  if (!(status & PCI_STS_CAPS))
      return -EINVAL;

  while (1)
    {
      pos = dev->bus->ops->pci_cfg_read(dev, pos + 1, 1);
      if (pos == 0)
          return -EINVAL;

      rcap = dev->bus->ops->pci_cfg_read(dev, pos, 1);

      if (rcap == cap)
          return pos;
    }
}

/****************************************************************************
 * Name: pci_get_bar
 *
 * Description:
 *  Get a 32 bits bar
 *
 * Input Parameters:
 *   dev    - Device private data
 *   bar    - Bar number
 *
 * Returned Value:
 *    Content of the bar
 *
 ****************************************************************************/

uint32_t pci_get_bar(FAR struct pci_dev_s *dev, uint32_t bar)
{
  DEBUGASSERT(bar <= 5);

  DEBUGASSERT(dev->bus->ops->pci_cfg_read);

  return dev->bus->ops->pci_cfg_read(dev, PCI_CFG_BAR + bar * 4, 4);
}

/****************************************************************************
 * Name: pci_get_bar64
 *
 * Description:
 *  Get a 64 bits bar
 *
 * Input Parameters:
 *   dev    - Device private data
 *   bar    - Bar number
 *
 * Returned Value:
 *    Content of the bar
 *
 ****************************************************************************/

uint64_t pci_get_bar64(FAR struct pci_dev_s *dev, uint32_t bar)
{
  DEBUGASSERT(bar <= 4 && ((bar % 2) == 0));

  DEBUGASSERT(dev->bus->ops->pci_cfg_read);

  uint32_t barmem1;
  uint32_t barmem2;

  barmem1 = dev->bus->ops->pci_cfg_read(dev, PCI_CFG_BAR + bar * 4, 4);

  DEBUGASSERT((barmem1 & PCI_BAR_64BIT) == PCI_BAR_64BIT);

  barmem2 = dev->bus->ops->pci_cfg_read(dev, PCI_CFG_BAR + bar * 4 + 4, 4);

  return ((uint64_t)barmem2 << 32) | barmem1;
}

/****************************************************************************
 * Name: pci_get_bar_size
 *
 * Description:
 *  Get a 32 bits bar size
 *
 * Input Parameters:
 *   dev    - Device private data
 *   bar    - Bar number
 *
 * Returned Value:
 *    Content of the bar
 *
 ****************************************************************************/

uint32_t pci_get_bar_size(FAR struct pci_dev_s *dev, uint32_t bar)
{
  DEBUGASSERT(bar <= 5);

  DEBUGASSERT(dev->bus->ops->pci_cfg_read);

  uint32_t original = pci_get_bar(dev, bar);
  pci_set_bar(dev, bar, 0xffffffff);

  uint32_t size = pci_get_bar(dev, bar);
  size = ~(size & ~0xf) + 1;

  pci_set_bar(dev, bar, original);

  return size;
}

/****************************************************************************
 * Name: pci_get_bar64_size
 *
 * Description:
 *  Get a 64 bits bar size
 *
 * Input Parameters:
 *   dev    - Device private data
 *   bar    - Bar number
 *
 * Returned Value:
 *    Content of the bar
 *
 ****************************************************************************/

uint64_t pci_get_bar64_size(FAR struct pci_dev_s *dev, uint32_t bar)
{
  DEBUGASSERT(bar <= 4 && ((bar % 2) == 0));

  uint64_t original = pci_get_bar64(dev, bar);

  pci_set_bar64(dev, bar, 0xffffffffffffffff);

  uint64_t size = pci_get_bar64(dev, bar);
  size = ~(size & ~0xf) + 1;

  pci_set_bar64(dev, bar, original);

  return size;
}

/****************************************************************************
 * Name: pci_set_bar
 *
 * Description:
 *  Set a 32 bits bar
 *
 * Input Parameters:
 *   dev    - Device private data
 *   bar    - Bar number
 *   val    - Bar Content
 *
 * Returned Value:
 *   0: success, <0: A negated errno
 *
 ****************************************************************************/

int pci_set_bar(FAR struct pci_dev_s *dev, uint32_t bar,
                uint32_t val)
{
  DEBUGASSERT(bar <= 5);

  DEBUGASSERT(dev->bus->ops->pci_cfg_write);

  dev->bus->ops->pci_cfg_write(dev, PCI_CFG_BAR + bar * 4, val, 4);

  return OK;
}

/****************************************************************************
 * Name: pci_set_bar64
 *
 * Description:
 *  Set a 64 bits bar
 *
 * Input Parameters:
 *   dev    - Device private data
 *   bar    - Bar number
 *   val    - Bar Content
 *
 * Returned Value:
 *   0: success, <0: A negated errno
 *
 ****************************************************************************/

int pci_set_bar64(FAR struct pci_dev_s *dev, uint32_t bar,
                  uint64_t val)
{
  DEBUGASSERT(bar <= 4 && ((bar % 2) == 0));

  DEBUGASSERT(dev->bus->ops->pci_cfg_write);

  dev->bus->ops->pci_cfg_write(dev, PCI_CFG_BAR + bar * 4,
                               (uint32_t)val, 4);
  dev->bus->ops->pci_cfg_write(dev, PCI_CFG_BAR + bar * 4 + 4,
                               (uint32_t)(val >> 32), 4);

  return OK;
}

/****************************************************************************
 * Name: pci_map_bar
 *
 * Description:
 *  Map address in a 32 bits bar in the flat memory address space
 *
 * Input Parameters:
 *   dev    - Device private data
 *   bar    - Bar number
 *   length - Map length, multiple of PAGE_SIZE
 *
 * Returned Value:
 *   NULL: error, Otherwise: Mapped address
 *
 ****************************************************************************/

void *pci_map_bar(FAR struct pci_dev_s *dev, uint32_t bar)
{
  void *ret;

  DEBUGASSERT(bar <= 5);

  if (!dev->bus->ops->pci_map_mem ||
      !dev->bus->ops->pci_cfg_read)
      return NULL;

  uint32_t barmem = pci_get_bar(dev, bar);
  unsigned long length = pci_get_bar_size(dev, bar);

  if (((bar % 2) == 0 &&
      (barmem & PCI_BAR_64BIT) == PCI_BAR_64BIT) ||
      (barmem & PCI_BAR_IO)    == PCI_BAR_IO)
      return NULL;

  ret = dev->bus->ops->pci_map_mem(dev, barmem & ~0xf, length);

  if (!(barmem & ~0xf))
      pci_set_bar(dev, bar, (uint32_t)((uintptr_t)ret));

  return ret;
}

/****************************************************************************
 * Name: pci_map_bar64
 *
 * Description:
 *  Map address in a 64 bits bar in the flat memory address space
 *
 * Input Parameters:
 *   dev    - Device private data
 *   bar    - Bar number
 *   length - Map length, multiple of PAGE_SIZE
 *
 * Returned Value:
 *   NULL: error, Otherwise: Mapped address
 *
 ****************************************************************************/

void *pci_map_bar64(FAR struct pci_dev_s *dev, uint32_t bar)
{
  void *ret;

  DEBUGASSERT(bar <= 4 && ((bar % 2) == 0));

  if (!dev->bus->ops->pci_map_mem ||
      !dev->bus->ops->pci_cfg_read)
      return NULL;

  uint64_t barmem = pci_get_bar64(dev, bar);
  unsigned long length = pci_get_bar64_size(dev, bar);

  if ((barmem & PCI_BAR_64BIT) != PCI_BAR_64BIT ||
      (barmem & PCI_BAR_IO)    == PCI_BAR_IO)
      return NULL;

  ret = dev->bus->ops->pci_map_mem(dev, barmem & ~0xf, length);

  if (!(barmem & ~0xf))
      pci_set_bar64(dev, bar, (uint64_t)ret);

  return ret;
}

/****************************************************************************
 * Name: pci_ioremap
 *
 * Description:
 *  Map PCI address region in the flat memory address space
 *
 * Input Parameters:
 *   dev       - Device private data
 *   from_addr - Address to map
 *   length    - Map length
 *
 * Returned Value:
 *   NULL: error, Otherwise: Mapped address
 *
 ****************************************************************************/

void *pci_ioremap(FAR struct pci_dev_s *dev,
                  uintptr_t from_addr, unsigned long length)
{
  DEBUGASSERT(from_addr != 0);

  if (!dev->bus->ops->pci_map_mem)
      return NULL;

  return dev->bus->ops->pci_map_mem(dev, from_addr, length);
}
