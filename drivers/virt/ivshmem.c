/*****************************************************************************
 * drivers/virt/ivhsmem.c
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
 *****************************************************************************/

/*****************************************************************************
 * Included Files
 *****************************************************************************/

#include <nuttx/config.h>
#include <nuttx/arch.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>

#include <arch/io.h>
#include <nuttx/pci/pci.h>
#include <nuttx/virt/ivshmem.h>

/*****************************************************************************
 * Pre-processor Definitions
 *****************************************************************************/

#define IVSHMEM_WAIT 10
#define IVSHMEM_WAKE 11

#define MIN(a,b) (((a)<(b))?(a):(b))

/*****************************************************************************
 * Private Types
 *****************************************************************************/

typedef FAR struct file        file_t;

struct ivshmem_mem_region_s
{
  uintptr_t       paddress;
  uintptr_t       address;
  unsigned long   size;
  unsigned long   seek_address;
  bool            readonly;
};

struct ivshmem_dev_s
{
  FAR struct pci_dev_s dev;

  FAR volatile struct jh_ivshmem_regs_s *regs;
  void *msix_table;
  int peer_id;
  int vectors;

  FAR struct ivshmem_mem_region_s mem[5];

  sem_t ivshmem_input_sem;
};

/*****************************************************************************
 * Private Function Prototypes
 *****************************************************************************/

static int ivshmem_open(file_t *filep);
static int ivshmem_close(file_t *filep);
static int ivshmem_ioctl(file_t *filep, int cmd, unsigned long arg);
static off_t ivshmem_seek(struct ivshmem_mem_region_s *mem,
                          off_t offset, int whence);
static off_t ivshmem_rw_seek(file_t *filep, off_t offset, int whence);
static off_t ivshmem_io_seek(file_t *filep, off_t offset, int whence);
static ssize_t ivshmem_read(struct ivshmem_mem_region_s *mem,
                            FAR char *buf, size_t buflen);
static ssize_t ivshmem_rw_read(file_t *filep, FAR char *buf, size_t buflen);
static ssize_t ivshmem_io_read(file_t *filep, FAR char *buf, size_t buflen);
static ssize_t ivshmem_write(struct ivshmem_mem_region_s *mem,
                             FAR const char *buf, size_t buflen);
static ssize_t ivshmem_rw_write(file_t *filep,
                                FAR const char *buf, size_t buflen);
static ssize_t ivshmem_io_write(file_t *filep,
                                FAR const char *buf, size_t buflen);

/*****************************************************************************
 * Private Data
 *****************************************************************************/

static int g_ivshmem_dev_count = 0;

struct ivshmem_dev_s g_ivshmem_devices[CONFIG_VIRT_JH_IVSHMEM_MAX_COUNT];

static const struct file_operations ivshmem_rw_ops =
{
    ivshmem_open,      /* open */
    ivshmem_close,     /* close */
    ivshmem_rw_read,   /* read */
    ivshmem_rw_write,  /* write */
    ivshmem_rw_seek,   /* seek */
    ivshmem_ioctl,     /* ioctl */
};

static const struct file_operations ivshmem_io_ops =
{
    ivshmem_open,      /* open */
    ivshmem_close,     /* close */
    ivshmem_io_read,   /* read */
    ivshmem_io_write,  /* write */
    ivshmem_io_seek,   /* seek */
    ivshmem_ioctl,     /* ioctl */
};

/*****************************************************************************
 *  ivshmem support functions
 *****************************************************************************/

static void send_irq(struct ivshmem_dev_s *dev, uint16_t vector)
{
    dev->regs->doorbell = ((uint32_t)dev->peer_id << 16) | vector;
}

static int ivshmem_irq_handler(int irq, uint32_t *regs, void *arg)
{
  int svalue;
  struct ivshmem_dev_s *priv = (struct ivshmem_dev_s *)arg;

  sem_getvalue(&(priv->ivshmem_input_sem), &svalue);
  if (svalue < 0)
      sem_post(&(priv->ivshmem_input_sem));

  return 0;
}

/*****************************************************************************
 * Private Functions
 *****************************************************************************/

/*****************************************************************************
 * ivshmem: Fileops
 *****************************************************************************/

static int ivshmem_open(file_t *filep)
{
  return OK;
}

static int ivshmem_close(file_t *filep)
{
  return OK;
}

static int ivshmem_ioctl(file_t *filep, int cmd, unsigned long arg)
{
  struct inode         *inode;
  struct ivshmem_dev_s *priv;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  priv  = (struct ivshmem_dev_s *)inode->i_private;

  switch (cmd)
    {
      case IVSHMEM_WAIT:
          sem_wait(&(priv->ivshmem_input_sem));
          break;
      case IVSHMEM_WAKE:
          send_irq(priv, (uint16_t)arg);
          break;
    }

  return 0;
}

static off_t ivshmem_seek(struct ivshmem_mem_region_s *mem,
                          off_t offset, int whence)
{
  unsigned long addr;
  switch (whence)
    {
      case SEEK_CUR:  /* Incremental seek */
        addr = mem->seek_address + offset;
        if (addr < 0 || addr > mem->size)
        {
            set_errno(-EINVAL);
            return -1;
        }

        mem->seek_address = addr;
        break;

      case SEEK_END:
        mem->seek_address = mem->size;
        break;

      case SEEK_SET:  /* Seek to designated address */
          if (offset < 0 || offset > mem->size)
          {
              set_errno(-EINVAL);
              return -1;
          }

          mem->seek_address = offset;
          break;

      default:        /* invalid whence */
          set_errno(-EINVAL);
          return -1;
    }

  return mem->seek_address;
}

static off_t ivshmem_rw_seek(file_t *filep, off_t offset, int whence)
{
  struct inode         *inode;
  struct ivshmem_dev_s *priv;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  priv  = (struct ivshmem_dev_s *)inode->i_private;

  return ivshmem_seek(priv->mem + 2, offset, whence);
}

static off_t ivshmem_io_seek(file_t *filep, off_t offset, int whence)
{
  struct inode         *inode;
  struct ivshmem_dev_s *priv;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  priv  = (struct ivshmem_dev_s *)inode->i_private;

  return ivshmem_seek(priv->mem + 3, offset, whence);
}

static ssize_t ivshmem_read(struct ivshmem_mem_region_s *mem,
                            FAR char *buf, size_t buflen)
{
  int size;

  if (buf == NULL || buflen < 1)
    {
      set_errno(-EINVAL);
      return -1;
    }

  size = MIN(buflen, mem->size - mem->seek_address);

  if (size <= 0)
      return EOF;

  memcpy(buf, (void *)(mem->address + mem->seek_address), size);

  mem->seek_address += size;

  return size;
}

static ssize_t ivshmem_rw_read(file_t *filep, FAR char *buf, size_t buflen)
{
  struct inode         *inode;
  struct ivshmem_dev_s *priv;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  priv  = (struct ivshmem_dev_s *)inode->i_private;

  return ivshmem_read(priv->mem + 2, buf, buflen);
}

static ssize_t ivshmem_io_read(file_t *filep, FAR char *buf, size_t buflen)
{
  struct inode         *inode;
  struct ivshmem_dev_s *priv;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  priv  = (struct ivshmem_dev_s *)inode->i_private;

  return ivshmem_read(priv->mem + 3, buf, buflen);
}

static ssize_t ivshmem_write(struct ivshmem_mem_region_s *mem,
                             FAR const char *buf, size_t buflen)
{
  int size;

  if (buf == NULL || buflen < 1)
    {
      set_errno(-EINVAL);
      return -1;
    }

  size = MIN(buflen, mem->size - mem->seek_address);

  if (size <= 0)
      return EOF;

  memcpy((void *)(mem->address + mem->seek_address), buf, size);

  mem->seek_address += size;

  return size;
}

static ssize_t ivshmem_rw_write(file_t *filep,
                                FAR const char *buf, size_t buflen)
{
  struct inode           *inode;
  struct ivshmem_dev_s   *priv;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  priv  = (struct ivshmem_dev_s *)inode->i_private;

  return ivshmem_write(priv->mem + 2, buf, buflen);
}

static ssize_t ivshmem_io_write(file_t *filep,
                                FAR const char *buf, size_t buflen)
{
  struct inode           *inode;
  struct ivshmem_dev_s   *priv;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  priv  = (struct ivshmem_dev_s *)inode->i_private;

  return ivshmem_write(priv->mem + 4, buf, buflen);
}

/*****************************************************************************
 * Public Functions
 *****************************************************************************/

/*****************************************************************************
 * Initialize device, add /dev/... nodes
 *****************************************************************************/

int ivshmem_probe(FAR struct pci_bus_s *bus,
                  FAR struct pci_dev_type_s *type, uint16_t bdf)
{
  char buf[32];
  int ret;
  int vndr_cap;
  int msix_cap;
  uint8_t vndr_length;
  uint32_t io_section_size;
  struct ivshmem_mem_region_s *mem;
  struct ivshmem_dev_s *dev = g_ivshmem_devices + g_ivshmem_dev_count;

  if (g_ivshmem_dev_count >= CONFIG_VIRT_JH_IVSHMEM_MAX_COUNT)
    {
      pcierr("Probed too many ivshmem devices!\n");
    }

  memset(dev, 0, sizeof(struct ivshmem_dev_s));

  dev->dev.bus = bus;
  dev->dev.type = type;
  dev->dev.bdf = bdf;

  if (pci_find_cap(&dev->dev, PCI_CAP_MSIX) < 0)
    {
      pcierr("Device is not MSIX capable\n");
      return -EINVAL;
    }

  dev->regs = pci_map_bar(&dev->dev, 0);
  dev->msix_table = pci_map_bar(&dev->dev, 1);

  pciinfo("Ivshmem[%d] mapped bar[0]: %p\n",
          g_ivshmem_dev_count, dev->regs);

  pciinfo("Ivshmem[%d] mapped bar[1]: %p\n",
          g_ivshmem_dev_count, dev->msix_table);

  if (!dev->regs || !dev->msix_table)
    {
      pcierr("Failed to map ivshmem bars!\n");
      return -EBUSY;
    }

  pci_enable_device(&dev->dev);

  if (dev->regs->max_peers != 2)
      return -EINVAL;

  dev->peer_id = !dev->regs->id;

  mem = &dev->mem[0];

  vndr_cap = pci_find_cap(&dev->dev, PCI_CAP_VNDR);

  if (vndr_cap < 0)
    {
      pcierr("Ivshmem[%d] missing vendor capability\n", g_ivshmem_dev_count);
      return -ENODEV;
    }

  mem->address = (uintptr_t)dev->regs;
  mem->size = pci_get_bar_size(&dev->dev, 0);

  pciinfo("Ivshmem[%d] shared memory base: 0x%lx, size: 0x%lx\n",
          g_ivshmem_dev_count, mem->address, mem->size);

  mem++;

  vndr_length =
    pci_cfg_read(&dev->dev, vndr_cap + JH_IVSHMEM_VND_LENGTH, 1);

  if (vndr_length == JH_IVSHMEM_VND_LENGTH_NO_ADDR)
    {
      mem->paddress = pci_get_bar64(&dev->dev, 2);
    }
  else
    {
      mem->paddress =
        ((uintptr_t)pci_cfg_read(&dev->dev,
          vndr_cap + JH_IVSHMEM_VND_ADDR + 4, 4) << 32);
      mem->paddress |=
        ((uintptr_t)pci_cfg_read(&dev->dev,
          vndr_cap + JH_IVSHMEM_VND_ADDR, 4));
    }

  mem->size =
        (pci_cfg_read(&dev->dev, vndr_cap + JH_IVSHMEM_VND_ST_SIZE, 4));
  mem->readonly = true;

  mem->address = (uintptr_t)pci_ioremap(&dev->dev, mem->paddress, mem->size);
  if (!mem->address)
      return -EBUSY;

  pciinfo("Ivshmem[%d] State Table phy_addr: " \
          "0x%lx virt_addr: 0x%lx, size: 0x%lx\n",
          g_ivshmem_dev_count, mem->paddress, mem->address, mem->size);

  mem++;

  mem->paddress = (mem - 1)->paddress + (mem - 1)->size;

  mem->size =
        (pci_cfg_read(&dev->dev, vndr_cap + JH_IVSHMEM_VND_RW_SIZE, 4));
  if (mem->size)
    {
      mem->readonly = false;

      mem->address =
        (uintptr_t)pci_ioremap(&dev->dev, mem->paddress, mem->size);

      if (!mem->address)
          return -EBUSY;

      strcpy((void *)mem->address, "IVSHMEM MAGIC!");

      pciinfo("Ivshmem[%d] R/W  region phy_addr: " \
              "0x%lx virt_addr: 0x%lx, size: 0x%lx\n",
              g_ivshmem_dev_count, mem->paddress, mem->address, mem->size);
    }

  mem++;

  io_section_size =
        (pci_cfg_read(&dev->dev, vndr_cap + JH_IVSHMEM_VND_IO_SIZE, 4));
  if (io_section_size)
    {
      mem->size = io_section_size * 2;
      mem->paddress = (mem - 1)->paddress + (mem - 1)->size;

      mem->readonly = true;

      mem->address =
        (uintptr_t)pci_ioremap(&dev->dev, mem->paddress, mem->size);
      if (!mem->address)
          return -EBUSY;

      pciinfo("Ivshmem[%d] I    region phy_addr: " \
              "0x%lx virt_addr: 0x%lx, size: 0x%lx\n",
              g_ivshmem_dev_count, mem->paddress, mem->address, mem->size);

      mem++;

      mem->size = io_section_size;
      mem->paddress =
        (mem - 2)->paddress + (mem - 2)->size + (!dev->peer_id) * mem->size;

      mem->readonly = false;

      mem->address =
        (uintptr_t)pci_ioremap(&dev->dev, mem->paddress, mem->size);
      if (!mem->address)
          return -EBUSY;

      memset((void *)mem->address, 0, mem->size);

      pciinfo("Ivshmem[%d] O    region phy_addr: " \
              "0x%lx virt_addr: 0x%lx, size: 0x%lx\n",
              g_ivshmem_dev_count, mem->paddress, mem->address, mem->size);
    }

  pci_cfg_write(&dev->dev, vndr_cap + JH_IVSHMEM_VND_PCTL,
                          JH_IVSHMEM_VND_PCTL_1SHOT, 1);

  msix_cap = pci_find_cap(&dev->dev, PCI_CAP_MSIX);

  dev->vectors =
    (pci_cfg_read(&dev->dev, msix_cap + PCI_MSIX_MCR, 2) & \
    PCI_MSIX_MCR_TBL_MASK) + 1;

  if (sem_init(&(dev->ivshmem_input_sem), 0, 0))
    {
      pcierr("Ivshmem[%d] Semaphore initialization failed\n");
      return -EFAULT;
    };

  for (int i = 0; i < dev->vectors; i++)
    {
      (void)irq_attach(CONFIG_VIRT_JH_IVSHMEM_BASE_IRQ + g_ivshmem_dev_count,
          (xcpt_t)ivshmem_irq_handler, &dev);
      pci_msix_register(&dev->dev,
          CONFIG_VIRT_JH_IVSHMEM_BASE_IRQ + g_ivshmem_dev_count, i);
    }

  sprintf(buf, "/dev/ivshmem%d-rw", g_ivshmem_dev_count);
  ret = register_driver(buf, &ivshmem_rw_ops, 0444, &dev);
  if (ret)
    {
      pcierr("Ivshmem[%d] R/W node registration failed: %d\n",
             g_ivshmem_dev_count, ret);
      return -ENODEV;
    };

  sprintf(buf, "/dev/ivshmem%d-io", g_ivshmem_dev_count);
  ret = register_driver(buf, &ivshmem_io_ops, 0444, &dev);
  if (ret)
    {
      pcierr("Ivshmem[%d] I/O node registration failed: %d\n",
             g_ivshmem_dev_count, ret);
      return -ENODEV;
    };

  g_ivshmem_dev_count++;
  pciinfo("Initialized Ivshmem[%d]\n", g_ivshmem_dev_count);

  return OK;
}

/*****************************************************************************
 * Public Data
 *****************************************************************************/

struct pci_dev_type_s pci_ivshmem =
{
    .vendor = JH_IVSHMEM_VENDORID,
    .device = JH_IVSHMEM_DEVICEID,
    .class_rev = PCI_ID_ANY,
    .name = "Jailhouse Ivshmem",
    .probe = ivshmem_probe
};
