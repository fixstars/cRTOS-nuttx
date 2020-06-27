/*****************************************************************************
 * arch/x86_64/src/tux/up_shadow.c
 * Copyright (C) 2020  Chung-Fan Yang
 *
 * Derived from Jailhouse Linux Ivshmem-net driver
 * Copyright (C) 2020  Jan Kiszka
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
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
#include <poll.h>

#include "sched/sched.h"
#include "semaphore/semaphore.h"

#include <arch/io.h>
#include <nuttx/pci/pci.h>
#include <nuttx/virt/ivshmem.h>
#include <nuttx/virt/virtio_ring.h>

#include "tux.h"

/*****************************************************************************
 * Pre-processor Definitions
 *****************************************************************************/

#if !defined(CONFIG_SCHED_WORKQUEUE)
#  error Work queue support is required!
#endif

#if !defined(LPWORK)
#  error Low priority workqueue is required
#endif

#define SHADOW_MAX_COUNT 1

#define SHADOW_STATE_RESET    0
#define SHADOW_STATE_INIT     1
#define SHADOW_STATE_READY    2
#define SHADOW_STATE_RUN      3

#define SHADOW_FLAG_RUN       0

#define SHADOW_MTU_MIN        68
#define SHADOW_MTU_DEFAULT    256

#define SHADOW_ALIGN(addr, align) (((addr) + (align - 1)) & ~(align - 1))
#define SMP_CACHE_BYTES         64
#define SHADOW_FRAME_SIZE(s)  SHADOW_ALIGN(18 + (s), SMP_CACHE_BYTES)

#define SHADOW_VQ_ALIGN       64

#define SHADOW_SECTION_REG    0
#define SHADOW_SECTION_ST     1
#define SHADOW_SECTION_RW     2
#define SHADOW_SECTION_RX     3
#define SHADOW_SECTION_TX     4

#define SHADOW_MSIX_STATE     0
#define SHADOW_MSIX_TX_RX     1

#define SHADOW_NUM_VECTORS    2

/*****************************************************************************
 * Private Types
 *****************************************************************************/

typedef FAR struct file        file_t;

struct shadow_queue {
  struct vring vr;
  uint32_t free_head;
  uint32_t num_free;
  uint32_t num_added;
  uint16_t last_avail_idx;
  uint16_t last_used_idx;

  void *data;
  void *end;
  uint32_t size;
  uint32_t head;
  uint32_t tail;
};

struct shadow_mem_region_s
{
  uintptr_t       paddress;
  uintptr_t       address;
  unsigned long   size;
  bool            readonly;
};

struct shadow_dev_s
{
  FAR struct pci_dev_s dev;

  FAR volatile struct jh_ivshmem_regs_s *regs;
  void *msix_table;
  int peer_id;
  int vectors;

  FAR struct shadow_mem_region_s mem[5];

  struct shadow_queue rx;
  struct shadow_queue tx;

  uint32_t vrsize;
  uint32_t qlen;
  uint32_t qsize;

  uint32_t state;
  uint32_t last_peer_state;
  volatile uint32_t *state_table;

  unsigned long flags;

  struct work_s sk_irqwork;
  struct work_s sk_statework;  /* For deferring interrupt work to the work queue */
};

/*****************************************************************************
 * Private Function Prototypes
 *****************************************************************************/

/*****************************************************************************
 * shadow: Fileops
 *****************************************************************************/

static int shadow_open(file_t *filep);
static int shadow_close(file_t *filep);
static int shadow_ioctl(file_t *filep, int cmd, unsigned long arg);
static off_t shadow_seek(file_t *filep,
                         off_t offset, int whence);
static ssize_t shadow_read(file_t *filep,
                           FAR char *buf, size_t buflen);
static ssize_t shadow_write(file_t *filep,
                            FAR const char *buf, size_t buflen);
#ifndef CONFIG_DISABLE_POLL
static int shadow_poll(FAR struct file *filep,
                       FAR struct pollfd *fds, bool setup);
#endif

/*****************************************************************************
 * shadow: Pipe
 *****************************************************************************/

/* State machine */

static void shadow_state_change(void *dev);
static void shadow_set_state(struct shadow_dev_s *dev, uint32_t state);
static void shadow_check_state(struct shadow_dev_s *dev);

/* Common RX/TX logic */

static uint64_t shadow_transmit(FAR struct shadow_dev_s *dev,
                                const uint64_t *data);
static void shadow_receive(FAR struct shadow_dev_s *dev, uint64_t *buf);

/* Interrupt handling */

static int  shadow_interrupt(int irq, FAR void *context, FAR void *arg);

/*****************************************************************************
 * Private Data
 *****************************************************************************/

static int g_shadow_dev_count = 0;

struct shadow_dev_s g_shadow_devices[SHADOW_MAX_COUNT];

static const struct file_operations shadow_ops = {
    shadow_open,      /* open */
    shadow_close,     /* close */
    shadow_read,      /* read */
    shadow_write,     /* write */
    shadow_seek,      /* seek */
    shadow_ioctl,     /* ioctl */
    shadow_poll       /* poll */
};

/*****************************************************************************
 * Private Functions
 *****************************************************************************/

static void shadow_set_prio(struct shadow_dev_s *dev, uint64_t prio)
{
  if(!dev)
      return;

  *((volatile uint64_t *)(dev->mem[SHADOW_SECTION_TX].address + \
        dev->mem[SHADOW_SECTION_TX].size)) = prio;

  wmb();
}

/*****************************************
 *  Shadow vring support functions  *
 *****************************************/

static void *shadow_desc_data(
        struct shadow_dev_s *dev, struct shadow_queue *q,
        unsigned int region,  struct vring_desc *desc,
        uint32_t *len)
{
  uint64_t offs = READ_ONCE(desc->addr);
  uint32_t dlen = READ_ONCE(desc->len);
  uint16_t flags = READ_ONCE(desc->flags);
  void *data;

  if (flags)
      return NULL;

  if (offs >= dev->mem[region].size)
      return NULL;

  data = (void *)(dev->mem[region].address + offs);

  if (data < q->data || data >= q->end)
      return NULL;

  if (dlen > q->end - data)
      return NULL;

  *len = dlen;

  return data;
}

static void shadow_init_queue(
        struct shadow_dev_s *dev, struct shadow_queue *q,
        void *mem, unsigned int len)
{
  memset(q, 0, sizeof(*q));

  vring_init(&q->vr, len, mem, SHADOW_VQ_ALIGN);
  q->data = mem + dev->vrsize;
  q->end = q->data + dev->qsize;
  q->size = dev->qsize;
}

static void shadow_init_queues(struct shadow_dev_s *dev)
{
  void *tx;
  void *rx;
  int i;
  void* tmp;

  tx = (void *)dev->mem[SHADOW_SECTION_TX].address;
  rx = (void *)dev->mem[SHADOW_SECTION_RX].address;

  memset(tx, 0, dev->mem[SHADOW_SECTION_TX].size);

  shadow_init_queue(dev, &dev->tx, tx, dev->qlen);
  shadow_init_queue(dev, &dev->rx, rx, dev->qlen);

  tmp = dev->rx.vr.used;
  dev->rx.vr.used = dev->tx.vr.used;
  dev->tx.vr.used = tmp;

  dev->tx.num_free = dev->tx.vr.num;

  for (i = 0; i < dev->tx.vr.num - 1; i++)
      dev->tx.vr.desc[i].next = i + 1;
}

static int shadow_calc_qsize(struct shadow_dev_s *dev)
{
  unsigned int vrsize;
  unsigned int qsize;
  unsigned int qlen;

  for (qlen = 4096; qlen > 32; qlen >>= 1)
    {
      vrsize = vring_size(qlen, SHADOW_VQ_ALIGN);
      vrsize = SHADOW_ALIGN(vrsize, SHADOW_VQ_ALIGN);
      if (vrsize < (dev->mem[SHADOW_SECTION_TX].size) / 8)
          break;
    }

  if (vrsize > dev->mem[SHADOW_SECTION_TX].size)
      return -EINVAL;

  qsize = dev->mem[SHADOW_SECTION_TX].size - vrsize;

  if (qsize < 4 * SHADOW_MTU_MIN)
      return -EINVAL;

  dev->vrsize = vrsize;
  dev->qlen = qlen;
  dev->qsize = qsize;

  return 0;
}

/*****************************************
 *  Shadow IRQ support functions  *
 *****************************************/

static void shadow_notify_tx(struct shadow_dev_s *dev, unsigned int num)
{
  dev->regs->doorbell =
    ((uint32_t)dev->peer_id << 16) | SHADOW_MSIX_TX_RX;
}

static void shadow_enable_rx_irq(struct shadow_dev_s *dev)
{
  vring_avail_event(&dev->rx.vr) = dev->rx.last_avail_idx;
  wmb();
}

static void shadow_enable_tx_irq(struct shadow_dev_s *dev)
{
  vring_used_event(&dev->tx.vr) = dev->tx.last_used_idx;
  wmb();
}

/*************************************
 *  Shadow vring syntax sugars  *
 *************************************/

static struct vring_desc *shadow_rx_desc(struct shadow_dev_s *dev)
{
  struct shadow_queue *rx = &dev->rx;
  struct vring *vr = &rx->vr;
  unsigned int avail;
  uint16_t avail_idx;

  avail_idx = virt_load_acquire(&vr->avail->idx);

  if (avail_idx == rx->last_avail_idx)
      return NULL;

  avail = vr->avail->ring[rx->last_avail_idx++ & (vr->num - 1)];
  if (avail >= vr->num)
    {
      svcerr("invalid rx avail %d\n", avail);
      return NULL;
    }

  return &vr->desc[avail];
}

static void shadow_rx_finish(struct shadow_dev_s *dev, struct vring_desc *desc)
{
  struct shadow_queue *rx = &dev->rx;
  struct vring *vr = &rx->vr;
  unsigned int desc_id = desc - vr->desc;
  unsigned int used;

  used = rx->last_used_idx++ & (vr->num - 1);
  vr->used->ring[used].id = desc_id;
  vr->used->ring[used].len = 1;

  virt_store_release(&vr->used->idx, rx->last_used_idx);
}

static size_t shadow_tx_space(struct shadow_dev_s *dev)
{
  struct shadow_queue *tx = &dev->tx;
  uint32_t tail = tx->tail;
  uint32_t head = tx->head;
  uint32_t space;

  if (head < tail)
      space = tail - head;
  else
      space = (tx->size - head) > tail ? (tx->size - head) : tail;

  return space;
}

static bool shadow_tx_ok(struct shadow_dev_s *dev, unsigned int mtu)
{
  return dev->tx.num_free >= 2 &&
      shadow_tx_space(dev) >= 2 * SHADOW_FRAME_SIZE(mtu);
}

static uint32_t shadow_tx_advance(struct shadow_queue *q,
                                  uint32_t *pos, uint32_t len)
{
  uint32_t p = *pos;

  len = SHADOW_FRAME_SIZE(len);

  if (q->size - p < len)
      p = 0;
  *pos = p + len;

  return p;
}

static int shadow_tx_clean(struct shadow_dev_s *dev)
{
  struct shadow_queue *tx = &dev->tx;
  struct vring *vr = &tx->vr;
  struct vring_desc *desc;
  struct vring_desc *fdesc;
  struct vring_used_elem *used;
  uint16_t last = tx->last_used_idx;
  uint32_t fhead;
  unsigned int num;
  bool tx_ok;

  fdesc = NULL;
  fhead = 0;
  num = 0;

  while (last != virt_load_acquire(&vr->used->idx))
    {
      void *data;
      uint32_t len;
      uint32_t tail;

      used = vr->used->ring + (last % vr->num);
      if (used->id >= vr->num || used->len != 1)
        {
          svcerr("invalid tx used->id %d ->len %d\n",
                 used->id, used->len);
          break;
        }

      desc = &vr->desc[used->id];

      data = shadow_desc_data(dev, &dev->tx, SHADOW_SECTION_TX,
               desc, &len);
      if (!data)
        {
          svcerr("bad tx descriptor, data == NULL\n");
          break;
        }

      tail = shadow_tx_advance(tx, &tx->tail, len);
      if (data != tx->data + tail)
        {
          svcerr("bad tx descriptor\n");
          break;
        }

      if (!num)
          fdesc = desc;
      else
          desc->next = fhead;

      fhead = used->id;

      tx->last_used_idx = ++last;
      num++;
      tx->num_free++;

      DEBUGASSERT(tx->num_free <= vr->num);

      tx_ok = shadow_tx_ok(dev, SHADOW_MTU_DEFAULT);
      if (!tx_ok)
          shadow_enable_tx_irq(dev);
  }

  if (num)
    {
      fdesc->next = tx->free_head;
      tx->free_head = fhead;
    }
  else
    {
      tx_ok = shadow_tx_ok(dev, SHADOW_MTU_DEFAULT);
    }

  return tx_ok;
}

static int shadow_tx_frame(struct shadow_dev_s *dev, void* data, int len)
{
  struct shadow_queue *tx = &dev->tx;
  struct vring *vr = &tx->vr;
  struct vring_desc *desc;
  unsigned int desc_idx;
  unsigned int avail;
  uint32_t head;
  void *buf;

  unsigned int ret = shadow_tx_clean(dev);
  DEBUGASSERT(ret);

  desc_idx = tx->free_head;
  desc = &vr->desc[desc_idx];
  tx->free_head = desc->next;
  tx->num_free--;

  head = shadow_tx_advance(tx, &tx->head, len);

  buf = tx->data + head;
  memcpy(buf, data, len);

  desc->addr = buf - (void *)dev->mem[SHADOW_SECTION_TX].address;
  desc->len = len;
  desc->flags = 0;

  avail = tx->last_avail_idx++ & (vr->num - 1);
  vr->avail->ring[avail] = desc_idx;
  tx->num_added++;

  virt_store_release(&vr->avail->idx, tx->last_avail_idx);
  shadow_notify_tx(dev, tx->num_added);
  tx->num_added = 0;

  return 0;
}

bool shadow_rx_avail(struct shadow_dev_s *in)
{
  mb();
  return READ_ONCE(in->rx.vr.avail->idx) != in->rx.last_avail_idx;
}

/*****************************************
 *  Shadow support functions  *
 *****************************************/

static void shadow_run(struct shadow_dev_s *dev)
{
  irqstate_t flags;

  if (dev->state < SHADOW_STATE_READY)
      return;

  /* test_and_set_bit */
  flags = enter_critical_section();
  if (dev->flags & SHADOW_FLAG_RUN)
    {
      dev->flags |= SHADOW_FLAG_RUN;
      leave_critical_section(flags);
      return;
    }

  dev->flags |= SHADOW_FLAG_RUN;
  leave_critical_section(flags);

  shadow_set_state(dev, SHADOW_STATE_RUN);
  shadow_enable_rx_irq(dev);

  return;
}

static void shadow_do_stop(struct shadow_dev_s *dev)
{
  irqstate_t flags;

  shadow_set_state(dev, SHADOW_STATE_RESET);

  /* test_and_clear_bit */
  flags = enter_critical_section();
  if (!(dev->flags & SHADOW_FLAG_RUN))
    {
      dev->flags &= ~SHADOW_FLAG_RUN;
      leave_critical_section(flags);
      return;
    }

  dev->flags &= ~SHADOW_FLAG_RUN;
  leave_critical_section(flags);

  return;
}

static uint64_t shadow_transmit(FAR struct shadow_dev_s *dev,
                                const uint64_t *data)
{
  struct tcb_s *rtcb = (struct tcb_s *)this_task();
  uint64_t buf[10];

  memcpy(buf, data, sizeof(uint64_t) * 7);
  buf[7] = (uint64_t)rtcb;

  uint64_t policy =
    ((rtcb->flags & TCB_FLAG_POLICY_MASK) >> TCB_FLAG_POLICY_SHIFT) + 1;
  uint64_t prio = rtcb->sched_priority;
  buf[8] = (policy << 32) | prio;

  buf[9] = rtcb->xcp.linux_tcb;

  shadow_tx_frame(dev, buf, sizeof(buf));

  return OK;
}

static void shadow_receive(FAR struct shadow_dev_s *dev, uint64_t *buf)
{
  struct vring_desc *desc;
  void *data;
  uint32_t len;

  /* Check for errors and update statistics */

  /* Get next avail rx descriptor from avail ring */

  desc = shadow_rx_desc(dev);
  if (!desc)
      return;

  /* Unpack descriptor and get the physical address in SHMEM and fill in len */

  data = shadow_desc_data(dev, &dev->rx, SHADOW_SECTION_RX,
                          desc, &len);
  if (!data)
    {
      svcerr("bad rx descriptor\n");
      return;
    }

  memcpy(buf, data, sizeof(uint64_t) * 2);

  /* Release the read descriptor in to the used ring */

  shadow_rx_finish(dev, desc);
}

int shadow_interrupt(int irq, FAR void *context, FAR void *arg)
{
  FAR struct shadow_dev_s *dev = (FAR struct shadow_dev_s *)arg;
  struct tcb_s *rtcb;
  uint64_t buf[2];

  DEBUGASSERT(dev != NULL);

  memset(buf, 0, sizeof(buf));

  shadow_receive(dev, buf);

  shadow_enable_rx_irq(dev);

  if (buf[1] & (1ULL << 63))
    {
      /* It is a signal */

      buf[1] &= ~(1ULL << 63);

      if (buf[0])
        {
          /*
          int lpid;
          lpid = get_nuttx_pid(buf[1]);
          if(lpid > 0)
              nxsig_kill(lpid, buf[0]);
              */
        }

    }
  else
    {
      rtcb = (struct tcb_s *)buf[1];

      if (rtcb)
        {
          rtcb->xcp.rsc_ret = buf[0];
          nxsem_post(&rtcb->xcp.rsc_lock);

          if(rtcb->xcp.rsc_pollfd)
            {
              /* Someone is waiting */

              rtcb->xcp.rsc_pollfd->revents |= POLLIN;
              nxsem_post(rtcb->xcp.rsc_pollfd->sem);
            }
        }
    }

  return OK;
}

/****************************************************************************
 * State Machine
 ****************************************************************************/

static void shadow_state_change(void *arg)
{
  struct shadow_dev_s *dev = (struct shadow_dev_s*)arg;
  uint32_t peer_state = READ_ONCE(dev->state_table[dev->peer_id]);

  svcinfo("Remote state: %d\n", peer_state);

  switch (dev->state)
    {
      case SHADOW_STATE_RESET:
          if (peer_state < SHADOW_STATE_READY)
              shadow_set_state(dev, SHADOW_STATE_INIT);
          break;

      case SHADOW_STATE_INIT:
          if (peer_state > SHADOW_STATE_RESET)
            {
              shadow_init_queues(dev);
              shadow_set_state(dev, SHADOW_STATE_READY);
            }
          break;

      case SHADOW_STATE_READY:
          if (peer_state >= SHADOW_STATE_READY)
            {
              shadow_run(dev);
              break;
            }
      case SHADOW_STATE_RUN:
          if (peer_state == SHADOW_STATE_RESET)
            {
              shadow_do_stop(dev);
            }
          break;
    }

  wmb();
  WRITE_ONCE(dev->last_peer_state, peer_state);
}

static void shadow_set_state(struct shadow_dev_s *dev, uint32_t state)
{
  wmb();
  WRITE_ONCE(dev->state, state);
  WRITE_ONCE(dev->regs->state, state);
}

static void shadow_check_state(struct shadow_dev_s *dev)
{
  irqstate_t flags;

  flags = enter_critical_section();

  /* test_bit */

  if (dev->state_table[dev->peer_id] != dev->last_peer_state ||
      !(SHADOW_FLAG_RUN & dev->flags))
      work_queue(LPWORK, &dev->sk_statework, shadow_state_change, dev, 0);

  leave_critical_section(flags);
}

static int shadow_state_handler(int irq, uint32_t *regs, void *arg)
{
  struct shadow_dev_s *dev = (struct shadow_dev_s *)arg;

  shadow_check_state(dev);

  return 0;
}

/*****************************************************************************
 * shadow: Fileops
 *****************************************************************************/

static int shadow_open(file_t *filep)
{
  return OK;
}

static int shadow_close(file_t *filep)
{
  return OK;
}

static int shadow_ioctl(file_t *filep, int cmd, unsigned long arg)
{
  struct inode        *inode;
  struct shadow_dev_s *dev;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  dev = (struct shadow_dev_s *)inode->i_private;

  if (cmd != 0)
      return -EINVAL;

  shadow_set_prio(dev, arg);

  return 0;
}

static off_t shadow_seek(file_t *filep,
                         off_t offset, int whence)
{
  return 0;
}

static ssize_t shadow_read(file_t *filep,
                           FAR char *buf, size_t buflen)
{
  struct tcb_s *rtcb = (struct tcb_s *)this_task();
  long ret;
  irqstate_t flags;

  DEBUGASSERT(buflen >= sizeof(uint64_t));

  flags = enter_critical_section();

  do {
    ret = nxsem_wait(&rtcb->xcp.rsc_lock);
  } while (ret);

  *((uint64_t *)buf) = rtcb->xcp.rsc_ret;

  leave_critical_section(flags);

  return sizeof(uint64_t);
}

static ssize_t shadow_write(file_t *filep,
                            FAR const char *buf, size_t buflen)
{
  struct inode          *inode;
  struct shadow_dev_s   *dev;
  uint64_t ret;

  DEBUGASSERT(filep);
  inode = filep->f_inode;

  DEBUGASSERT(inode && inode->i_private);
  dev = (struct shadow_dev_s *)inode->i_private;

  ret = shadow_transmit(dev, (const uint64_t *)buf);

  DEBUGASSERT(ret == 0);

  return buflen;
}

#ifndef CONFIG_DISABLE_POLL
static int shadow_poll(FAR struct file *filep,
                       FAR struct pollfd *fds, bool setup)
{
  struct tcb_s          *rtcb = (struct tcb_s *)this_task();
  int rd;

  /* Are we setting up the poll?  Or tearing it down? */

  if (setup)
      {
        if (fds->events & POLLOUT)
            fds->revents |= POLLOUT;

        if (fds->events & POLLIN)
          {
            nxsem_get_value(&rtcb->xcp.rsc_lock, &rd);

            if(rd > 0)
              {
                fds->revents |= POLLIN;
                nxsem_post(fds->sem);
                return OK;
              }
          }

        DEBUGASSERT(this_task()->xcp.rsc_pollfd == NULL);

        rtcb->xcp.rsc_pollfd = fds;
    }
  else /* Tear it down */
    {
        rtcb->xcp.rsc_pollfd = NULL;
    }
  return OK;
}
#else
#error "cRTOS shadow process require poll function"
#endif

/*****************************************************************************
 * Public Functions
 *****************************************************************************/

/*****************************************************************************
 * Initialize device, add /dev/... nodes
 *****************************************************************************/

int shadow_probe(FAR struct pci_bus_s *bus,
                  FAR struct pci_dev_type_s *type, uint16_t bdf)
{
  char buf[32];
  int ret;
  int vndr_cap;
  int msix_cap;
  uint8_t vndr_length;
  uint32_t io_section_size;
  struct shadow_mem_region_s *mem;
  struct shadow_dev_s *dev = g_shadow_devices + g_shadow_dev_count;

  if (g_shadow_dev_count >= SHADOW_MAX_COUNT)
    {
      pcierr("Probed too many shadow devices!\n");
    }

  memset(dev, 0, sizeof(struct shadow_dev_s));

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

  pciinfo("Shadow[%d] mapped bar[0]: %p\n",
          g_shadow_dev_count, dev->regs);

  pciinfo("Shadow[%d] mapped bar[1]: %p\n",
          g_shadow_dev_count, dev->msix_table);

  if (!dev->regs || !dev->msix_table)
    {
      pcierr("Failed to map shadow bars!\n");
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
      pcierr("Shadow[%d] missing vendor capability\n", g_shadow_dev_count);
      return -ENODEV;
    }

  mem->address = (uintptr_t)dev->regs;
  mem->size = pci_get_bar_size(&dev->dev, 0);

  pciinfo("Shadow[%d] shared memory base: 0x%lx, size: 0x%lx\n",
          g_shadow_dev_count, mem->address, mem->size);

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

  dev->state_table = (void*)mem->address;

  pciinfo("Shadow[%d] State Table phy_addr: " \
          "0x%lx virt_addr: 0x%lx, size: 0x%lx\n",
          g_shadow_dev_count, mem->paddress, mem->address, mem->size);

  mem++;

  /* The R/W region is hard coded to start from 0x1000, omitting first page */

  mem->paddress = 0x1000;

  mem->size =
      (pci_cfg_read(&dev->dev, vndr_cap + JH_IVSHMEM_VND_RW_SIZE, 4) - 0x1000);
  if (mem->size)
    {
      mem->readonly = false;

      mem->address =
        (uintptr_t)pci_ioremap(&dev->dev, mem->paddress, mem->size);

      if (!mem->address)
          return -EBUSY;

      pciinfo("Shadow[%d] R/W  region phy_addr: " \
              "0x%lx virt_addr: 0x%lx, size: 0x%lx\n",
              g_shadow_dev_count, mem->paddress, mem->address, mem->size);
    }

  mem++;

  io_section_size =
    (pci_cfg_read(&dev->dev, vndr_cap + JH_IVSHMEM_VND_IO_SIZE, 4) - 0x1000);
  if (io_section_size)
    {
      mem->size = io_section_size;
      mem->paddress = (mem - 2)->paddress + (mem - 2)->size;

      mem->readonly = true;

      mem->address =
        (uintptr_t)pci_ioremap(&dev->dev, mem->paddress, mem->size + 0x1000);
      if (!mem->address)
          return -EBUSY;

      pciinfo("Shadow[%d] I    region phy_addr: " \
              "0x%lx virt_addr: 0x%lx, size: 0x%lx\n",
              g_shadow_dev_count, mem->paddress, mem->address, mem->size);

      mem++;

      mem->size = io_section_size;
      mem->paddress =
        (mem - 3)->paddress + (mem - 3)->size +
        (!dev->peer_id) * mem->size + 0x1000;

      mem->readonly = false;

      mem->address =
        (uintptr_t)pci_ioremap(&dev->dev, mem->paddress, mem->size + 0x1000);
      if (!mem->address)
          return -EBUSY;

      memset((void *)mem->address, 0, mem->size);

      pciinfo("Shadow[%d] O    region phy_addr: " \
              "0x%lx virt_addr: 0x%lx, size: 0x%lx\n",
              g_shadow_dev_count, mem->paddress, mem->address, mem->size);
    }

  pci_cfg_write(&dev->dev, vndr_cap + JH_IVSHMEM_VND_PCTL, 0, 1);

  msix_cap = pci_find_cap(&dev->dev, PCI_CAP_MSIX);

  dev->vectors =
    (pci_cfg_read(&dev->dev, msix_cap + PCI_MSIX_MCR, 2) & \
    PCI_MSIX_MCR_TBL_MASK) + 1;

  if(dev->vectors < SHADOW_NUM_VECTORS)
    {
      pcierr("Shadow[%d] Number of vector must be at least 2\n");
      return -EBUSY;
    }

  (void)irq_attach(CONFIG_VIRT_SHADOW_BASE_IRQ + g_shadow_dev_count * 2,
                   (xcpt_t)shadow_state_handler, dev);
  (void)irq_attach(CONFIG_VIRT_SHADOW_BASE_IRQ + g_shadow_dev_count * 2 + 1,
                   (xcpt_t)shadow_interrupt, dev);

  pci_msix_register(&dev->dev,
      CONFIG_VIRT_SHADOW_BASE_IRQ + g_shadow_dev_count * 2, 0);
  pci_msix_register(&dev->dev,
      CONFIG_VIRT_SHADOW_BASE_IRQ + g_shadow_dev_count * 2 + 1, 1);

  if (shadow_calc_qsize(dev))
      return -EINVAL;

  sprintf(buf, "/dev/shadow%d", g_shadow_dev_count);
  ret = register_driver(buf, &shadow_ops, 0444, dev);
  if (ret)
    {
      pcierr("Shadow[%d] I/O node registration failed: %d\n",
             g_shadow_dev_count, ret);
      return -ENODEV;
    };

  shadow_set_prio(dev, this_task()->sched_priority);

  dev->regs->int_control = JH_IVSHMEM_INT_EN;
  dev->regs->state = SHADOW_STATE_RESET;
  dev->state = SHADOW_STATE_RESET;

  shadow_check_state(dev);

  pciinfo("Initialized Shadow[%d]\n", g_shadow_dev_count);

  g_shadow_dev_count++;

  return OK;
}

/****************************************************************************
 * Name: shadow_set_global_prio
 *
 * Description:
 *  Publish the tcb's priority
 *
 * Input Parameters:
 *   prio: tcb's priority
 *
 ****************************************************************************/

void shadow_set_global_prio(uint64_t prio)
{
  if(!g_shadow_dev_count)
      return;

  shadow_set_prio(g_shadow_devices, prio);
}

/****************************************************************************
 * Name: up_check_tasks
 *
 * Description:
 *   The currently executing task at the head of the ready to run list must
 *   be stopped.  Save its context and move it to the inactive list specified
 *   by task_state.
 *
 * Input Parameters:
 *   None
 *
 ****************************************************************************/

void up_check_tasks(void)
{
  uint64_t buf[2];
  struct tcb_s *rtcb;
  irqstate_t flags;

  if(!g_shadow_dev_count)
      return;

  if(!(g_shadow_devices->flags & SHADOW_FLAG_RUN))
      return;

  /* the IRQ of shadow process might race with us */

  flags = enter_critical_section();

  while (shadow_rx_avail(g_shadow_devices))
    {
      memset(buf, 0, sizeof(buf));

      shadow_receive(g_shadow_devices, buf);

      rtcb = (struct tcb_s *)buf[1];

      if (buf[1] & (1ULL << 63))
        {
          /* It is a signal */

          buf[1] &= ~(1ULL << 63);

          if(buf[0])
            {
              int lpid;
              lpid = get_nuttx_pid(buf[1]);

              if (lpid > 0)
                  nxsig_kill(lpid, buf[0]);
            }
        }
      else
        {
          buf[1] &= ~(1ULL << 63);

          rtcb = (struct tcb_s *)buf[1];

          if (rtcb)
            {
              /* Write the return value */
              rtcb->xcp.rsc_ret = buf[0];

              if (rtcb->xcp.rsc_pollfd)
                {
                  /* Someone is waiting */
                  rtcb->xcp.rsc_pollfd->revents |= POLLIN;
                }

              /* The sem to unblock,
               * either the poll sem or the rsc_lock sem
               */

              sem_t *to_unlock = rtcb->waitsem;

              /* It is, let the task take the semaphore */

              rtcb->waitsem = NULL;

              nxsem_release_holder(to_unlock);
              to_unlock->semcount++;

              /* The task will be the new holder of the semaphore when
               * it is awakened.
               */
              nxsem_add_holder_tcb(rtcb, to_unlock);

              nxsched_remove_blocked(rtcb);

              /* Add the task in the correct location in the prioritized
               * ready-to-run task list
               */
              nxsched_add_prioritized(rtcb, (FAR dq_queue_t *)&g_pendingtasks);
              rtcb->task_state = TSTATE_TASK_PENDING;
            }
        }
    }

  shadow_enable_rx_irq(g_shadow_devices);

  leave_critical_section(flags);
}

/*****************************************************************************
 * Public Data
 *****************************************************************************/

struct pci_dev_type_s pci_shadow =
{
    .vendor = JH_IVSHMEM_VENDORID,
    .device = JH_IVSHMEM_DEVICEID,
    .class_rev = JH_IVSHMEM_PROTOCOL_SHADOW,
    .name = "Jailhouse Shadow process memory and pipe",
    .probe = shadow_probe
};
