/*****************************************************************************
 * drivers/net/ivhsmem_net.c
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
#include <debug.h>

#include <arch/io.h>
#include <nuttx/pci/pci.h>
#include <nuttx/virt/ivshmem.h>
#include <nuttx/virt/virtio_ring.h>

#include <arpa/inet.h>
#include <nuttx/net/netdev.h>
#include <nuttx/net/arp.h>
#include <nuttx/net/ivshmem_net.h>

#ifdef CONFIG_NET_PKT
#  include <nuttx/net/pkt.h>
#endif

/*****************************************************************************
 * Pre-processor Definitions
 *****************************************************************************/

#define bswap16 __builtin_bswap16
#define bswap32 __builtin_bswap32
#define bswap64 __builtin_bswap64

/* Work queue support is required. */

#if !defined(CONFIG_SCHED_WORKQUEUE)
#  error Work queue support is required!
#else

/* The low priority work queue is preferred.  If it is not enabled, LPWORK
 * will be the same as HPWORK.
 */

#  if defined(CONFIG_IVSHMNET_HPWORK)
#    define ETHWORK HPWORK
#  elif defined(CONFIG_IVSHMNET_LPWORK)
#    define ETHWORK LPWORK
#  else
#    error Neither high or Low priority workqueue is defined
#  endif
#endif

/* CONFIG_IVSHMEM_NET_NINTERFACES determines the number of physical interfaces
 * that will be supported.
 */

#ifndef CONFIG_IVSHMNET_NINTERFACES
# define CONFIG_IVSHMNET_NINTERFACES 1
#endif

/* TX poll delay = 1 seconds. CLK_TCK is the number of clock ticks per second */

#define IVSHMNET_WDDELAY   (1 * CLK_TCK)

/* TX timeout = 1 minute */

#define IVSHMNET_TXTIMEOUT (20ULL * CLK_TCK)

/* This is a helper pointer for accessing the contents of the Ethernet header */

#define BUF ((struct eth_hdr_s *)priv->sk_dev.d_buf)

#define IVSHMNET_STATE_RESET    0
#define IVSHMNET_STATE_INIT     1
#define IVSHMNET_STATE_READY    2
#define IVSHMNET_STATE_RUN      3

#define IVSHMNET_FLAG_RUN       0

#define IVSHMNET_MTU_MIN        68
#define IVSHMNET_MTU_DEFAULT    16384

#define IVSHMNET_ALIGN(addr, align) (((addr) + (align - 1)) & ~(align - 1))
#define SMP_CACHE_BYTES         64
#define IVSHMNET_FRAME_SIZE(s)  IVSHMNET_ALIGN(18 + (s), SMP_CACHE_BYTES)

#define IVSHMNET_VQ_ALIGN       64

#define IVSHMNET_SECTION_ST     0
#define IVSHMNET_SECTION_TX     1
#define IVSHMNET_SECTION_RX     2

#define IVSHMNET_MSIX_STATE     0
#define IVSHMNET_MSIX_TX_RX     1

#define IVSHMNET_NUM_VECTORS    2

/*****************************************************************************
 * Private Types
 *****************************************************************************/

typedef FAR struct file        file_t;

struct ivshmnet_queue {
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

struct ivshmem_mem_region_s
{
  uintptr_t       paddress;
  uintptr_t       address;
  unsigned long   size;
  bool            readonly;
};

struct ivshmnet_driver_s
{
  FAR struct pci_dev_s dev;

  FAR volatile struct jh_ivshmem_regs_s *regs;
  void *msix_table;
  uint16_t peer_id;
  uint16_t vectors;

  FAR struct ivshmem_mem_region_s mem[3];

  struct ivshmnet_queue rx;
  struct ivshmnet_queue tx;

  uint32_t vrsize;
  uint32_t qlen;
  uint32_t qsize;

  uint32_t state;
  uint32_t last_peer_state;
  volatile uint32_t *state_table;

  unsigned long flags;

  struct net_driver_s sk_dev;  /* Interface understood by the network */
  bool sk_bifup;               /* true:ifup false:ifdown */
  WDOG_ID sk_txpoll;           /* TX poll timer */
  WDOG_ID sk_txtimeout;        /* TX timeout timer */
  struct work_s sk_pollwork;   /* For deferring poll work to the work queue */
  struct work_s sk_irqwork;
  struct work_s sk_statework;  /* For deferring interrupt work to the work queue */

  uint8_t pktbuf[MAX_NETDEV_PKTSIZE + CONFIG_NET_GUARDSIZE];
};

/*****************************************************************************
 * Private Data
 *****************************************************************************/

int g_ivshmnet_dev_count = 0;

struct ivshmnet_driver_s g_ivshmnet_devices[CONFIG_IVSHMNET_NINTERFACES];


/*****************************************************************************
 * Private Function Prototypes
 *****************************************************************************/

/* ivshm-net */

static void ivshmnet_state_change(void *in);
static void ivshmnet_set_state(struct ivshmnet_driver_s *in, uint32_t state);
static void ivshmnet_check_state(struct ivshmnet_driver_s *in);

/* Common TX logic */

static int  ivshmnet_transmit(FAR struct ivshmnet_driver_s *priv);
static int  ivshmnet_txpoll(FAR struct net_driver_s *dev);

/* Interrupt handling */

static void ivshmnet_reply(struct ivshmnet_driver_s *priv);
static void ivshmnet_receive(FAR struct ivshmnet_driver_s *priv);
static void ivshmnet_txdone(FAR struct ivshmnet_driver_s *priv);

static void ivshmnet_interrupt_work(FAR void *arg);
static int  ivshmnet_interrupt(int irq, FAR void *context, FAR void *arg);

/* Watchdog timer expirations */

static void ivshmnet_txtimeout_work(FAR void *arg);
static void ivshmnet_txtimeout_expiry(int argc, wdparm_t arg, ...);

static void ivshmnet_poll_work(FAR void *arg);
static void ivshmnet_poll_expiry(int argc, wdparm_t arg, ...);

/* NuttX callback functions */

static int  ivshmnet_ifup(FAR struct net_driver_s *dev);
static int  ivshmnet_ifdown(FAR struct net_driver_s *dev);

static void ivshmnet_txavail_work(FAR void *arg);
static int  ivshmnet_txavail(FAR struct net_driver_s *dev);

#if defined(CONFIG_NET_IGMP) || defined(CONFIG_NET_ICMPv6)
static int  ivshmnet_addmac(FAR struct net_driver_s *dev,
              FAR const uint8_t *mac);
#ifdef CONFIG_NET_IGMP
static int  ivshmnet_rmmac(FAR struct net_driver_s *dev,
              FAR const uint8_t *mac);
#endif
#ifdef CONFIG_NET_ICMPv6
static void ivshmnet_ipv6multicast(FAR struct ivshmnet_driver_s *priv);
#endif
#endif
#ifdef CONFIG_NETDEV_IOCTL
static int  ivshmnet_ioctl(FAR struct net_driver_s *dev, int cmd,
              unsigned long arg);
#endif

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/*****************************************
 *  ivshmem-net vring support functions  *
 *****************************************/

static void *ivshmnet_desc_data(
        struct ivshmnet_driver_s *in, struct ivshmnet_queue *q,
        unsigned int region,  struct vring_desc *desc,
        uint32_t *len)
{
  uint64_t offs = READ_ONCE(desc->addr);
  uint32_t dlen = READ_ONCE(desc->len);
  uint16_t flags = READ_ONCE(desc->flags);
  void *data;

  if (flags)
      return NULL;

  if (offs >= in->mem[region].size)
      return NULL;

  data = (void *)(in->mem[region].address + offs);

  if (data < q->data || data >= q->end)
      return NULL;

  if (dlen > q->end - data)
      return NULL;

  *len = dlen;

  return data;
}

static void ivshmnet_init_queue(
        struct ivshmnet_driver_s *in, struct ivshmnet_queue *q,
        void *mem, unsigned int len)
{
  memset(q, 0, sizeof(*q));

  vring_init(&q->vr, len, mem, IVSHMNET_VQ_ALIGN);
  q->data = mem + in->vrsize;
  q->end = q->data + in->qsize;
  q->size = in->qsize;
}

static void ivshmnet_init_queues(struct ivshmnet_driver_s *in)
{
  void *tx;
  void *rx;
  int i;
  void* tmp;

  tx = (void *)in->mem[IVSHMNET_SECTION_TX].address;
  rx = (void *)in->mem[IVSHMNET_SECTION_RX].address;

  memset(tx, 0, in->mem[IVSHMNET_SECTION_TX].size);

  ivshmnet_init_queue(in, &in->tx, tx, in->qlen);
  ivshmnet_init_queue(in, &in->rx, rx, in->qlen);

  tmp = in->rx.vr.used;
  in->rx.vr.used = in->tx.vr.used;
  in->tx.vr.used = tmp;

  in->tx.num_free = in->tx.vr.num;

  for (i = 0; i < in->tx.vr.num - 1; i++)
      in->tx.vr.desc[i].next = i + 1;
}

static int ivshmnet_calc_qsize(struct ivshmnet_driver_s *in)
{
  unsigned int vrsize;
  unsigned int qsize;
  unsigned int qlen;

  for (qlen = 4096; qlen > 32; qlen >>= 1)
    {
      vrsize = vring_size(qlen, IVSHMNET_VQ_ALIGN);
      vrsize = IVSHMNET_ALIGN(vrsize, IVSHMNET_VQ_ALIGN);
      if (vrsize < (in->mem[IVSHMNET_SECTION_TX].size) / 8)
          break;
    }

  if (vrsize > in->mem[IVSHMNET_SECTION_TX].size)
      return -EINVAL;

  qsize = in->mem[IVSHMNET_SECTION_TX].size - vrsize;

  if (qsize < 4 * IVSHMNET_MTU_MIN)
      return -EINVAL;

  in->vrsize = vrsize;
  in->qlen = qlen;
  in->qsize = qsize;

  return 0;
}

/*****************************************
 *  ivshmem-net IRQ support functions  *
 *****************************************/

static void ivshmnet_notify_tx(struct ivshmnet_driver_s *in, unsigned int num)
{
  uint16_t evt, old, new;

  mb();

  evt = READ_ONCE(vring_avail_event(&in->tx.vr));
  old = in->tx.last_avail_idx - num;
  new = in->tx.last_avail_idx;

  if (vring_need_event(evt, new, old))
    {
      in->regs->doorbell =
        ((uint32_t)in->peer_id << 16) | IVSHMNET_MSIX_TX_RX;
    }
}

static void ivshmnet_enable_rx_irq(struct ivshmnet_driver_s *in)
{
  vring_avail_event(&in->rx.vr) = in->rx.last_avail_idx;
  wmb();
}

static void ivshmnet_notify_rx(struct ivshmnet_driver_s *in, unsigned int num)
{
  uint16_t evt, old, new;

  mb();

  evt = vring_used_event(&in->rx.vr);
  old = in->rx.last_used_idx - num;
  new = in->rx.last_used_idx;

  if (vring_need_event(evt, new, old))
    {
      in->regs->doorbell =
        ((uint32_t)in->peer_id << 16) | IVSHMNET_MSIX_TX_RX;
    }
}

static void ivshmnet_enable_tx_irq(struct ivshmnet_driver_s *in)
{
  vring_used_event(&in->tx.vr) = in->tx.last_used_idx;
  wmb();
}

/*************************************
 *  ivshmem-net vring syntax sugars  *
 *************************************/

static struct vring_desc *ivshmnet_rx_desc(struct ivshmnet_driver_s *in)
{
  struct ivshmnet_queue *rx = &in->rx;
  struct vring *vr = &rx->vr;
  unsigned int avail;
  uint16_t avail_idx;

  avail_idx = virt_load_acquire(&vr->avail->idx);

  if (avail_idx == rx->last_avail_idx)
      return NULL;

  avail = vr->avail->ring[rx->last_avail_idx++ & (vr->num - 1)];
  if (avail >= vr->num)
    {
      nerr("invalid rx avail %d\n", avail);
      return NULL;
    }

  return &vr->desc[avail];
}

static bool ivshmnet_rx_avail(struct ivshmnet_driver_s *in)
{
  mb();
  return READ_ONCE(in->rx.vr.avail->idx) != in->rx.last_avail_idx;
}

static void ivshmnet_rx_finish(struct ivshmnet_driver_s *in, struct vring_desc *desc)
{
  struct ivshmnet_queue *rx = &in->rx;
  struct vring *vr = &rx->vr;
  unsigned int desc_id = desc - vr->desc;
  unsigned int used;

  used = rx->last_used_idx++ & (vr->num - 1);
  vr->used->ring[used].id = desc_id;
  vr->used->ring[used].len = 1;

  virt_store_release(&vr->used->idx, rx->last_used_idx);
}

static size_t ivshmnet_tx_space(struct ivshmnet_driver_s *in)
{
  struct ivshmnet_queue *tx = &in->tx;
  uint32_t tail = tx->tail;
  uint32_t head = tx->head;
  uint32_t space;

  if (head < tail)
      space = tail - head;
  else
      space = (tx->size - head) > tail ? (tx->size - head) : tail;

  return space;
}

static bool ivshmnet_tx_ok(struct ivshmnet_driver_s *in, unsigned int mtu)
{
  return in->tx.num_free >= 2 &&
      ivshmnet_tx_space(in) >= 2 * IVSHMNET_FRAME_SIZE(mtu);
}

static uint32_t ivshmnet_tx_advance(struct ivshmnet_queue *q, uint32_t *pos, uint32_t len)
{
  uint32_t p = *pos;

  len = IVSHMNET_FRAME_SIZE(len);

  if (q->size - p < len)
      p = 0;
  *pos = p + len;

  return p;
}

static int ivshmnet_tx_clean(struct ivshmnet_driver_s *in)
{
  struct ivshmnet_queue *tx = &in->tx;
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
          nerr("invalid tx used->id %d ->len %d\n",
                 used->id, used->len);
          break;
        }

      desc = &vr->desc[used->id];

      data = ivshmnet_desc_data(in, &in->tx, IVSHMNET_SECTION_TX,
                                desc, &len);
      if (!data)
        {
          nerr("bad tx descriptor, data == NULL\n");
          break;
        }

      tail = ivshmnet_tx_advance(tx, &tx->tail, len);
      if (data != tx->data + tail)
        {
          nerr("bad tx descriptor\n");
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

      tx_ok = ivshmnet_tx_ok(in, IVSHMNET_MTU_DEFAULT);
      if (!tx_ok)
          ivshmnet_enable_tx_irq(in);
  }

  if (num)
    {
      fdesc->next = tx->free_head;
      tx->free_head = fhead;
    }
  else
    {
      tx_ok = ivshmnet_tx_ok(in, IVSHMNET_MTU_DEFAULT);
    }

  return tx_ok;
}


static int ivshmnet_tx_frame(struct ivshmnet_driver_s *in, void* data, int len)
{
  struct ivshmnet_queue *tx = &in->tx;
  struct vring *vr = &tx->vr;
  struct vring_desc *desc;
  unsigned int desc_idx;
  unsigned int avail;
  uint32_t head;
  void *buf;

  unsigned int ret = ivshmnet_tx_clean(in);
  DEBUGASSERT(ret);

  desc_idx = tx->free_head;
  desc = &vr->desc[desc_idx];
  tx->free_head = desc->next;
  tx->num_free--;

  head = ivshmnet_tx_advance(tx, &tx->head, len);

  buf = tx->data + head;
  memcpy(buf, data, len);

  desc->addr = buf - (void *)in->mem[IVSHMNET_SECTION_TX].address;
  desc->len = len;
  desc->flags = 0;

  avail = tx->last_avail_idx++ & (vr->num - 1);
  vr->avail->ring[avail] = desc_idx;
  tx->num_added++;

  virt_store_release(&vr->avail->idx, tx->last_avail_idx);
  ivshmnet_notify_tx(in, tx->num_added);
  tx->num_added = 0;

  return 0;
}

/*****************************************
 *  ivshmem-net support functions  *
 *****************************************/

static void ivshmnet_run(struct ivshmnet_driver_s *in)
{
  irqstate_t flags;

  if (in->state < IVSHMNET_STATE_READY)
      return;

  /* test_and_set_bit */
  flags = enter_critical_section();
  if(in->flags & IVSHMNET_FLAG_RUN)
    {
      in->flags |= IVSHMNET_FLAG_RUN;
      leave_critical_section(flags);
      return;
    }

  in->flags |= IVSHMNET_FLAG_RUN;
  leave_critical_section(flags);

  ivshmnet_set_state(in, IVSHMNET_STATE_RUN);
  in->sk_bifup = true;

  return;
}

static void ivshmnet_do_stop(struct ivshmnet_driver_s *in)
{
  irqstate_t flags;

  in->sk_bifup = false;

  ivshmnet_set_state(in, IVSHMNET_STATE_RESET);

  /* test_and_clear_bit */
  flags = enter_critical_section();
  if(!(in->flags & IVSHMNET_FLAG_RUN))
    {
      in->flags &= ~IVSHMNET_FLAG_RUN;
      leave_critical_section(flags);
      return;
    }

  in->flags &= ~IVSHMNET_FLAG_RUN;
  leave_critical_section(flags);

  return;
}

/****************************************************************************
 * State Machine
 ****************************************************************************/

static void ivshmnet_state_change(void *arg)
{
  struct ivshmnet_driver_s *in = (struct ivshmnet_driver_s*)arg;
  uint32_t peer_state = READ_ONCE(in->state_table[in->peer_id]);

  ninfo("Remote state: %d\n", peer_state);

  switch (in->state)
    {
      case IVSHMNET_STATE_RESET:
          if (peer_state < IVSHMNET_STATE_READY)
              ivshmnet_set_state(in, IVSHMNET_STATE_INIT);
          break;

      case IVSHMNET_STATE_INIT:
          if (peer_state > IVSHMNET_STATE_RESET)
            {
              ivshmnet_init_queues(in);
              ivshmnet_set_state(in, IVSHMNET_STATE_READY);
            }
          break;

      case IVSHMNET_STATE_READY:
          if (peer_state >= IVSHMNET_STATE_READY)
            {
              ivshmnet_run(in);
              break;
            }
      case IVSHMNET_STATE_RUN:
          if (peer_state == IVSHMNET_STATE_RESET)
            {
              ivshmnet_do_stop(in);
            }
          break;
    }

  wmb();
  WRITE_ONCE(in->last_peer_state, peer_state);
}

static void ivshmnet_set_state(struct ivshmnet_driver_s *in, uint32_t state)
{
  wmb();
  WRITE_ONCE(in->state, state);
  WRITE_ONCE(in->regs->state, state);
}

static void ivshmnet_check_state(struct ivshmnet_driver_s *in)
{
  irqstate_t flags;

  flags = enter_critical_section();

  /* test_bit */
  if (in->state_table[in->peer_id] != in->last_peer_state ||
      !(IVSHMNET_FLAG_RUN & in->flags))
      work_queue(ETHWORK, &in->sk_statework, ivshmnet_state_change, in, 0);

  leave_critical_section(flags);
}

/****************************************************************************
 * State IRQ Handlers
 ****************************************************************************/

static int ivshmnet_state_handler(int irq, uint32_t *regs, void *arg)
{
  struct ivshmnet_driver_s *priv = arg;

  ivshmnet_check_state(priv);

  return 0;
}

#if 0
static void dump_ethernet_frame(void *data, int len){
    uint8_t* ptr8 = data;
    uint16_t* ptr16 = data;
    uint32_t* ptrip = (uint32_t*)(ptr8 + 14);
    uint16_t etype;

    ninfo("======= Dumping Ethernet Frame =======\n");
    ninfo("Dest MAC: %x:%x:%x:%x:%x:%x\n", ptr8[0], ptr8[1], ptr8[2], ptr8[3], ptr8[4], ptr8[5]);
    ninfo("Src  MAC: %x:%x:%x:%x:%x:%x\n", ptr8[6], ptr8[7], ptr8[8], ptr8[9], ptr8[10], ptr8[11]);
    etype = bswap16(ptr16[6]);
    ninfo("Ether Type: 0x%x\n", etype);
    if(etype == 0x806) // ARP
    {
      ninfo("------- Begin ARP Frame -------\n");
      ninfo("HW type: 0x%lx, Proto type: 0x%lx\n", bswap16((ptrip[0]) & 0xffff), bswap16((ptrip[0] >> 16) & 0xffff));
      ninfo("HW addr len: 0x%lx, Proto addr len: 0x%lx\n", (ptrip[1]) & 0xff, (ptrip[1] >> 8) & 0xff);
      ninfo("Operation: 0x%lx\n", bswap16((ptrip[1] >> 16) & 0xffff));
      ninfo("Sender hardware address: %x:%x:%x:%x:%x:%x\n",
              (ptrip[2]) & 0xff,
              (ptrip[2] >> 8) & 0xff,
              (ptrip[2] >> 16) & 0xff,
              (ptrip[2] >> 24) & 0xff,
              (ptrip[3]) & 0xff,
              (ptrip[3] >> 8) & 0xff
              );
      ninfo("Sender protocol address: %x:%x:%x:%x\n",
              (ptrip[3] >> 16) & 0xff,
              (ptrip[3] >> 24) & 0xff,
              (ptrip[4]) & 0xff,
              (ptrip[4] >> 8) & 0xff
              );
      ninfo("Target hardware address: %x:%x:%x:%x:%x:%x\n",
              (ptrip[4] >> 16) & 0xff,
              (ptrip[4] >> 24) & 0xff,
              (ptrip[5]) & 0xff,
              (ptrip[5] >> 8) & 0xff,
              (ptrip[5] >> 16) & 0xff,
              (ptrip[5] >> 24) & 0xff
              );
      ninfo("Target protocol address: %x:%x:%x:%x\n",
              (ptrip[6]) & 0xff,
              (ptrip[6] >> 8) & 0xff,
              (ptrip[6] >> 16) & 0xff,
              (ptrip[6] >> 24) & 0xff
              );
    }
    else if(etype == 0x800) //IPV4
    {
      ninfo("------- Begin IP Frame -------\n");
      ninfo("Version: %d, Hdr len: 0x%lx\n", (ptrip[0] >> 4) & 0xf, hdr_len);
      ninfo("Diff Service: 0x%lx\n", (ptrip[0] >> 8) & 0xff);
      ninfo("Total Length: 0x%lx\n", (ptrip[0] >> 16) & 0xffff);
      ninfo("Identification: 0x%lx\n", (ptrip[1]) & 0xffff);
      ninfo("Flags: 0x%lx, Frags: 0x%lx\n", (ptrip[1] >> 16) & 0x7, bswap16((ptrip[1] >> 16) & 0xffff) & 0x1fff);
      ninfo("TTL: %d, Protocol: 0x%lx\n", (ptrip[2]) & 0xff, (ptrip[2] >> 8) & 0xff);
      ninfo("Hdr checksum: 0x%lx\n", (ptrip[2] >> 16) & 0xffff);
      ninfo("Src  address: %d.%d.%d.%d\n", (ptrip[3]) & 0xff, (ptrip[3] >> 8) & 0xff, (ptrip[3] >> 16) & 0xff, (ptrip[3] >> 24) & 0xff);
      ninfo("Dest address: %d.%d.%d.%d\n", (ptrip[4]) & 0xff, (ptrip[4] >> 8) & 0xff, (ptrip[4] >> 16) & 0xff, (ptrip[4] >> 24) & 0xff);

      ninfo("Src  port: %d\n", bswap16(ptrip[hdr_len]) & 0xffff);
      ninfo("Dest port: %d\n", bswap16(ptrip[hdr_len] >> 16) & 0xffff);
    }

    return;
}
#else

#define dump_ethernet_frame(data, len)

#endif

/****************************************************************************
 * Name: ivshmnet_transmit
 *
 * Description:
 *   Start hardware transmission.  Called either from the txdone interrupt
 *   handling or from watchdog based polling.
 *
 * Input Parameters:
 *   priv - Reference to the driver state structure
 *
 * Returned Value:
 *   OK on success; a negated errno on failure
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

static int ivshmnet_transmit(FAR struct ivshmnet_driver_s *priv)
{
  /* Verify that the hardware is ready to send another packet.  If we get
   * here, then we are committed to sending a packet; Higher level logic
   * must have assured that there is no transmission in progress.
   */

  /* Increment statistics */

  NETDEV_TXPACKETS(priv->sk_dev);

  /* Send the packet: address=priv->sk_dev.d_buf, length=priv->sk_dev.d_len */
  ivshmnet_tx_clean(priv);

  ASSERT(ivshmnet_tx_ok(priv, IVSHMNET_MTU_DEFAULT));

  ivshmnet_tx_frame(priv, priv->sk_dev.d_buf, priv->sk_dev.d_len);

  /* Enable Tx interrupts */
  ivshmnet_enable_tx_irq(priv);

  /* Setup the TX timeout watchdog (perhaps restarting the timer) */
  (void)wd_start(priv->sk_txtimeout, IVSHMNET_TXTIMEOUT,
                 ivshmnet_txtimeout_expiry, 1, (wdparm_t)priv);
  return OK;
}

/****************************************************************************
 * Name: ivshmnet_txpoll
 *
 * Description:
 *   The transmitter is available, check if the network has any outgoing
 *   packets ready to send.  This is a callback from devif_poll().
 *   devif_poll() may be called:
 *
 *   1. When the preceding TX packet send is complete,
 *   2. When the preceding TX packet send timesout and the interface is reset
 *   3. During normal TX polling
 *
 * Input Parameters:
 *   dev - Reference to the NuttX driver state structure
 *
 * Returned Value:
 *   OK on success; a negated errno on failure
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

static int ivshmnet_txpoll(FAR struct net_driver_s *dev)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)dev->d_private;

  /* If the polling resulted in data that should be sent out on the network,
   * the field d_len is set to a value > 0.
   */

  if (priv->sk_dev.d_len > 0)
    {
      /* Look up the destination MAC address and add it to the Ethernet
       * header.
       */

#ifdef CONFIG_NET_IPv4
#ifdef CONFIG_NET_IPv6
      if (IFF_IS_IPv4(priv->sk_dev.d_flags))
#endif
        {
          arp_out(&priv->sk_dev);
        }
#endif /* CONFIG_NET_IPv4 */

#ifdef CONFIG_NET_IPv6
#ifdef CONFIG_NET_IPv4
      else
#endif
        {
          neighbor_out(&priv->sk_dev);
        }
#endif /* CONFIG_NET_IPv6 */

      /* Send the packet */

      ivshmnet_transmit(priv);

      /* Check if there is room in the device to hold another packet. If not,
       * return a non-zero value to terminate the poll.
       */
    }

  /* If zero is returned, the polling will continue until all connections have
   * been examined.
   */

  return 0;
}

/****************************************************************************
 * Name: ivshmnet_reply
 *
 * Description:
 *   After a packet has been received and dispatched to the network, it
 *   may return return with an outgoing packet.  This function checks for
 *   that case and performs the transmission if necessary.
 *
 * Input Parameters:
 *   priv - Reference to the driver state structure
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

static void ivshmnet_reply(struct ivshmnet_driver_s *priv)
{
  /* If the packet dispatch resulted in data that should be sent out on the
   * network, the field d_len will set to a value > 0.
   */

  if (priv->sk_dev.d_len > 0)
    {
      /* Update the Ethernet header with the correct MAC address */

#ifdef CONFIG_NET_IPv4
#ifdef CONFIG_NET_IPv6
      /* Check for an outgoing IPv4 packet */

      if (IFF_IS_IPv4(priv->sk_dev.d_flags))
#endif
        {
          arp_out(&priv->sk_dev);
        }
#endif

#ifdef CONFIG_NET_IPv6
#ifdef CONFIG_NET_IPv4
      /* Otherwise, it must be an outgoing IPv6 packet */

      else
#endif
        {
          neighbor_out(&ivshmnet->sk_dev);
        }
#endif

      /* And send the packet */

      ivshmnet_transmit(priv);
    }
}

/****************************************************************************
 * Name: ivshmnet_receive
 *
 * Description:
 *   An interrupt was received indicating the availability of a new RX packet
 *
 * Input Parameters:
 *   priv - Reference to the driver state structure
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

static void ivshmnet_receive(FAR struct ivshmnet_driver_s *priv)
{
  int received = 0;

  do
    {
      struct vring_desc *desc;
      void *data;
      uint32_t len;

      /* Check for errors and update statistics */
      ninfo("processing receive\n");

      desc = ivshmnet_rx_desc(priv); /* get next avail rx descriptor from avail ring */
      if (!desc)
        break;

      data = ivshmnet_desc_data(priv, &priv->rx, IVSHMNET_SECTION_RX,
                   desc, &len); /* Unpack descriptor and get the physical address in SHMEM and fill in len */
      if (!data) {
        nerr("bad rx descriptor\n");
        break;
      }

      dump_ethernet_frame(data, len);

      /* Check if the packet is a valid size for the network buffer
       * configuration.
       */

      /* Copy the data data from the hardware to priv->sk_dev.d_buf.  Set
       * amount of data in priv->sk_dev.d_len
       */
      memcpy(priv->sk_dev.d_buf, data, len);
      priv->sk_dev.d_len = len;

      ivshmnet_rx_finish(priv, desc); /* Release the read descriptor in to the used ring */

#ifdef CONFIG_NET_PKT
      /* When packet sockets are enabled, feed the frame into the packet tap */

       pkt_input(&priv->sk_dev);
#endif

#ifdef CONFIG_NET_IPv4
      /* Check for an IPv4 packet */

      if (BUF->type == HTONS(ETHTYPE_IP))
        {
          ninfo("IPv4 frame\n");
          NETDEV_RXIPV4(&priv->sk_dev);

          /* Handle ARP on input, then dispatch IPv4 packet to the network
           * layer.
           */

          arp_ipin(&priv->sk_dev);
          ipv4_input(&priv->sk_dev);

          /* Check for a reply to the IPv4 packet */

          ivshmnet_reply(priv);
        }
      else
#endif
#ifdef CONFIG_NET_IPv6
      /* Check for an IPv6 packet */

      if (BUF->type == HTONS(ETHTYPE_IP6))
        {
          ninfo("Iv6 frame\n");
          NETDEV_RXIPV6(&priv->sk_dev);

          /* Dispatch IPv6 packet to the network layer */

          ipv6_input(&priv->sk_dev);

          /* Check for a reply to the IPv6 packet */

          ivshmnet_reply(priv);
        }
      else
#endif
#ifdef CONFIG_NET_ARP
      /* Check for an ARP packet */

      if (BUF->type == htons(ETHTYPE_ARP))
        {
          /* Dispatch ARP packet to the network layer */

          arp_arpin(&priv->sk_dev);
          NETDEV_RXARP(&priv->sk_dev);

          /* If the above function invocation resulted in data that should be
           * sent out on the network, the field  d_len will set to a value > 0.
           */

          if (priv->sk_dev.d_len > 0)
            {
              ivshmnet_transmit(priv);
            }
        }
      else
#endif
        {
          NETDEV_RXDROPPED(&priv->sk_dev);
        }
      received++;
    }
  while (true); /* Whether are there more packets to be processed is checked above */

  ivshmnet_enable_rx_irq(priv); /* enable the irq by writing the last avail index to the end of the ring */
  if (ivshmnet_rx_avail(priv)) /* More stuff to read?, which is very unlikely*/
    work_queue(ETHWORK, &priv->sk_irqwork, ivshmnet_interrupt_work, priv, 0); /* schedule the work again */

  if (received)
    ivshmnet_notify_rx(priv, received); /* We had did some work, notify we had rx the data by triggering door bell*/
}

/****************************************************************************
 * Name: ivshmnet_txdone
 *
 * Description:
 *   An interrupt was received indicating that the last TX packet(s) is done
 *
 * Input Parameters:
 *   priv - Reference to the driver state structure
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

static void ivshmnet_txdone(FAR struct ivshmnet_driver_s *priv)
{
  /* Check for errors and update statistics */

  NETDEV_TXDONE(priv->sk_dev);

  /* Check if there are pending transmissions */

  /* If no further transmissions are pending, then cancel the TX timeout and
   * disable further Tx interrupts.
   */

  wd_cancel(priv->sk_txtimeout);

  /* And disable further TX interrupts. */

  /* In any event, poll the network for new TX data */

  (void)devif_poll(&priv->sk_dev, ivshmnet_txpoll);
}

/****************************************************************************
 * Name: ivshmnet_interrupt_work
 *
 * Description:
 *   Perform interrupt related work from the worker thread
 *
 * Input Parameters:
 *   arg - The argument passed when work_queue() was called.
 *
 * Returned Value:
 *   OK on success
 *
 * Assumptions:
 *   Runs on a worker thread.
 *
 ****************************************************************************/

static void ivshmnet_interrupt_work(FAR void *arg)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)arg;

  /* Lock the network and serialize driver operations if necessary.
   * NOTE: Serialization is only required in the case where the driver work
   * is performed on an LP worker thread and where more than one LP worker
   * thread has been configured.
   */

  ninfo("processing int\n");

  net_lock();

  /* Process pending Ethernet interrupts */

  /* Get and clear interrupt status bits */

  /*ivshmnet_tx_clean(priv);*/

  /* Handle interrupts according to status bit settings */

  /* Check if we received an incoming packet, if so, call ivshmnet_receive() */
  if(ivshmnet_rx_avail(priv))
    {

      ivshmnet_receive(priv);
    }
  else
    {
      /* Check if a packet transmission just completed.  If so, call ivshmnet_txdone.
       * This may disable further Tx interrupts if there are no pending
       * transmissions.
       */

      /* XXX: Assuming single interrupt only represent TX or RX might not be a good idea */

      ivshmnet_txdone(priv);
    }

  net_unlock();

  /* Re-enable Ethernet interrupts */

  /*up_enable_irq(CONFIG_IVSHMEM_NET_IRQ);*/
}

/****************************************************************************
 * Name: ivshmnet_interrupt
 *
 * Description:
 *   Hardware interrupt handler
 *
 * Input Parameters:
 *   irq     - Number of the IRQ that generated the interrupt
 *   context - Interrupt register state save info (architecture-specific)
 *
 * Returned Value:
 *   OK on success
 *
 * Assumptions:
 *   Runs in the context of a the Ethernet interrupt handler.  Local
 *   interrupts are disabled by the interrupt logic.
 *
 ****************************************************************************/

static int ivshmnet_interrupt(int irq, FAR void *context, FAR void *arg)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)arg;

  DEBUGASSERT(priv != NULL);

  /* Disable further Ethernet interrupts.  Because Ethernet interrupts are
   * also disabled if the TX timeout event occurs, there can be no race
   * condition here.
   */

  /*up_disable_irq(CONFIG_IVSHMEM_NET_IRQ);*/

  /* TODO: Determine if a TX transfer just completed */

    {
      /* If a TX transfer just completed, then cancel the TX timeout so
       * there will be no race condition between any subsequent timeout
       * expiration and the deferred interrupt processing.
       */

       /*wd_cancel(priv->sk_txtimeout);*/
    }

  /* Schedule to perform the interrupt processing on the worker thread. */

  work_queue(ETHWORK, &priv->sk_irqwork, ivshmnet_interrupt_work, priv, 0);
  return OK;
}

/****************************************************************************
 * Name: ivshmnet_txtimeout_work
 *
 * Description:
 *   Perform TX timeout related work from the worker thread
 *
 * Input Parameters:
 *   arg - The argument passed when work_queue() as called.
 *
 * Returned Value:
 *   OK on success
 *
 ****************************************************************************/

static void ivshmnet_txtimeout_work(FAR void *arg)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)arg;

  /* Lock the network and serialize driver operations if necessary.
   * NOTE: Serialization is only required in the case where the driver work
   * is performed on an LP worker thread and where more than one LP worker
   * thread has been configured.
   */

  net_lock();

  /* Increment statistics and dump debug info */

  NETDEV_TXTIMEOUTS(priv->sk_dev);

  /* Then reset the hardware */

  /* Then poll the network for new XMIT data */

  (void)devif_poll(&priv->sk_dev, ivshmnet_txpoll);
  net_unlock();
}

/****************************************************************************
 * Name: ivshmnet_txtimeout_expiry
 *
 * Description:
 *   Our TX watchdog timed out.  Called from the timer interrupt handler.
 *   The last TX never completed.  Reset the hardware and start again.
 *
 * Input Parameters:
 *   argc - The number of available arguments
 *   arg  - The first argument
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   Runs in the context of a the timer interrupt handler.  Local
 *   interrupts are disabled by the interrupt logic.
 *
 ****************************************************************************/

static void ivshmnet_txtimeout_expiry(int argc, wdparm_t arg, ...)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)arg;

  /* Disable further Ethernet interrupts.  This will prevent some race
   * conditions with interrupt work.  There is still a potential race
   * condition with interrupt work that is already queued and in progress.
   */

  /*up_disable_irq(CONFIG_IVSHMEM_NET_IRQ);*/

  /* Schedule to perform the TX timeout processing on the worker thread. */

  work_queue(ETHWORK, &priv->sk_irqwork, ivshmnet_txtimeout_work, priv, 0);
}

/****************************************************************************
 * Name: ivshmnet_poll_work
 *
 * Description:
 *   Perform periodic polling from the worker thread
 *
 * Input Parameters:
 *   arg - The argument passed when work_queue() as called.
 *
 * Returned Value:
 *   OK on success
 *
 * Assumptions:
 *   Run on a work queue thread.
 *
 ****************************************************************************/

static void ivshmnet_poll_work(FAR void *arg)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)arg;

  /* Lock the network and serialize driver operations if necessary.
   * NOTE: Serialization is only required in the case where the driver work
   * is performed on an LP worker thread and where more than one LP worker
   * thread has been configured.
   */

  net_lock();

  /* Perform the poll */

  /* Check if there is room in the send another TX packet.  We cannot perform
   * the TX poll if he are unable to accept another packet for transmission.
   */

  /* If so, update TCP timing states and poll the network for new XMIT data.
   * Hmmm.. might be bug here.  Does this mean if there is a transmit in
   * progress, we will missing TCP time state updates?
   */

  (void)devif_timer(&priv->sk_dev, IVSHMNET_WDDELAY, ivshmnet_txpoll);

  /* Setup the watchdog poll timer again */

  (void)wd_start(priv->sk_txpoll, IVSHMNET_WDDELAY, ivshmnet_poll_expiry, 1,
                 (wdparm_t)priv);
  net_unlock();
}

/****************************************************************************
 * Name: ivshmnet_poll_expiry
 *
 * Description:
 *   Periodic timer handler.  Called from the timer interrupt handler.
 *
 * Input Parameters:
 *   argc - The number of available arguments
 *   arg  - The first argument
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   Runs in the context of a the timer interrupt handler.  Local
 *   interrupts are disabled by the interrupt logic.
 *
 ****************************************************************************/

static void ivshmnet_poll_expiry(int argc, wdparm_t arg, ...)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)arg;

  /* Schedule to perform the interrupt processing on the worker thread. */

  work_queue(ETHWORK, &priv->sk_pollwork, ivshmnet_poll_work, priv, 0);
}

/****************************************************************************
 * Name: ivshmnet_ifup
 *
 * Description:
 *   NuttX Callback: Bring up the Ethernet interface when an IP address is
 *   provided
 *
 * Input Parameters:
 *   dev - Reference to the NuttX driver state structure
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

static int ivshmnet_ifup(FAR struct net_driver_s *dev)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)dev->d_private;

#ifdef CONFIG_NET_IPv4
  ninfo("Bringing up: %d.%d.%d.%d\n",
        dev->d_ipaddr & 0xff, (dev->d_ipaddr >> 8) & 0xff,
        (dev->d_ipaddr >> 16) & 0xff, dev->d_ipaddr >> 24);
#endif
#ifdef CONFIG_NET_IPv6
  ninfo("Bringing up: %04x:%04x:%04x:%04x:%04x:%04x:%04x:%04x\n",
        dev->d_ipv6addr[0], dev->d_ipv6addr[1], dev->d_ipv6addr[2],
        dev->d_ipv6addr[3], dev->d_ipv6addr[4], dev->d_ipv6addr[5],
        dev->d_ipv6addr[6], dev->d_ipv6addr[7]);
#endif

  priv->regs->int_control = JH_IVSHMEM_INT_EN;
  priv->regs->state = IVSHMNET_STATE_RESET;
  priv->state = IVSHMNET_STATE_RESET;
  ivshmnet_check_state(priv);

  /* Instantiate the MAC address from priv->sk_dev.d_mac.ether.ether_addr_octet */

#ifdef CONFIG_NET_ICMPv6
  /* Set up IPv6 multicast address filtering */

  ivshmnet_ipv6multicast(priv);
#endif

  /* Set and activate a timer process */

  (void)wd_start(priv->sk_txpoll, IVSHMNET_WDDELAY, ivshmnet_poll_expiry, 1,
                 (wdparm_t)priv);

  /* Enable the Ethernet interrupt */

  return OK;
}

/****************************************************************************
 * Name: ivshmnet_ifdown
 *
 * Description:
 *   NuttX Callback: Stop the interface.
 *
 * Input Parameters:
 *   dev - Reference to the NuttX driver state structure
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

static int ivshmnet_ifdown(FAR struct net_driver_s *dev)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)dev->d_private;
  irqstate_t flags;

  /* Disable the Ethernet interrupt */

  flags = enter_critical_section();

  priv->regs->int_control &= ~JH_IVSHMEM_INT_EN;
  priv->regs->state = IVSHMNET_STATE_RESET;

  /* Cancel the TX poll timer and TX timeout timers */

  wd_cancel(priv->sk_txpoll);
  wd_cancel(priv->sk_txtimeout);

  /* Put the EMAC in its reset, non-operational state.  This should be
   * a known configuration that will guarantee the ivshmnet_ifup() always
   * successfully brings the interface back up.
   */

  /* Mark the device "down" */

  priv->sk_bifup = false;
  leave_critical_section(flags);
  return OK;
}

/****************************************************************************
 * Name: ivshmnet_txavail_work
 *
 * Description:
 *   Perform an out-of-cycle poll on the worker thread.
 *
 * Input Parameters:
 *   arg - Reference to the NuttX driver state structure (cast to void*)
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   Runs on a work queue thread.
 *
 ****************************************************************************/

static void ivshmnet_txavail_work(FAR void *arg)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)arg;

  /* Lock the network and serialize driver operations if necessary.
   * NOTE: Serialization is only required in the case where the driver work
   * is performed on an LP worker thread and where more than one LP worker
   * thread has been configured.
   */

  net_lock();

  /* Ignore the notification if the interface is not yet up */

  if (priv->sk_bifup)
    {
      /* Check if there is room in the hardware to hold another outgoing packet. */

      /* If so, then poll the network for new XMIT data */

      (void)devif_poll(&priv->sk_dev, ivshmnet_txpoll);
    }

  net_unlock();
}

/****************************************************************************
 * Name: ivshmnet_txavail
 *
 * Description:
 *   Driver callback invoked when new TX data is available.  This is a
 *   stimulus perform an out-of-cycle poll and, thereby, reduce the TX
 *   latency.
 *
 * Input Parameters:
 *   dev - Reference to the NuttX driver state structure
 *
 * Returned Value:
 *   None
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

static int ivshmnet_txavail(FAR struct net_driver_s *dev)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)dev->d_private;

  /* Is our single work structure available?  It may not be if there are
   * pending interrupt actions and we will have to ignore the Tx
   * availability action.
   */

  if (work_available(&priv->sk_pollwork))
    {
      /* Schedule to serialize the poll on the worker thread. */

      work_queue(ETHWORK, &priv->sk_pollwork, ivshmnet_txavail_work, priv, 0);
    }

  return OK;
}

/****************************************************************************
 * Name: ivshmnet_addmac
 *
 * Description:
 *   NuttX Callback: Add the specified MAC address to the hardware multicast
 *   address filtering
 *
 * Input Parameters:
 *   dev  - Reference to the NuttX driver state structure
 *   mac  - The MAC address to be added
 *
 * Returned Value:
 *   Zero (OK) on success; a negated errno value on failure.
 *
 ****************************************************************************/

#if defined(CONFIG_NET_IGMP) || defined(CONFIG_NET_ICMPv6)
static int ivshmnet_addmac(FAR struct net_driver_s *dev, FAR const uint8_t *mac)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)dev->d_private;

  /* Add the MAC address to the hardware multicast routing table */

  return OK;
}
#endif

/****************************************************************************
 * Name: ivshmnet_rmmac
 *
 * Description:
 *   NuttX Callback: Remove the specified MAC address from the hardware multicast
 *   address filtering
 *
 * Input Parameters:
 *   dev  - Reference to the NuttX driver state structure
 *   mac  - The MAC address to be removed
 *
 * Returned Value:
 *   Zero (OK) on success; a negated errno value on failure.
 *
 ****************************************************************************/

#ifdef CONFIG_NET_IGMP
static int ivshmnet_rmmac(FAR struct net_driver_s *dev, FAR const uint8_t *mac)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)dev->d_private;

  /* Add the MAC address to the hardware multicast routing table */

  return OK;
}
#endif

/****************************************************************************
 * Name: ivshmnet_ipv6multicast
 *
 * Description:
 *   Configure the IPv6 multicast MAC address.
 *
 * Input Parameters:
 *   priv - A reference to the private driver state structure
 *
 * Returned Value:
 *   Zero (OK) on success; a negated errno value on failure.
 *
 ****************************************************************************/

#ifdef CONFIG_NET_ICMPv6
static void ivshmnet_ipv6multicast(FAR struct ivshmnet_driver_s *priv)
{
  FAR struct net_driver_s *dev;
  uint16_t tmp16;
  uint8_t mac[6];

  /* For ICMPv6, we need to add the IPv6 multicast address
   *
   * For IPv6 multicast addresses, the Ethernet MAC is derived by
   * the four low-order octets OR'ed with the MAC 33:33:00:00:00:00,
   * so for example the IPv6 address FF02:DEAD:BEEF::1:3 would map
   * to the Ethernet MAC address 33:33:00:01:00:03.
   *
   * NOTES:  This appears correct for the ICMPv6 Router Solicitation
   * Message, but the ICMPv6 Neighbor Solicitation message seems to
   * use 33:33:ff:01:00:03.
   */

  mac[0] = 0x33;
  mac[1] = 0x33;

  dev    = &priv->dev;
  tmp16  = dev->d_ipv6addr[6];
  mac[2] = 0xff;
  mac[3] = tmp16 >> 8;

  tmp16  = dev->d_ipv6addr[7];
  mac[4] = tmp16 & 0xff;
  mac[5] = tmp16 >> 8;

  ninfo("IPv6 Multicast: %02x:%02x:%02x:%02x:%02x:%02x\n",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

  (void)ivshmnet_addmac(dev, mac);

#ifdef CONFIG_NET_ICMPv6_AUTOCONF
  /* Add the IPv6 all link-local nodes Ethernet address.  This is the
   * address that we expect to receive ICMPv6 Router Advertisement
   * packets.
   */

  (void)ivshmnet_addmac(dev, g_ipv6_ethallnodes.ether_addr_octet);

#endif /* CONFIG_NET_ICMPv6_AUTOCONF */

#ifdef CONFIG_NET_ICMPv6_ROUTER
  /* Add the IPv6 all link-local routers Ethernet address.  This is the
   * address that we expect to receive ICMPv6 Router Solicitation
   * packets.
   */

  (void)ivshmnet_addmac(dev, g_ipv6_ethallrouters.ether_addr_octet);

#endif /* CONFIG_NET_ICMPv6_ROUTER */
}
#endif /* CONFIG_NET_ICMPv6 */

/****************************************************************************
 * Name: ivshmnet_ioctl
 *
 * Description:
 *   Handle network IOCTL commands directed to this device.
 *
 * Input Parameters:
 *   dev - Reference to the NuttX driver state structure
 *   cmd - The IOCTL command
 *   arg - The argument for the IOCTL command
 *
 * Returned Value:
 *   OK on success; Negated errno on failure.
 *
 * Assumptions:
 *   The network is locked.
 *
 ****************************************************************************/

#ifdef CONFIG_NETDEV_IOCTL
static int ivshmnet_ioctl(FAR struct net_driver_s *dev, int cmd,
                      unsigned long arg)
{
  FAR struct ivshmnet_driver_s *priv = (FAR struct ivshmnet_driver_s *)dev->d_private;
  int ret;

  /* Decode and dispatch the driver-specific IOCTL command */

  switch (cmd)
    {
      /* Add cases here to support the IOCTL commands */

      default:
        nerr("ERROR: Unrecognized IOCTL command: %d\n", command);
        return -ENOTTY;  /* Special return value for this case */
    }

  return OK;
}
#endif

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: ivshmnet_probe
 *
 * Description:
 *   Initialize the Ethernet controller and driver
 *
 * Input Parameters:
 *   intf - In the case where there are multiple EMACs, this value
 *          identifies which EMAC is to be initialized.
 *
 * Returned Value:
 *   OK on success; Negated errno on failure.
 *
 * Assumptions:
 *   Called early in initialization before multi-tasking is initiated.
 *
 ****************************************************************************/

int ivshmnet_probe(FAR struct pci_bus_s *bus,
                   FAR struct pci_dev_type_s *type, uint16_t bdf)
{
  int vndr_cap;
  int msix_cap;
  uint8_t vndr_length;
  uint32_t io_section_size;
  uintptr_t rw_section_addr;
  uintptr_t io_section_addr;
  struct ivshmem_mem_region_s *mem;
  struct ivshmnet_driver_s *dev = g_ivshmnet_devices + g_ivshmnet_dev_count;

  if (g_ivshmnet_dev_count >= CONFIG_IVSHMNET_NINTERFACES)
    {
      pcierr("Probed too many ivshmem-net devices!\n");
    }

  memset(dev, 0, sizeof(struct ivshmnet_driver_s));

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

  pciinfo("Ivshmem-net[%d] mapped bar[0]: %p\n",
          g_ivshmnet_dev_count, dev->regs);

  pciinfo("Ivshmem-net[%d] mapped bar[1]: %p\n",
          g_ivshmnet_dev_count, dev->msix_table);

  if (!dev->regs || !dev->msix_table)
    {
      pcierr("Failed to map ivshmem-net bars!\n");
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
      pcierr("Ivshmem[%d] missing vendor capability\n", g_ivshmnet_dev_count);
      return -ENODEV;
    }

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

  dev->state_table = (volatile uint32_t *)mem->address;

  pciinfo("Ivshmem-net[%d] State Table phy_addr:"
          "0x%lx virt_addr: 0x%lx, size: 0x%lx\n",
          g_ivshmnet_dev_count, mem->paddress, mem->address, mem->size);

  mem++;

  rw_section_addr = (mem - 1)->paddress + (mem - 1)->size;

  io_section_addr = rw_section_addr +
    (pci_cfg_read(&dev->dev, vndr_cap + JH_IVSHMEM_VND_RW_SIZE, 4));

  io_section_size =
        (pci_cfg_read(&dev->dev, vndr_cap + JH_IVSHMEM_VND_IO_SIZE, 4));

  if (!io_section_size)
    {
      pcierr("Ivshmem-net[%d] I/O region does not exist");
    }

  mem->paddress = io_section_addr + (!dev->peer_id) * io_section_size;
  mem->size = io_section_size;
  mem->readonly = false;

  mem->address =
    (uintptr_t)pci_ioremap(&dev->dev, mem->paddress, mem->size);
  if (!mem->address)
    {
      pciinfo("TX region mapping failed");
      return -EBUSY;
    }

  pciinfo("Ivshmem-net[%d] TX region phy_addr: " \
          "0x%lx virt_addr: 0x%lx, size: 0x%lx\n",
           g_ivshmnet_dev_count, mem->paddress, mem->address, mem->size);

  memset((void *)mem->address, 0, mem->size);

  mem++;

  mem->paddress = io_section_addr + (!!dev->peer_id) * io_section_size;
  mem->size = io_section_size;
  mem->readonly = true;

  mem->address =
    (uintptr_t)pci_ioremap(&dev->dev, mem->paddress, mem->size);
  if (!mem->address)
      return -EBUSY;

  pciinfo("Ivshmem-net[%d] RX region phy_addr: " \
          "0x%lx virt_addr: 0x%lx, size: 0x%lx\n",
           g_ivshmnet_dev_count, mem->paddress, mem->address, mem->size);

  pci_cfg_write(&dev->dev, vndr_cap + JH_IVSHMEM_VND_PCTL, 0, 1);

  msix_cap = pci_find_cap(&dev->dev, PCI_CAP_MSIX);

  dev->vectors =
    (pci_cfg_read(&dev->dev, msix_cap + PCI_MSIX_MCR, 2) & \
     PCI_MSIX_MCR_TBL_MASK) + 1;

  if(dev->vectors != IVSHMNET_NUM_VECTORS)
    {
      pcierr("Ivshmem-net[%d] Number of vector must be 2\n");
      return -EBUSY;
    }

  (void)irq_attach(CONFIG_IVSHMNET_BASE_IRQ + g_ivshmnet_dev_count * 2,
                   (xcpt_t)ivshmnet_state_handler, dev);
  (void)irq_attach(CONFIG_IVSHMNET_BASE_IRQ + g_ivshmnet_dev_count * 2 + 1,
                   (xcpt_t)ivshmnet_interrupt, dev);

  pci_msix_register(&dev->dev,
      CONFIG_IVSHMNET_BASE_IRQ + g_ivshmnet_dev_count * 2, 0);
  pci_msix_register(&dev->dev,
      CONFIG_IVSHMNET_BASE_IRQ + g_ivshmnet_dev_count * 2 + 1, 1);

  if (ivshmnet_calc_qsize(dev))
      return -EINVAL;

  /* fill in the rest of the structure */
  dev->sk_dev.d_buf     = dev->pktbuf;       /* Single packet buffer */
  dev->sk_dev.d_ifup    = ivshmnet_ifup;     /* I/F up (new IP address) callback */
  dev->sk_dev.d_ifdown  = ivshmnet_ifdown;   /* I/F down callback */
  dev->sk_dev.d_txavail = ivshmnet_txavail;  /* New TX data callback */
#ifdef CONFIG_NET_IGMP
  dev->sk_dev.d_addmac  = ivshmnet_addmac;   /* Add multicast MAC address */
  dev->sk_dev.d_rmmac   = ivshmnet_rmmac;    /* Remove multicast MAC address */
#endif
#ifdef CONFIG_NETDEV_IOCTL
  dev->sk_dev.d_ioctl   = ivshmnet_ioctl;    /* Handle network IOCTL commands */
#endif
  dev->sk_dev.d_private = (void *)dev;       /* Used to recover private state from dev */

  /* Create a watchdog for timing polling for and timing of transmissions */

  dev->sk_txpoll        = wd_create();       /* Create periodic poll timer */
  dev->sk_txtimeout     = wd_create();       /* Create TX timeout timer */

  DEBUGASSERT(dev->sk_txpoll != NULL && dev->sk_txtimeout != NULL);

  /* Put the interface in the down state.  This usually amounts to resetting
   * the device and/or calling ivshmnet_ifdown().
   */

  dev->sk_bifup = false;

  /* Register the device with the OS so that socket IOCTLs can be performed */

  (void)netdev_register(&dev->sk_dev, NET_LL_ETHERNET);

  g_ivshmnet_dev_count++;
  pciinfo("Initialized Ivshmem-net[%d]\n", g_ivshmnet_dev_count);

  return OK;
}

/*****************************************************************************
 * Public Data
 *****************************************************************************/

struct pci_dev_type_s pci_ivshmnet =
{
    .vendor = JH_IVSHMEM_VENDORID,
    .device = JH_IVSHMEM_DEVICEID,
    .class_rev = JH_IVSHMEM_PROTOCOL_NET,
    .name = "Jailhouse Ivshmem-net",
    .probe = ivshmnet_probe
};
