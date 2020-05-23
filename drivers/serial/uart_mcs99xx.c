/****************************************************************************
 * drivers/serial/uart_mcs99xx.c
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

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <debug.h>

#include <nuttx/irq.h>
#include <nuttx/arch.h>
#include <nuttx/init.h>
#include <nuttx/serial/serial.h>
#include <nuttx/fs/ioctl.h>
#include <nuttx/serial/uart_mcs99xx.h>
#include <nuttx/pci/pci.h>

#include <arch/board/board.h>
#include <arch/io.h>

#ifdef CONFIG_MCS99XX_UART

/****************************************************************************
 * Pre-processor definitions
 ****************************************************************************/

/****************************************************************************
 * Private Types
 ****************************************************************************/

struct mcs99xx_dev_s
{
  struct pci_dev_s dev;
  uart_dev_t uart_port;

  uint32_t          *membase;
  uint32_t          baud;      /* Configured baud */
  uint32_t          uartclk;   /* UART clock frequency */
  uint8_t           ier;       /* Saved IER value */
  uint8_t           irq;       /* IRQ associated with this UART */
  uint8_t           parity;    /* 0=none, 1=odd, 2=even */
  uint8_t           bits;      /* Number of bits (7 or 8) */
  bool              stopbits2; /* true: Configure with 2 stop bits instead of 1 */

  bool              initialized;

  /* I/O buffers */

  char rxbuffer[CONFIG_MCS99XX_UART_RXBUFSIZE];
  char txbuffer[CONFIG_MCS99XX_UART_TXBUFSIZE];
};

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static int  mcs99xx_setup(FAR struct uart_dev_s *dev);
static void mcs99xx_shutdown(FAR struct uart_dev_s *dev);
static int  mcs99xx_attach(FAR struct uart_dev_s *dev);
static void mcs99xx_detach(FAR struct uart_dev_s *dev);
static int  mcs99xx_interrupt(int irq, FAR void *context, FAR void *arg);
static int  mcs99xx_ioctl(FAR struct file *filep,
                          int cmd, unsigned long arg);
static int  mcs99xx_receive(FAR struct uart_dev_s *dev, uint32_t *status);
static void mcs99xx_rxint(FAR struct uart_dev_s *dev, bool enable);
static bool mcs99xx_rxavailable(FAR struct uart_dev_s *dev);
static void mcs99xx_send(FAR struct uart_dev_s *dev, int ch);
static void mcs99xx_txint(FAR struct uart_dev_s *dev, bool enable);
static bool mcs99xx_txready(FAR struct uart_dev_s *dev);
static bool mcs99xx_txempty(FAR struct uart_dev_s *dev);

/****************************************************************************
 * Private Data
 ****************************************************************************/

static const struct uart_ops_s g_mcs99xx_ops =
{
  .setup          = mcs99xx_setup,
  .shutdown       = mcs99xx_shutdown,
  .attach         = mcs99xx_attach,
  .detach         = mcs99xx_detach,
  .ioctl          = mcs99xx_ioctl,
  .receive        = mcs99xx_receive,
  .rxint          = mcs99xx_rxint,
  .rxavailable    = mcs99xx_rxavailable,
  .send           = mcs99xx_send,
  .txint          = mcs99xx_txint,
  .txready        = mcs99xx_txready,
  .txempty        = mcs99xx_txempty,
};

static int g_mcs99xx_count = 0;

struct mcs99xx_dev_s g_mcs99xx_devices[CONFIG_MCS99XX_UART_MAX_COUNT];

#ifdef CONFIG_MCS99XX_UART_SERIAL_CONSOLE
#define HAVE_MCS99XX_CONSOLE

struct mcs99xx_dev_s *g_mcs99xx_console = g_mcs99xx_devices;
struct pci_dev_type_s pci_mcs99xx;
extern struct pci_bus_s *pci_bus;
#endif

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: mcs99xx_serialin
 ****************************************************************************/

static inline uint8_t mcs99xx_serialin(FAR struct mcs99xx_dev_s *priv,
                                               int offset)
{
  if (priv->initialized)
      return mmio_read32(priv->membase + 0xa0 + offset);
  return 0;
}

/****************************************************************************
 * Name: mcs99xx_serialout
 ****************************************************************************/

static inline void mcs99xx_serialout(FAR struct mcs99xx_dev_s *priv,
                                    int offset, uint32_t value)
{
  if (priv->initialized)
      mmio_write32(priv->membase + 0xa0 + offset,  value);
}

/****************************************************************************
 * Name: mcs99xx_serial_icr_write
 ****************************************************************************/

static inline void mcs99xx_serial_icr_write(FAR struct mcs99xx_dev_s *priv,
                                           int offset, uint32_t value)
{
  mcs99xx_serialout(priv, UART_SCR_OFFSET, offset);
  mcs99xx_serialout(priv, UART_ICR_OFFSET, value);
}

/****************************************************************************
 * Name: mcs99xx_serial_icr_read
 ****************************************************************************/

static inline uint8_t mcs99xx_serial_icr_read(FAR struct mcs99xx_dev_s *priv,
                                             int offset)
{
  uint8_t value;
  mcs99xx_serial_icr_write(priv, UART_ACR_OFFSET,
                          UART_ACR_CONFIG | UART_ACR_ICRRD);
  mcs99xx_serialout(priv, UART_SCR_OFFSET, offset);
  value = mcs99xx_serialin(priv, UART_ICR_OFFSET);
  mcs99xx_serial_icr_write(priv, UART_ACR_OFFSET, UART_ACR_CONFIG);
  return value;
}

/****************************************************************************
 * Name: mcs99xx_setserial_enhance_mode
 ****************************************************************************/

static
inline void mcs99xx_setserial_enhance_mode(FAR struct mcs99xx_dev_s *priv)
{
  uint8_t lcr;
  uint8_t efr;

  lcr = mcs99xx_serialin(priv, UART_LCR_OFFSET);
  mcs99xx_serialout(priv, UART_LCR_OFFSET, 0xbf);

  efr = mcs99xx_serialin(priv, UART_EFR_OFFSET);
  efr |= UART_EFR_ECB;
  mcs99xx_serialout(priv, UART_EFR_OFFSET, efr);

  mcs99xx_serialout(priv, UART_LCR_OFFSET, lcr);
}

/****************************************************************************
 * Name: mcs99xx_serial_clear_fifos
 ****************************************************************************/

static inline void mcs99xx_serial_clear_fifos(FAR struct mcs99xx_dev_s *priv)
{
  mcs99xx_serialout(priv, UART_FCR_OFFSET, UART_FCR_FIFOEN);
  mcs99xx_serialout(priv, UART_FCR_OFFSET, UART_FCR_FIFOEN |
                     UART_FCR_RXRST | UART_FCR_TXRST);
  mcs99xx_serialout(priv, UART_FCR_OFFSET, 0);
}

/****************************************************************************
 * Name: mcs99xx_disableuartint
 ****************************************************************************/

static inline void mcs99xx_disableuartint(FAR struct mcs99xx_dev_s *priv,
                                         FAR uint8_t *ier)
{
  if (ier)
    {
      *ier = priv->ier & UART_IER_ALLIE;
    }

  priv->ier &= ~UART_IER_ALLIE;
  mcs99xx_serialout(priv, UART_IER_OFFSET, priv->ier);
}

/****************************************************************************
 * Name: mcs99xx_restoreuartint
 ****************************************************************************/

static inline void mcs99xx_restoreuartint(FAR struct mcs99xx_dev_s *priv,
                                         uint32_t ier)
{
  priv->ier |= ier & UART_IER_ALLIE;
  mcs99xx_serialout(priv, UART_IER_OFFSET, priv->ier);
}

/****************************************************************************
 * Name: mcs99xx_enablebreaks
 ****************************************************************************/

static inline void mcs99xx_enablebreaks(FAR struct mcs99xx_dev_s *priv,
                                       bool enable)
{
  uint32_t lcr = mcs99xx_serialin(priv, UART_LCR_OFFSET);

  if (enable)
    {
      lcr |= UART_LCR_BRK;
    }
  else
    {
      lcr &= ~UART_LCR_BRK;
    }

  mcs99xx_serialout(priv, UART_LCR_OFFSET, lcr);
}

/****************************************************************************
 * Name: mcs99xx_divisor
 *
 * Description:
 *   Select a divider to produce the BAUD from the UART_CLK.
 *
 *     BAUD = UART_CLK / (16 * DL), or
 *     DIV  = UART_CLK / BAUD / 16
 *
 *   Ignoring the fractional divider for now.
 *
 ****************************************************************************/

static inline uint32_t mcs99xx_divisor(FAR struct mcs99xx_dev_s *priv)
{
  return (priv->uartclk + (priv->baud << 3)) / (priv->baud << 4);
}

/****************************************************************************
 * Name: mcs99xx_setup
 *
 * Description:
 *   Configure the UART baud, bits, parity, fifos, etc. This
 *   method is called the first time that the serial port is
 *   opened.
 *
 ****************************************************************************/

static int mcs99xx_setup(FAR struct uart_dev_s *dev)
{
  FAR struct mcs99xx_dev_s *priv = (FAR struct mcs99xx_dev_s *)dev->priv;
  uint16_t div;
  uint32_t lcr;

  /* Clear fifos */

  mcs99xx_serialout(priv, UART_FCR_OFFSET,
                   (UART_FCR_RXRST | UART_FCR_TXRST));

  /* Set trigger */

  mcs99xx_serialout(priv, UART_FCR_OFFSET,
                   (UART_FCR_FIFOEN | UART_FCR_RXTRIGGER_8));

  /* Set up the IER */

  priv->ier = mcs99xx_serialin(priv, UART_IER_OFFSET);

  /* Set up the LCR */

  lcr = 0;
  switch (priv->bits)
    {
      case 5 :
        lcr |= UART_LCR_WLS_5BIT;
        break;

      case 6 :
        lcr |= UART_LCR_WLS_6BIT;
        break;

      case 7 :
        lcr |= UART_LCR_WLS_7BIT;
        break;

      default:
      case 8 :
        lcr |= UART_LCR_WLS_8BIT;
        break;
    }

  if (priv->stopbits2)
    {
      lcr |= UART_LCR_STB;
    }

  if (priv->parity == 1)
    {
      lcr |= UART_LCR_PEN;
    }
  else if (priv->parity == 2)
    {
      lcr |= (UART_LCR_PEN | UART_LCR_EPS);
    }

  /* Enter DLAB=1 */

  mcs99xx_serialout(priv, UART_LCR_OFFSET, (lcr | UART_LCR_DLAB));

  /* Set the BAUD divisor */

  div = mcs99xx_divisor(priv);
  mcs99xx_serialout(priv, UART_DLM_OFFSET, div >> 8);
  mcs99xx_serialout(priv, UART_DLL_OFFSET, div & 0xff);

  /* Clear DLAB */

  mcs99xx_serialout(priv, UART_LCR_OFFSET, lcr);

  /* Configure the FIFOs */

  mcs99xx_serialout(priv, UART_FCR_OFFSET,
                   (UART_FCR_RXTRIGGER_8 | UART_FCR_TXRST | UART_FCR_RXRST |
                    UART_FCR_FIFOEN));

  return OK;
}

/****************************************************************************
 * Name: mcs99xx_shutdown
 *
 * Description:
 *   Disable the UART.  This method is called when the serial
 *   port is closed
 *
 ****************************************************************************/

static void mcs99xx_shutdown(struct uart_dev_s *dev)
{
  FAR struct mcs99xx_dev_s *priv = (FAR struct mcs99xx_dev_s *)dev->priv;
  mcs99xx_disableuartint(priv, NULL);
}

/****************************************************************************
 * Name: mcs99xx_attach
 *
 * Description:
 *   Configure the UART to operation in interrupt driven mode.  This method
 *   is called when the serial port is opened.  Normally, this is just after
 *   the setup() method is called, however, the serial console may operate in
 *   a non-interrupt driven mode during the boot phase.
 *
 *   RX and TX interrupts are not enabled when by the attach method (unless
 *   the hardware supports multiple levels of interrupt enabling).  The RX
 *   and TX interrupts are not enabled until the txint() and rxint() methods
 *   are called.
 *
 ****************************************************************************/

static int mcs99xx_attach(struct uart_dev_s *dev)
{
  FAR struct mcs99xx_dev_s *priv = (FAR struct mcs99xx_dev_s *)dev->priv;
  int ret;

  /* Attach and enable the IRQ */

  ret = irq_attach(priv->irq, mcs99xx_interrupt, dev);
  if (ret == OK)
    {
      /* Enable the interrupt (RX and TX interrupts are still disabled
       * in the UART
       */

      up_enable_irq(priv->irq);
    }

  return ret;
}

/****************************************************************************
 * Name: mcs99xx_detach
 *
 * Description:
 *   Detach UART interrupts.  This method is called when the serial port is
 *   closed normally just before the shutdown method is called.  The
 *   exception is the serial console which is never shutdown.
 *
 ****************************************************************************/

static void mcs99xx_detach(FAR struct uart_dev_s *dev)
{
  FAR struct mcs99xx_dev_s *priv = (FAR struct mcs99xx_dev_s *)dev->priv;

  up_disable_irq(priv->irq);
  irq_detach(priv->irq);
}

/****************************************************************************
 * Name: mcs99xx_interrupt
 *
 * Description:
 *   This is the UART interrupt handler.  It will be invoked when an
 *   interrupt received on the 'irq'  It should call uart_transmitchars or
 *   uart_receivechar to perform the appropriate data transfers.  The
 *   interrupt handling logic must be able to map the 'irq' number into the
 *   appropriate mcs99xx_s structure in order to call these functions.
 *
 ****************************************************************************/

static int mcs99xx_interrupt(int irq, FAR void *context, FAR void *arg)
{
  FAR struct uart_dev_s *dev = (struct uart_dev_s *)arg;
  FAR struct mcs99xx_dev_s *priv;
  uint32_t status;
  int passes;

  DEBUGASSERT(dev != NULL && dev->priv != NULL);
  priv = (FAR struct mcs99xx_dev_s *)dev->priv;

  /* Loop until there are no characters to be transferred or,
   * until we have been looping for a long time.
   */

  for (passes = 0; passes < 256; passes++)
    {
      /* Get the current UART status and check for loop
       * termination conditions
       */

      status = mcs99xx_serialin(priv, UART_IIR_OFFSET);

      /* The UART_IIR_INTSTATUS bit should be zero if there are pending
       * interrupts
       */

      if ((status & UART_IIR_INTSTATUS) != 0)
        {
          /* Break out of the loop when there is no longer a
           * pending interrupt
           */

          break;
        }

      /* Handle the interrupt by its interrupt ID field */

      switch (status & UART_IIR_INTID_MASK)
        {
          /* Handle incoming, receive bytes (with or without timeout) */

          case UART_IIR_INTID_RDA:
          case UART_IIR_INTID_CTI:
            {
              uart_recvchars(dev);
              break;
            }

          /* Handle outgoing, transmit bytes */

          case UART_IIR_INTID_THRE:
            {
              uart_xmitchars(dev);
              break;
            }

          /* Just clear modem status interrupts (UART1 only) */

          case UART_IIR_INTID_MSI:
            {
              /* Read the modem status register (MSR) to clear */

              status = mcs99xx_serialin(priv, UART_MSR_OFFSET);
              sinfo("MSR: %02x\n", status);
              break;
            }

          /* Just clear any line status interrupts */

          case UART_IIR_INTID_RLS:
            {
              /* Read the line status register (LSR) to clear */

              status = mcs99xx_serialin(priv, UART_LSR_OFFSET);
              sinfo("LSR: %02x\n", status);
              break;
            }

          /* There should be no other values */

          default:
            {
              serr("ERROR: Unexpected IIR: %02x\n", status);
              break;
            }
        }
    }

  return OK;
}

/****************************************************************************
 * Name: mcs99xx_ioctl
 *
 * Description:
 *   All ioctl calls will be routed through this method
 *
 ****************************************************************************/

static int mcs99xx_ioctl(struct file *filep, int cmd, unsigned long arg)
{
  FAR struct inode *inode = filep->f_inode;
  FAR struct uart_dev_s *dev   = inode->i_private;
  FAR struct mcs99xx_dev_s *priv = (FAR struct mcs99xx_dev_s *)dev->priv;
  int ret;

#ifdef CONFIG_SERIAL_UART_ARCH_IOCTL
  ret = uart_ioctl(filep, cmd, arg);

  if (ret != -ENOTTY)
    {
      return ret;
    }

#else
  ret = OK;
#endif

  switch (cmd)
    {
#ifdef CONFIG_SERIAL_TIOCSERGSTRUCT
    case TIOCSERGSTRUCT:
      {
        FAR struct mcs99xx_dev_s *user = (FAR struct mcs99xx_dev_s *)arg;
        if (!user)
          {
            ret = -EINVAL;
          }
        else
          {
            memcpy(user, dev, sizeof(struct mcs99xx_dev_s));
          }
      }
      break;
#endif

    case TIOCSBRK:  /* BSD compatibility: Turn break on, unconditionally */
      {
        irqstate_t flags = enter_critical_section();
        mcs99xx_enablebreaks(priv, true);
        leave_critical_section(flags);
      }
      break;

    case TIOCCBRK:  /* BSD compatibility: Turn break off, unconditionally */
      {
        irqstate_t flags;
        flags = enter_critical_section();
        mcs99xx_enablebreaks(priv, false);
        leave_critical_section(flags);
      }
      break;

#if defined(CONFIG_SERIAL_TERMIOS)
    case TCGETS:
      {
        FAR struct termios *termiosp = (FAR struct termios *)arg;
        irqstate_t flags;

        if (!termiosp)
          {
            ret = -EINVAL;
            break;
          }

        flags = enter_critical_section();

        cfsetispeed(termiosp, priv->baud);
        termiosp->c_cflag = ((priv->parity != 0) ? PARENB : 0) |
                            ((priv->parity == 1) ? PARODD : 0);
        termiosp->c_cflag |= (priv->stopbits2) ? CSTOPB : 0;

        switch (priv->bits)
          {
          case 5:
            termiosp->c_cflag |= CS5;
            break;

          case 6:
            termiosp->c_cflag |= CS6;
            break;

          case 7:
            termiosp->c_cflag |= CS7;
            break;

          case 8:
          default:
            termiosp->c_cflag |= CS8;
            break;
          }

        leave_critical_section(flags);
      }
      break;

    case TCSETS:
      {
        FAR struct termios *termiosp = (FAR struct termios *)arg;
        irqstate_t flags;

        if (!termiosp)
          {
            ret = -EINVAL;
            break;
          }

        flags = enter_critical_section();

        switch (termiosp->c_cflag & CSIZE)
          {
          case CS5:
            priv->bits = 5;
            break;

          case CS6:
            priv->bits = 6;
            break;

          case CS7:
            priv->bits = 7;
            break;

          case CS8:
          default:
            priv->bits = 8;
            break;
          }

        if ((termiosp->c_cflag & PARENB) != 0)
          {
            priv->parity = (termiosp->c_cflag & PARODD) ? 1 : 2;
          }
        else
          {
            priv->parity = 0;
          }

        priv->baud      = cfgetispeed(termiosp);
        priv->stopbits2 = (termiosp->c_cflag & CSTOPB) != 0;

        mcs99xx_setup(dev);
        leave_critical_section(flags);
      }
      break;
#endif

    default:
      ret = -ENOTTY;
      break;
    }

  return ret;
}

/****************************************************************************
 * Name: mcs99xx_receive
 *
 * Description:
 *   Called (usually) from the interrupt level to receive one
 *   character from the UART.  Error bits associated with the
 *   receipt are provided in the return 'status'.
 *
 ****************************************************************************/

static int mcs99xx_receive(struct uart_dev_s *dev, uint32_t *status)
{
  FAR struct mcs99xx_dev_s *priv = (FAR struct mcs99xx_dev_s *)dev->priv;
  uint32_t rbr;

  *status = mcs99xx_serialin(priv, UART_LSR_OFFSET);
  rbr     = mcs99xx_serialin(priv, UART_RBR_OFFSET);
  return rbr;
}

/****************************************************************************
 * Name: mcs99xx_rxint
 *
 * Description:
 *   Call to enable or disable RX interrupts
 *
 ****************************************************************************/

static void mcs99xx_rxint(struct uart_dev_s *dev, bool enable)
{
  FAR struct mcs99xx_dev_s *priv = (FAR struct mcs99xx_dev_s *)dev->priv;

  if (enable)
    {
      priv->ier |= UART_IER_ERBFI;
    }
  else
    {
      priv->ier &= ~UART_IER_ERBFI;
    }

  mcs99xx_serialout(priv, UART_IER_OFFSET, priv->ier);
}

/****************************************************************************
 * Name: mcs99xx_rxavailable
 *
 * Description:
 *   Return true if the receive fifo is not empty
 *
 ****************************************************************************/

static bool mcs99xx_rxavailable(struct uart_dev_s *dev)
{
  FAR struct mcs99xx_dev_s *priv = (FAR struct mcs99xx_dev_s *)dev->priv;
  return ((mcs99xx_serialin(priv, UART_LSR_OFFSET) & UART_LSR_DR) != 0);
}

/****************************************************************************
 * Name: mcs99xx_send
 *
 * Description:
 *   This method will send one byte on the UART
 *
 ****************************************************************************/

static void mcs99xx_send(struct uart_dev_s *dev, int ch)
{
  FAR struct mcs99xx_dev_s *priv = (FAR struct mcs99xx_dev_s *)dev->priv;
  mcs99xx_serialout(priv, UART_THR_OFFSET, (uint8_t)ch);
}

/****************************************************************************
 * Name: mcs99xx_txint
 *
 * Description:
 *   Call to enable or disable TX interrupts
 *
 ****************************************************************************/

static void mcs99xx_txint(struct uart_dev_s *dev, bool enable)
{
  FAR struct mcs99xx_dev_s *priv = (FAR struct mcs99xx_dev_s *)dev->priv;
  irqstate_t flags;

  flags = enter_critical_section();
  if (enable)
    {
      priv->ier |= UART_IER_ETBEI;
      mcs99xx_serialout(priv, UART_IER_OFFSET, priv->ier);

      /* Fake a TX interrupt here by just calling uart_xmitchars() with
       * interrupts disabled (note this may recurse).
       */

      uart_xmitchars(dev);
    }
  else
    {
      priv->ier &= ~UART_IER_ETBEI;
      mcs99xx_serialout(priv, UART_IER_OFFSET, priv->ier);
    }

  leave_critical_section(flags);
}

/****************************************************************************
 * Name: mcs99xx_txready
 *
 * Description:
 *   Return true if the tranmsit fifo is not full
 *
 ****************************************************************************/

static bool mcs99xx_txready(struct uart_dev_s *dev)
{
  FAR struct mcs99xx_dev_s *priv = (FAR struct mcs99xx_dev_s *)dev->priv;
  return ((mcs99xx_serialin(priv, UART_LSR_OFFSET) & UART_LSR_THRE) != 0);
}

/****************************************************************************
 * Name: mcs99xx_txempty
 *
 * Description:
 *   Return true if the transmit fifo is empty
 *
 ****************************************************************************/

static bool mcs99xx_txempty(struct uart_dev_s *dev)
{
  FAR struct mcs99xx_dev_s *priv = (FAR struct mcs99xx_dev_s *)dev->priv;
  return ((mcs99xx_serialin(priv, UART_LSR_OFFSET) & UART_LSR_TEMT) != 0);
}

/****************************************************************************
 * Name: mcs99xx_putc
 *
 * Description:
 *   Write one character to the UART (polled)
 *
 ****************************************************************************/

#ifdef HAVE_MCS99XX_CONSOLE
static void mcs99xx_putc(FAR struct mcs99xx_dev_s *priv, int ch)
{
  while ((mcs99xx_serialin(priv, UART_LSR_OFFSET) & UART_LSR_THRE) == 0);
  mcs99xx_serialout(priv, UART_THR_OFFSET, (uint8_t)ch);
}
#endif

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: mcs99xx_probe
 *
 * Description:
 *   Initialize device
 ****************************************************************************/

int mcs99xx_probe(FAR struct pci_bus_s *bus,
                  FAR struct pci_dev_type_s *type, uint16_t bdf)
{
  uint32_t ser_ven_val;

  if (g_mcs99xx_count >= CONFIG_MCS99XX_UART_MAX_COUNT)
    {
      pcierr("Probed too many MCS99xx serial devices!\n");
    }

  for (int i = 0; i < g_mcs99xx_count; i++)
      if (g_mcs99xx_devices[i].initialized &&
          g_mcs99xx_devices[i].dev.bdf == bdf)
        {
          pciinfo("This MCS99xx serial devices is initialized, skipping\n");
          return OK;
        }

  struct mcs99xx_dev_s *mdev = g_mcs99xx_devices + g_mcs99xx_count;

  mdev->dev.bus = bus;
  mdev->dev.type = type;
  mdev->dev.bdf = bdf;

  if (pci_find_cap(&mdev->dev, PCI_CAP_MSI) < 0)
    {
      pcierr("Device is not MSI capable\n");
      return -EINVAL;
    }

  mdev->membase = (uint32_t *)(pci_map_bar(&mdev->dev, 1));

  /* Enable device with MMIO region */

  pci_enable_device(&mdev->dev);

  mdev->irq = CONFIG_MCS99XX_UART_BASE_IRQ + g_mcs99xx_count;

  pci_msi_register(&mdev->dev, mdev->irq);

  mmio_write32(((uint8_t*)mdev->membase) + SER_SOFT_RESET_REG, 0x01);

  mcs99xx_serial_clear_fifos(mdev);

  mcs99xx_setserial_enhance_mode(mdev);

  /* Setting the FIFO trigger Levels */

  mcs99xx_serial_icr_write(mdev, UART_RTL_OFFSET, UART_FIFO_DEPTH);
  mcs99xx_serial_icr_write(mdev, UART_TTL_OFFSET, UART_FIFO_DEPTH);
  mcs99xx_serial_icr_write(mdev, UART_ACR_OFFSET, UART_ACR_CONFIG);

  uint8_t *svr_mem = ((uint8_t *)mdev->membase) + SER_VEN_REG;
  uint8_t *sclr_mem = ((uint8_t *)mdev->membase) + SP_CLK_SELECT_REG;

  /* Set the device clock */

  ser_ven_val = mmio_read32(svr_mem);
  ser_ven_val = 0;
  mmio_write32(svr_mem, ser_ven_val);

  /* 14745600 Hz */

  ser_ven_val |= 0x50;
  mmio_write32(svr_mem, ser_ven_val);

  /* Enable pre-scaling for high clock rate */

  mmio_write32(sclr_mem, 0);

  mdev->uartclk = 14745600;

  mdev->baud      = CONFIG_MCS99XX_UART_BAUD;
  mdev->parity    = CONFIG_MCS99XX_UART_PARITY;
  mdev->bits      = CONFIG_MCS99XX_UART_BITS;
  mdev->stopbits2 = CONFIG_MCS99XX_UART_2STOP;

  mdev->uart_port.recv.size = CONFIG_MCS99XX_UART_RXBUFSIZE;
  mdev->uart_port.recv.buffer = mdev->rxbuffer;
  mdev->uart_port.xmit.size = CONFIG_MCS99XX_UART_TXBUFSIZE;
  mdev->uart_port.xmit.buffer = mdev->txbuffer;
  mdev->uart_port.ops = &g_mcs99xx_ops;
  mdev->uart_port.priv = mdev;

  mdev->initialized = true;

  if (OSINIT_HW_READY())
    {
      char buf[32];
      sprintf(buf, "/dev/ttyS%d", g_mcs99xx_count);
      uart_register(buf, &mdev->uart_port);
    }

  g_mcs99xx_count++;

  return OK;
}

/****************************************************************************
 * Name: up_earlyserialinit
 *
 * Description:
 *   Performs the low level UART initialization early in debug so that the
 *   serial console will be available during bootup.  This must be called
 *   before uart_serialinit.
 *
 *   NOTE: Configuration of the CONSOLE UART was performed by uart_lowsetup()
 *   very early in the boot sequence.
 *
 ****************************************************************************/

void up_earlyserialinit(void)
{
  /* Configuration whichever one is the console */

#ifdef CONFIG_MCS99XX_UART_SERIAL_CONSOLE
  mcs99xx_probe(pci_bus,
                &pci_mcs99xx, CONFIG_MCS99XX_CONSOLE_BUS_BDF);

  g_mcs99xx_console->uart_port.isconsole = true;
  mcs99xx_setup(&g_mcs99xx_console->uart_port);
#endif
}

/****************************************************************************
 * Name: up_serialinit
 *
 * Description:
 *   Register serial console and serial ports.  This assumes that
 *   up_earlyserialinit was called previously.
 *
 ****************************************************************************/

void up_serialinit(void)
{
#ifdef CONFIG_MCS99XX_UART_SERIAL_CONSOLE
  uart_register("/dev/console", &g_mcs99xx_console->uart_port);
  uart_register("/dev/ttyS0", &g_mcs99xx_console->uart_port);
#endif
}

/****************************************************************************
 * Name: up_putc
 *
 * Description:
 *   Provide priority, low-level access to support OS debug  writes
 *
 ****************************************************************************/

#ifdef HAVE_MCS99XX_CONSOLE
int up_putc(int ch)
{
  FAR struct mcs99xx_dev_s *priv = g_mcs99xx_console;
  uint8_t ier;
  if (!priv->initialized)
      return 0;

  mcs99xx_disableuartint(priv, &ier);

  /* Check for LF */

  if (ch == '\n')
    {
      /* Add CR */

      mcs99xx_putc(priv, '\r');
    }

  mcs99xx_putc(priv, ch);
  mcs99xx_restoreuartint(priv, ier);
  return ch;
}
#endif

struct pci_dev_type_s pci_mcs99xx =
{
  .vendor = MOSTECH_ID,
  .device = MCS99XX_ID,
  .class_rev = MCS99XX_CLASS_SERIAL,
  .name = "MCS99xx PCI-E Serial Adapter",
  .probe = mcs99xx_probe
};

#endif /* CONFIG_MCS99XX_UART */
