/****************************************************************************
 * drivers/serial/mcs99xx.c
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

#include <nuttx/config.h>
#include <nuttx/arch.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include <errno.h>
#include <sched.h>

#include <nuttx/pcie/pcie.h>
#include <nuttx/serial/uart_16550.h>
#include <nuttx/serial/uart_mcs99xx.h>

/************************************************************************************
 * Pre-processor Definitions
 ************************************************************************************/

// These are for 16C950
#define UART_ICR_OFFSET     UART_LSR_OFFSET
#define UART_EFR_OFFSET     UART_IIR_OFFSET
# define UART_EFR_ECB        0b00010000
#define UART_ACR_OFFSET     0x00
# define UART_ACR_ASRE       0b10000000
# define UART_ACR_ICRRD      0b01000000
# define UART_ACR_TLE        0b00100000
#define UART_CPR_OFFSET     0x01
#define UART_TCR_OFFSET     0x02
#define UART_CKS_OFFSET     0x03
#define UART_TTL_OFFSET     0x04
#define UART_RTL_OFFSET     0x05

// MCS99xx specific
#define SER_VEN_REG         (0x204)
#define SER_SOFT_RESET_REG  (0x238)
#define SP_CLK_SELECT_REG   (0x214)

#define UART_ACR_CONFIG (UART_ACR_TLE)
#define UART_FIFO_DEPTH (16)

/************************************************************************************
 * Private Types
 ************************************************************************************/

struct mcs99xx_dev_s {
    struct pcie_dev_s dev;
    uint8_t* membase;
};

/************************************************************************************
 * Private Function Prototypes
 ************************************************************************************/

// Helper Function to prevent compiler doing wired things
static inline uint32_t  mmio_read32(void* membase);
static inline void      mmio_write32(void* membase, uint32_t value);

// Helper function for IO type read/write
static inline uint8_t   mcs99xx_serial_in(uint8_t* membase, int offset);
static inline void      mcs99xx_serial_out(uint8_t* membase, int offset, uint8_t value);

// Helper function to read/write to index control register
static inline void      mcs99xx_serial_icr_write(uint8_t* membase, int offset, uint8_t value);
static inline uint8_t   mcs99xx_serial_icr_read(uint8_t* membase, int offset);

// Helper function to enter enhanced mode
static inline void      mcs99xx_setserial_enhance_mode(uint8_t* membase);

// Helper function to clear device fifos
static inline void      mcs99xx_serial_clear_fifos(uint8_t* membase);

/************************************************************************************
 * Private Data
 ************************************************************************************/

static int mcs99xx_count = 0;

struct mcs99xx_dev_s mcs99xx_devices[CONFIG_MCS99xx_UART_MAX_COUNT];

/************************************************************************************
 * private functions
 ************************************************************************************/

static inline uint32_t mmio_read32(void* membase)
{
  return *(FAR volatile uint32_t*)(membase);
}

static inline void     mmio_write32(void* membase, uint32_t value)
{
  *(FAR volatile uint32_t*)(membase) = value;
}

static inline uint8_t mcs99xx_serial_in(uint8_t* membase, int offset)
{
  uint8_t* mem = membase + 0x280 + (offset * 4);
  return *(FAR volatile uint8_t*)(mem);
}

static inline void    mcs99xx_serial_out(uint8_t* membase, int offset, uint8_t value)
{
  uint8_t* mem = membase + 0x280 + (offset * 4);
  *(FAR volatile uint8_t*)(mem) = value;
}

static inline void    mcs99xx_serial_icr_write(uint8_t* membase, int offset, uint8_t value)
{
  mcs99xx_serial_out(membase, UART_SCR_OFFSET, offset);
  mcs99xx_serial_out(membase, UART_ICR_OFFSET, value);
}

static inline uint8_t mcs99xx_serial_icr_read(uint8_t* membase, int offset)
{
  uint8_t value;
  mcs99xx_serial_icr_write(membase, UART_ACR_OFFSET, UART_ACR_CONFIG | UART_ACR_ICRRD);
  mcs99xx_serial_out(membase, UART_SCR_OFFSET, offset);
  value = mcs99xx_serial_in(membase, UART_ICR_OFFSET);
  mcs99xx_serial_icr_write(membase, UART_ACR_OFFSET, UART_ACR_CONFIG);
  return value;
}

static inline void mcs99xx_setserial_enhance_mode(uint8_t* membase)
{
  uint8_t lcr, efr;

  lcr = mcs99xx_serial_in(membase, UART_LCR_OFFSET);
  mcs99xx_serial_out(membase, UART_LCR_OFFSET, 0xBF);

  efr = mcs99xx_serial_in(membase, UART_EFR_OFFSET);
  efr |= UART_EFR_ECB;
  mcs99xx_serial_out(membase, UART_EFR_OFFSET, efr);

  mcs99xx_serial_out(membase, UART_LCR_OFFSET, lcr);
}

static inline void mcs99xx_serial_clear_fifos(uint8_t* membase)
{
  mcs99xx_serial_out(membase, UART_FCR_OFFSET, UART_FCR_FIFOEN);
  mcs99xx_serial_out(membase, UART_FCR_OFFSET, UART_FCR_FIFOEN |
                     UART_FCR_RXRST | UART_FCR_TXRST);
  mcs99xx_serial_out(membase, UART_FCR_OFFSET, 0);
}

/************************************************************************************
 * Public functions
 ************************************************************************************/

/****************************************************************************
 * Name: mcs99xx_probe
 *
 * Description:
 *   Initialize device
 ****************************************************************************/

int mcs99xx_probe(FAR struct pcie_bus_s* bus,
                  FAR struct pcie_dev_type_s* type, uint16_t bdf)
{
  uint32_t ser_ven_val;

  if(mcs99xx_count >= CONFIG_MCS99xx_UART_MAX_COUNT)
    {
      pcierr("Probed too many MCS99xx serial devices!\n");
    }

  struct mcs99xx_dev_s* mdev = mcs99xx_devices + mcs99xx_count;

  mdev->dev.bus = bus;
  mdev->dev.type = type;
  mdev->dev.bdf = bdf;

  if(pci_find_cap(&mdev->dev, PCI_CAP_MSI) < 0)
    {
      pcierr("Device is not MSI capable\n");
      return -EINVAL;
    }

  uint32_t map_ret;
  pci_map_bar(&mdev->dev, 1, 0x1000, &map_ret);
  mdev->membase = (uint8_t*)((uintptr_t)map_ret);

  // Enable device with MMIO region
  pci_enable_device(&mdev->dev);

  bus->ops->pci_msi_register(&mdev->dev, CONFIG_MCS99xx_UART_BASE_IRQ + mcs99xx_count);

  mmio_write32(mdev->membase + SER_SOFT_RESET_REG, 0x01);

  mcs99xx_serial_clear_fifos(mdev->membase);

  mcs99xx_setserial_enhance_mode(mdev->membase);

  //Setting the FIFO trigger Levels
  mcs99xx_serial_icr_write(mdev->membase, UART_RTL_OFFSET, UART_FIFO_DEPTH);
  mcs99xx_serial_icr_write(mdev->membase, UART_TTL_OFFSET, UART_FIFO_DEPTH);
  mcs99xx_serial_icr_write(mdev->membase, UART_ACR_OFFSET, UART_ACR_CONFIG);

  uint8_t* svr_mem = mdev->membase + SER_VEN_REG;
  uint8_t* sclr_mem = mdev->membase + SP_CLK_SELECT_REG;

  // Set the device clock
  ser_ven_val = mmio_read32(svr_mem);
  ser_ven_val = 0;
  mmio_write32(svr_mem, ser_ven_val);

  // 14745600 Hz
  ser_ven_val |= 0x50;
  mmio_write32(svr_mem, ser_ven_val);

  // Enable pre-scaling for high clock rate
  mmio_write32(sclr_mem, 0);

  mcs99xx_count++;

  return OK;
}

struct pcie_dev_type_s pcie_mcs99xx = {
    .vendor = 0x9710,
    .device = 0x9912,
    .class_rev = 0x00000200,
    .name = "MCS99xx PCI-E Serial Adapter",
    .probe = mcs99xx_probe
};
