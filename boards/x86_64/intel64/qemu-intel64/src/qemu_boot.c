/****************************************************************************
 * boards/x86_64/intel64/qemu/src/qemu_boot.c
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

#include <debug.h>

#include <nuttx/board.h>
#include <nuttx/serial/uart_16550.h>
#include <arch/board/board.h>

#include "up_arch.h"
#include "up_internal.h"

#include "qemu_intel64.h"

#ifdef CONFIG_CRTOS
#include "arch/../src/linux_subsystem/tux.h"
#endif

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: x86_64_boardinitialize
 *
 * Description:
 *   All x86_64 architectures must provide the following entry point.
 *   This entry point is called early in the initialization -- after all
 *   memory has been configured and mapped but before any devices have been
 *   initialized.
 *
 ****************************************************************************/

void x86_64_boardinitialize(void)
{
#if defined(CONFIG_16550_UART0) && (CONFIG_16550_UART0_BASE == 0x3f8)
  uart_putreg(CONFIG_16550_UART0_BASE, UART_MCR_OFFSET, UART_MCR_OUT2);
#endif

#if defined(CONFIG_16550_UART1) && (CONFIG_16550_UART1_BASE == 0x3f8)
  uart_putreg(CONFIG_16550_UART1_BASE, UART_MCR_OFFSET, UART_MCR_OUT2);
#endif

#ifdef CONFIG_ARCH_LEDS
  /* Configure on-board LEDs if LED support has been selected. */

  board_autoled_initialize();
#endif
}

/****************************************************************************
 * Name: board_early_initialize
 *
 * Description:
 *   If CONFIG_BOARD_EARLY_INITIALIZE is selected, then an additional
 *   initialization call will be performed in the boot-up sequence to a
 *   function called board_late_initialize().  board_late_initialize() will
 *   be called immediately after up_initialize() is called and just before
 *   the initial application is started.  This additional initialization
 *   phase may be used, for example, to initialize board-specific device
 *   drivers.
 *
 ****************************************************************************/

#ifdef CONFIG_BOARD_EARLY_INITIALIZE
void board_early_initialize(void)
{
#ifdef CONFIG_QEMU_PCI
  /* Initialization of system */

  qemu_pci_init();
#endif

#ifdef CONFIG_CRTOS
  tux_mm_init();
#endif
}
#endif
