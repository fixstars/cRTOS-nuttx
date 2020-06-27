#ifndef __LINUX_SUBSYSTEM_TUX_SYSCALL_TABLE_H
#define __LINUX_SUBSYSTEM_TUX_SYSCALL_TABLE_H

#include <nuttx/config.h>
#include <nuttx/compiler.h>

#include <sys/time.h>

#include "tux.h"

extern syscall_t linux_syscall_action_table[500];
extern uint64_t linux_syscall_number_table[500];

#endif//__LINUX_SUBSYSTEM_TUX_SYSCALL_TABLE_H
