/****************************************************************************
 *  arch/x86_64/src/linux_subsystem/tux_exec.c
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

#include <nuttx/arch.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>

#include "tux.h"
#include "elf64.h"

#include "up_internal.h"
#include "sched/sched.h"
#include "signal/signal.h"
#include <sched/sched.h>
#include <group/group.h>
#include <task/task.h>

/****************************************************************************
 * Pre-processor definitions
 ****************************************************************************/

#define TUX_STACK_START (124 * HUGE_PAGE_SIZE)
#define TUX_STACK_SIZE  (4 * HUGE_PAGE_SIZE)

#define TUX_HEAP_START  (123 * HUGE_PAGE_SIZE)
#define TUX_HEAP_SIZE   (1 * HUGE_PAGE_SIZE)

/****************************************************************************
 * Private Types
 ****************************************************************************/

#ifndef __ASSEMBLY__
typedef struct
{
  uint64_t a_type;
  union
    {
      uint64_t a_val;
    } a_un;
} Elf64_auxv_t;
#endif

/****************************************************************************
 * Private Functions
 ****************************************************************************/

void *exec_setupargs(uint64_t stack,
                     int argc, char *argv[],
                     int envc, char *envp[])
{
  /* Now we have to organize the stack as Linux exec will do
   * ---------
   * argv
   * ---------
   * NULL
   * ---------
   * envp
   * ---------
   * NULL
   * ---------
   * auxv
   * ---------
   * a_type = AT_NULL(0)
   * ---------
   * Stack_top
   * ---------
   */

  Elf64_auxv_t *auxptr;
  uint64_t argv_size, envp_size, total_size;
  uint64_t done;
  char **argv_ptr;
  char **envp_ptr;
  void *sp;

  argv_size = 0;
  for (int i = 0; i < argc; i++)
    {
      argv_size += strlen(argv[i]) + 1;
    }

  envp_size = 0;
  for (int i = 0; i < envc; i++)
    {
      envp_size += strlen(envp[i]) + 1;
    }

  total_size = argv_size + envp_size;

  total_size += sizeof(uint64_t);             /* argc */
  total_size += sizeof(char *) * (argc + 1);  /* argvs + NULL */
  total_size += sizeof(char *) * (envc + 1);  /* envp + NULL */
  total_size += sizeof(Elf64_auxv_t) * 7;     /* 7 aux vectors */
  total_size += sizeof(uint64_t) * 2;         /* AT_RANDOM */

  sp = (void *)(stack + TUX_STACK_SIZE - total_size - PAGE_SIZE);

  sinfo("Setting up stack args at %p\n", sp);

  *((uint64_t *)sp) = argc;

  sinfo("Setting up stack argc is %d\n", *(((uint64_t *)sp) - 1));

  done = 0;
  argv_ptr = ((char **)(((uint8_t *)sp) + sizeof(uint64_t)));
  for (int i = 0; i < argc; i++)
    {
      argv_ptr[i] = (char *)(sp + total_size - argv_size - envp_size + done);
      strcpy(argv_ptr[i], argv[i]);
      done += strlen(argv[i]) + 1;

      argv_ptr[i] += -stack + TUX_STACK_START;
    }

  done = 0;
  envp_ptr = ((char **)(((uint8_t *)sp) + sizeof(uint64_t)) + (argc + 1));
  for (int i = 0; i < envc; i++)
    {
      envp_ptr[i] = (char *)(sp + total_size - envp_size + done);
      strcpy(envp_ptr[i], envp[i]);
      done += strlen(envp[i]) + 1;

      envp_ptr[i] += -stack + TUX_STACK_START;
    }

  auxptr = (Elf64_auxv_t *)(sp + (argc + 1 + envc + 1) * sizeof(char *));

  auxptr[0].a_type = AT_PAGESZ;
  auxptr[0].a_un.a_val = PAGE_SIZE;

  auxptr[1].a_type = AT_RANDOM;
  auxptr[1].a_un.a_val = (uint64_t)(sp + total_size - argv_size - envp_size -
                                    16 - stack + TUX_STACK_START);

  auxptr[2].a_type = AT_SYSINFO_EHDR;
  auxptr[2].a_un.a_val = 0x0;

  auxptr[3].a_type = AT_SECURE;
  auxptr[3].a_un.a_val = 0x0;

  /* AT_NULL */

  auxptr[4].a_type = AT_NULL;
  auxptr[4].a_un.a_val = 0x0;

  auxptr[5].a_type = AT_NULL;
  auxptr[5].a_un.a_val = 0x0;

  auxptr[6].a_type = AT_NULL;
  auxptr[6].a_un.a_val = 0x0;

  return sp;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

long _tux_exec(char *path, char *argv[], char *envp[])
{
  int argc;
  int envc;
  int i;
  int j;
  int ret;
  void *tmp_ptr;

  struct tcb_s *rtcb = this_task();
  struct vma_s *ptr;
  struct vma_s *to_free;

  svcinfo("ARGV:\n");
  for (i = 0; argv[i] != NULL; i++)
    {
      svcinfo("argv[%d] %s\n", i, argv[i]);
    }

  argc = i;

  svcinfo("TOTAL: %d\n", argc);

  for (i = 0; envp[i] != NULL; i++)
      ;
  envc = i;

  /* Hack use of fstat, hard code the linux struct stat size */

  uint64_t filesz;

  tmp_ptr = kmm_zalloc(144);
  tux_delegate(4, (uintptr_t)path, (uintptr_t)tmp_ptr, 0, 0, 0, 0);
  filesz = ((uint64_t *)tmp_ptr)[6];
  kmm_free(tmp_ptr);

  svcinfo("Path: %s, size: 0x%llx\n", path, filesz);

  /* We are in a linux context, so free to use remote system calls
   * Get the ELF header
   */

  int elf_fd =
      tux_open_delegate(2, (uintptr_t)path, TUX_O_RDONLY, 0, 0, 0, 0);
  if (elf_fd < 0)
      return elf_fd;

  /* The mapping might be overwrite during loading
   * Extra care should be taken
   * Map it to a section not used by usual Linux application
   * Or copy it on to the kernel heap
   */

  void *binary = kmm_zalloc(filesz);

  /* use a read instead of mmap
   * This retains the pristine pda and vma in TCB
   */

  int readed = tux_delegate(0, elf_fd, (uintptr_t)binary, filesz, 0, 0, 0);
  if (readed != filesz)
    {
      ret = -ENOMEM;
      tux_file_delegate(3, elf_fd, 0, 0, 0, 0, 0);
      goto err_binary_mem;
    }

  /* We got everything in memory, not needed any more */

  tux_file_delegate(3, elf_fd, 0, 0, 0, 0, 0);

  svcinfo("Testing header...\n");

  /* Test script */

  if (((char *)binary)[0] == '#' && ((char *)binary)[1] == '!')
    {
      /* This is a script
       * Use the scripting program as interpreter
       */

      svcinfo("Oh! A script is found\n");

      /* At max 16 arguments for the interpreter */

      char *holder[16];
      int hidx = 0;
      memset(holder, 0, sizeof(char *) * 16);

      char *scan_ptr = binary + 2;
      char *prev_ptr = binary + 2;
      while (*scan_ptr != '\n')
        {
          if (*scan_ptr == ' ')
            {
              *scan_ptr = '\0';
              if (prev_ptr != scan_ptr)
                {
                  /* a new string */

                  if (hidx >= 16)
                    {
                      for (hidx--; hidx >= 0; hidx--)
                        {
                          kmm_free(holder[hidx]);
                        }

                      return -EINVAL;
                    }

                  holder[hidx++] = strdup(prev_ptr);
                }

              prev_ptr = scan_ptr + 1;
            }

          scan_ptr++;
        }

      if (prev_ptr != scan_ptr)
        {
          *scan_ptr = '\0';

          /* a new string */

          if (hidx >= 16)
            {
              for (hidx--; hidx >= 0; hidx--)
                {
                  kmm_free(holder[hidx]);
                }

              return -EINVAL;
            }

          holder[hidx++] = strdup(prev_ptr);
        }

      /* No interpreter given */

      if (hidx < 1)
          return -EINVAL;

      svcinfo("The interpreter is %s\n", holder[0]);

      for (i = 1; i < hidx; i++)
          svcinfo("Argv[%d] %s\n", i, holder[i]);

      /* Insert the interpreter as argv[0] */

      argv = kmm_realloc(argv, sizeof(char *) * (argc + 1 + hidx));
      argv[argc + hidx] = NULL;
      for (i = argc; i > hidx - 1; i--)
          argv[i] = argv[i - 1];

      kmm_free(argv[hidx]);
      argv[hidx] = path;

      for (; i >= 0; i--)
          argv[i] = holder[i];

      /* We will never return, clear the resource now */

      kmm_free(binary);

      for (i = 0; i < argc + hidx; i++)
        {
          svcinfo("new argv[%d] %s\n", i, argv[i]);
        }

      /* Now we load again with Interpreter */

      ret = _tux_exec(strdup(holder[0]), argv, envp);
    }

  Elf64_Ehdr * header = binary;

  /* Test ELF */

  if ((header->e_ident[EI_MAG0] != ELFMAG0) &&
      (header->e_ident[EI_MAG1] != ELFMAG1) &&
      (header->e_ident[EI_MAG2] != ELFMAG2) &&
      (header->e_ident[EI_MAG3] != ELFMAG3))
    {
      ret = -EINVAL;
      goto err_binary_mem;
    }

  svcinfo("ELF magic verified\n");

  if ((header->e_ident[EI_CLASS] != ELFCLASS64))
    {
      svcerr("Only 64bit ELF is supported!");
      ret = -EINVAL;
      goto err_binary_mem;
    }

  if ((header->e_machine != EM_X86_64))
    {
      svcerr("Only x86-64 ELF is supported!");
      ret = -EINVAL;
      goto err_binary_mem;
    }

  svcinfo("x86-64 ELF verified\n");

  /* free all the resource of the previous task now
   * We have the binary in memory and verified
   * fds we assume 4096 is the max
   * let stdin, stdout, stderr and shadow process retain
   * Skip Linux part, we do it in a single execve call
   */

  for (i = 3; i < _POSIX_OPEN_MAX; i++)
      if (i != rtcb->xcp.linux_sock)
          close(i);

  /* Memory */

  svcinfo("Wiping Memory Map: \n");

  ptr = rtcb->xcp.vma;
  while (ptr)
    {
      if (ptr == &g_vm_full_map)
          continue;

      svcinfo("0x%08llx - 0x%08llx : backed by 0x%08llx 0x%08llx %s\n",
              ptr->va_start, ptr->va_end,
              ptr->pa_start, ptr->pa_start + VMA_SIZE(ptr), ptr->_backing);

      to_free = ptr;
      ptr = ptr->next;

      gran_free(tux_mm_hnd, (void *)(to_free->pa_start), VMA_SIZE(to_free));
      kmm_free(to_free);
    }

  rtcb->xcp.vma = NULL;

  svcinfo("Wiping PDAs: \n");

  ptr = rtcb->xcp.pda;
  while (ptr)
    {
      if (ptr == &g_vm_full_map) continue;

      svcinfo("0x%08llx - 0x%08llx : 0x%08llx 0x%08llx\n",
              ptr->va_start, ptr->va_end,
              ptr->pa_start, ptr->pa_start + VMA_SIZE(ptr));

      to_free = ptr;
      ptr = ptr->next;

      kmm_free(to_free);
    }

  rtcb->xcp.pda = NULL;

  /* Delegate a execve to notify Linux to do some cleaning */

  tux_delegate(59, 0, 0, 0, 0, 0, 0);

  /* print basic info */

  svcinfo("Entry point: 0x%lx\n", header->e_entry);
  svcinfo("ELF header size: 0x%lx\n", header->e_ehsize);
  svcinfo("Program header: 0x%lx\n", header->e_phoff);
  svcinfo("Program header size: 0x%lx\n", header->e_phentsize);
  svcinfo("Program count: 0x%lx\n", header->e_phnum);

  svcinfo("Section header: 0x%lx\n", header->e_shoff);
  svcinfo("Section header size: 0x%lx\n", header->e_shentsize);
  svcinfo("Section count: 0x%lx\n", header->e_shnum);

  /* Map the Segments and Sections */

  Elf64_Phdr *phdr = binary + header->e_phoff;
  Elf64_Shdr *shdr = binary + header->e_shoff;

  /* Search for PT_INTPR, if found it's a dynamic binary */

  int is_dynamic = 0;
  char *interpreter;

  for (i = 0; i < header->e_phnum; i++)
    {
      if (phdr[i].p_type == PT_INTERP)
        {
          is_dynamic = 1;
          interpreter = binary + phdr[i].p_offset;
        }
    }

  if (is_dynamic)
    {
      svcinfo("Dynamic linked ELF detected!\n");
      svcinfo("The interpreter is %s\n", interpreter);
      svcinfo("Loading the interpreter instead of %s\n", path);

      /* Put the interpreter string on to the stack */

      tmp_ptr = strdup(interpreter);

      /* Insert the interpreter as argv[0] */

      argv = kmm_realloc(argv, sizeof(char *) * (argc + 2));
      argv[argc + 1] = NULL;
      for (i = argc; i > 0; i--)
          argv[i] = argv[i - 1];
      kmm_free(argv[1]);
      argv[1] = path;
      argv[0] = tmp_ptr;

      /* We will never return, clear the resource now */

      kmm_free(binary);

      /* Now we load again with statically linked dynamic loader */

      ret = _tux_exec(tmp_ptr, argv, envp);
    }
  else
    {
      svcinfo("Static linked ELF detected!\n");
      svcinfo("Start loading...\n");

      uintptr_t min_seg_addr = 0xffffffff;

      /* Load the Segments with PT_LOAD
       * At this point we should have a clean memory map
       */

      for (i = 0; i < header->e_phnum; i++)
        {
          if (phdr[i].p_type == PT_LOAD)
            {
              svcinfo("Loading Segment #%d/%d...\n", i, header->e_phnum);

              /* First populate the pages */

              tmp_ptr =
                tux_mmap(9, (void *)phdr[i].p_vaddr, phdr[i].p_memsz,
                         TUX_PROT_READ | TUX_PROT_WRITE | TUX_PROT_EXEC,
                         TUX_MAP_ANONYMOUS | TUX_MAP_PRIVATE | TUX_MAP_FIXED,
                         0, 0);

              if (tmp_ptr == MAP_FAILED)
                {
                  ret = -ENOMEM;
                  /* We don't brother reverting the mmap upon error
                   * up_release stack will do this for us
                   * But the original process mmap will be trashed
                   */

                  goto static_err;
                }

              if (phdr[i].p_vaddr < min_seg_addr)
                  min_seg_addr = phdr[i].p_vaddr;

              for (j = 0; j < header->e_shnum; j++)
                {
                  /* Only sections belongs to this segment
                   * Use file offset to map section to segment
                   * Memory address are unreliable,
                   * e.g. debug information will be loaded
                   */

                  if (!((shdr[j].sh_offset >= phdr[i].p_offset) &&
                        (shdr[j].sh_offset < phdr[i].p_offset +
                            phdr[i].p_filesz)
                       ))
                      continue;

                  svcinfo("Section [%02d] %-16s \t "
                          "Virtual address: 0x%016llx \t size: 0x%016llx\n",
                          j,
                          (binary + shdr[header->e_shstrndx].sh_offset) +
                              shdr[j].sh_name,
                          (void *)shdr[j].sh_addr, shdr[j].sh_size);

                  if (shdr[j].sh_type == SHT_NOBITS)
                    {
                      memset((void *)shdr[j].sh_addr,
                             0,
                             shdr[j].sh_size);
                    }
                  else
                    {
                      memcpy((void *)shdr[j].sh_addr,
                             binary + shdr[j].sh_offset,
                             shdr[j].sh_size);
                    }
                }
            }
        }

      /* Set Stack */

      svcinfo("Setting up stack\n");

      tmp_ptr = tux_mmap(9, (void *)TUX_STACK_START, TUX_STACK_SIZE,
                         TUX_PROT_READ | TUX_PROT_WRITE | TUX_PROT_EXEC,
                         TUX_MAP_ANONYMOUS | TUX_MAP_PRIVATE | TUX_MAP_FIXED,
                         0, 0);

      if (tmp_ptr == MAP_FAILED)
        {
          ret = -ENOMEM;
          goto static_err;
        }

      void *sp = exec_setupargs((uintptr_t)tmp_ptr, argc, argv, envc, envp);
      if (sp < 0)
        {
          ret = -get_errno();
          svcerr("execvs_setupargs() failed: %d\n", ret);
          goto static_err;
        }

      /* Set brk */

      svcinfo("Setting up heap\n");

      tmp_ptr = tux_mmap(9, (void *)TUX_HEAP_START, TUX_HEAP_SIZE,
                         TUX_PROT_READ | TUX_PROT_WRITE | TUX_PROT_EXEC,
                         TUX_MAP_ANONYMOUS | TUX_MAP_PRIVATE | TUX_MAP_FIXED,
                         0, 0);

      if (tmp_ptr == MAP_FAILED)
        {
          ret = -ENOMEM;
          goto static_err;
        }

      this_task()->xcp.__min_brk = tmp_ptr;
      this_task()->xcp.__brk = tmp_ptr;

      svcinfo("Preparing _ehdr\n");

      /* populate the elf and program header
       * The evil glibc and binutils not only assume
       * Linux will map the Ehdr but also the Phdr during exec
       */

      memcpy((void *)min_seg_addr, header, sizeof(Elf64_Ehdr));
      memcpy((void *)(min_seg_addr + header->e_phoff),
             binary + header->e_phoff, sizeof(Elf64_Phdr) * header->e_phnum);

      /* record the entry point before we free header */

      uintptr_t entry = header->e_entry;

      /* reclaim some resources */

      kmm_free(binary);
      kmm_free(path);
      for (i = 0; argv[i] != NULL; i++);
          kmm_free(argv[i]);
      for (i = 0; envp[i] != NULL; i++)
          kmm_free(envp[i]);

#ifdef CONFIG_SIG_DEFAULT
      /* Set up default signal actions */

      nxsig_default_initialize(this_task());

      struct sigaction sa;

      /* Attach the signal handler.
       *
       * NOTE: nxsig_action will call nxsig_default(tcb, action, false).
       * Don't be surprised.
       */

      memset(&sa, 0, sizeof(sa));
      sa.sa_handler = tux_abnormal_termination;
      sa.sa_flags   = SA_SIGINFO;
      (void)nxsig_action(SIGKILL, &sa, NULL, true);
      (void)sigaddset(&this_task()->group->tg_sigdefault, (int)SIGKILL);

      (void)nxsig_action(SIGINT,  &sa, NULL, true);
      (void)sigaddset(&this_task()->group->tg_sigdefault, (int)SIGINT);
#endif

      /* TODO: Do we need to close all fds? */

      svcinfo("Starting, jumping to: 0x%llx\n", entry);

      /* enter the new program
       * Somehow, glibc take rdx as the address of rtld_fini, clear it
       */

      asm volatile ("mov %0, %%rsp; \t\n\
                     mov $0, %%rdx; \t\n\
                     jmpq %1"::"g"(sp), "g"(entry));

static_err:
      /* Resource is only reclaimed in static loading
       * This prevent double free in recursive use of _tux_exec
       */

      kmm_free(path);
      for (i = 0; argv[i] != NULL; i++)
          kmm_free(argv[i]);
      for (i = 0; envp[i] != NULL; i++)
          kmm_free(envp[i]);
    }

  return -EINVAL;

err_binary_mem:
  kmm_free(binary);

  return ret;
};

long tux_exec(unsigned long nbr, const char *path,
              char *argv[], char *envp[])
{
  int i;
  int argc, envc;

  void *ppath = strdup(path);

  for (i = 0; argv[i] != NULL; i++)
      ;
  argc = i;

  char **aargv = kmm_zalloc(sizeof(char *) * (argc + 1));
  for (i = 0; argv[i] != NULL; i++)
    {
      aargv[i] = strdup(argv[i]);
    }

  aargv[i] = NULL;

  for (i = 0; envp[i] != NULL; i++);
  envc = i;

  char **eenvp = kmm_zalloc(sizeof(char *) * (envc + 1));
  for (i = 0; envp[i] != NULL; i++)
    {
      eenvp[i] = strdup(envp[i]);
    }

  eenvp[i] = NULL;

  return _tux_exec(ppath, aargv, eenvp);
}

