#include <nuttx/config.h>
#include <nuttx/compiler.h>

#include <nuttx/fs/fs.h>

#include <sys/select.h>

#include <nuttx/arch.h>
#include <nuttx/sched.h>
#include <nuttx/board.h>
#include <nuttx/irq.h>
#include <arch/io.h>
#include <syscall.h>
#include <fcntl.h>
#include <semaphore.h>
#include <errno.h>
#include <poll.h>

#include "up_internal.h"
#include "sched/sched.h"

#include "tux.h"
#include "tux_syscall_table.h"

int tux_errno[__ELASTERROR] = {
    0,   //                     0
    1,   // EPERM               1
    2,   // ENOENT              2
    3,   // ESRCH               3
    4,   // EINTR               4
    5,   // EIO                 5
    6,   // ENXIO               6
    7,   // E2BIG               7
    8,   // ENOEXEC             8
    9,   // EBADF               9
    10,  // ECHILD              10
    11,  // EAGAIN              11
    12,  // ENOMEM              12
    13,  // EACCES              13
    14,  // EFAULT              14                         /* Linux errno extension */
    15,  // ENOTBLK             15
    16,  // EBUSY               16
    17,  // EEXIST              17
    18,  // EXDEV               18
    19,  // ENODEV              19
    20,  // ENOTDIR             20
    21,  // EISDIR              21
    22,  // EINVAL              22
    23,  // ENFILE              23
    24,  // EMFILE              24
    25,  // ENOTTY              25
    26,  // ETXTBSY             26
    27,  // EFBIG               27
    28,  // ENOSPC              28
    29,  // ESPIPE              29
    30,  // EROFS               30
    31,  // EMLINK              31
    32,  // EPIPE               32
    33,  // EDOM                33
    34,  // ERANGE              34
    42,  // ENOMSG              35
    43,  // EIDRM               36
    44,  // ECHRNG              37                         /* Linux errno extension */
    45,  // EL2NSYNC            38                         /* Linux errno extension */
    46,  // EL3HLT              39                         /* Linux errno extension */
    47,  // EL3RST              40                         /* Linux errno extension */
    48,  // ELNRNG              41                         /* Linux errno extension */
    49,  // EUNATCH             42                         /* Linux errno extension */
    50,  // ENOCSI              43                         /* Linux errno extension */
    51,  // EL2HLT              44                         /* Linux errno extension */
    35,  // EDEADLK             45
    37,  // ENOLCK              46
    0,   //                     47
    0,   //                     48
    0,   //                     49
    52,  // EBADE               50                         /* Linux errno extension */
    53,  // EBADR               51                         /* Linux errno extension */
    54,  // EXFULL              52                         /* Linux errno extension */
    55,  // ENOANO              53                         /* Linux errno extension */
    56,  // EBADRQC             54                         /* Linux errno extension */
    57,  // EBADSLT             55                         /* Linux errno extension */
    35,  // EDEADLOCK           56                         /* Linux errno extension */
    59,  // EBFONT              57                         /* Linux errno extension */
    0,   //                     58
    0,   //                     59
    60,  // ENOSTR              60
    61,  // ENODATA             61
    62,  // ETIME               62
    63,  // ENOSR               63
    64,  // ENONET              64                         /* Linux errno extension */
    65,  // ENOPKG              65                         /* Linux errno extension */
    66,  // EREMOTE             66                         /* Linux errno extension */
    67,  // ENOLINK             67
    68,  // EADV                68                         /* Linux errno extension */
    69,  // ESRMNT              69                         /* Linux errno extension */
    70,  // ECOMM               70                         /* Linux errno extension */
    71,  // EPROTO              71
    0,   //                     72
    0,   //                     73
    72,  // EMULTIHOP           74
    0,// ELBIN               75                         /* Linux errno extension */
    73,  // EDOTDOT             76                         /* Linux errno extension */
    74,  // EBADMSG             77
    0,   //                     78
    0,// EFTYPE              79
    76,  // ENOTUNIQ            80                         /* Linux errno extension */
    77,  // EBADFD              81                         /* Linux errno extension */
    78,  // EREMCHG             82                         /* Linux errno extension */
    79,  // ELIBACC             83                         /* Linux errno extension */
    80, // ELIBBAD             84                         /* Linux errno extension */
    81,  // ELIBSCN             85                         /* Linux errno extension */
    82,  // ELIBMAX             86                         /* Linux errno extension */
    83,  // ELIBEXEC            87                         /* Linux errno extension */
    38,  // ENOSYS              88
    0,// ENMFILE             89                         /* Cygwin */
    39,  // ENOTEMPTY           90
    36,  // ENAMETOOLONG        91
    40,  // ELOOP               92
    0,   //                     93
    0,   //                     94
    95,  // EOPNOTSUPP          95
    96,  // EPFNOSUPPORT        96
    0,   //                     97
    0,   //                     98
    0,   //                     99
    0,   //                     100
    0,   //                     101
    0,   //                     102
    0,   //                     103
    104, // ECONNRESET          104
    105, // ENOBUFS             105
    97,  // EAFNOSUPPORT        106
    91,  // EPROTOTYPE          107
    88,  // ENOTSOCK            108
    92,  // ENOPROTOOPT         109
    108, // ESHUTDOWN           110                         /* Linux errno extension */
    111, // ECONNREFUSED        111
    98,  // EADDRINUSE          112
    103, // ECONNABORTED        113
    101, // ENETUNREACH         114
    100, // ENETDOWN            115
    110, // ETIMEDOUT           116
    112, // EHOSTDOWN           117
    113, // EHOSTUNREACH        118
    115, // EINPROGRESS         119
    114, // EALREADY            120
    89,  // EDESTADDRREQ        121
    90,  // EMSGSIZE            122
    93,  // EPROTONOSUPPORT     123
    94,  // ESOCKTNOSUPPORT     124                         /* Linux errno extension */
    99,  // EADDRNOTAVAIL       125
    102, // ENETRESET           126
    106, // EISCONN             127
    107, // ENOTCONN            128
    109, // ETOOMANYREFS        129
    0,// EPROCLIM            130
    87,  // EUSERS              131
    122, // EDQUOT              132
    116, // ESTALE              133
    0,// ENOTSUP             134
    123, // ENOMEDIUM           135                         /* Linux errno extension */
    0,// ENOSHARE            136                         /* Cygwin */
    0,// ECASECLASH          137                         /* Cygwin */
    84,  // EILSEQ              138
    0,// EOVERFLOW           139
    125, // ECANCELED           140
    131, // ENOTRECOVERABLE     141
    130, // EOWNERDEAD          142
    86  // ESTRPIPE            143                         /* Linux errno extension */
};

void tux_errno_sanitaizer(int *ret){
    if(*ret < 0)
        *ret = -tux_errno[-*ret];

    return;
}


long tux_local(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  int ret;
  svcinfo("Local syscall %d, %d\n", nbr, linux_syscall_number_table[nbr]);

  if(linux_syscall_number_table[nbr] == (uint64_t)-1){
    _alert("Not implemented Local syscall %d\n", nbr);
    PANIC();
  }

  errno = 0;
  ret = ((syscall_t) \
         (g_stublookup[linux_syscall_number_table[nbr] - CONFIG_SYS_RESERVED])) \
         (linux_syscall_number_table[nbr] - CONFIG_SYS_RESERVED, parm1, parm2, parm3, parm4, parm5, parm6);

  if(errno != 0)
      ret = -errno;

  tux_errno_sanitaizer(&ret);

  return ret;
}

long tux_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  struct tcb_s *rtcb = this_task();
  uint64_t params[7];
  uint64_t syscall_ret;
  int ret;
  svcinfo("Delegating syscall %d to linux\n", nbr);

  if(rtcb->xcp.is_linux && rtcb->xcp.linux_sock)
  {
    params[0] = nbr;
    params[1] = parm1;
    params[2] = parm2;
    params[3] = parm3;
    params[4] = parm4;
    params[5] = parm5;
    params[6] = parm6;

    ret = write(rtcb->xcp.linux_sock, params, sizeof(params));
    ret = read(rtcb->xcp.linux_sock, &syscall_ret, sizeof(uint64_t));

  } else {
    _err("Non-linux process calling linux syscall or invalid sock fd %d, %d\n", rtcb->xcp.is_linux, rtcb->xcp.linux_sock);
    PANIC();
  }
  return syscall_ret;
}

long tux_file_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  struct tcb_s *rtcb = this_task();
  int ret = -EBADF;
  svcinfo("Multiplexed File related syscall %d, fd: %d\n", nbr, parm1);

  if(parm1 >= 0 && parm1 <= 2) {
      if(rtcb->xcp.fd[parm1] != parm1) {
        if(linux_syscall_number_table[nbr] != (uint64_t)-1){
          svcinfo("Facking: %d\n", rtcb->xcp.fd[parm1]);
          ret = tux_local(nbr, rtcb->xcp.fd[parm1], parm2, parm3, parm4, parm5, parm6);
        }
      } else {
        ret = tux_delegate(nbr, parm1, parm2, parm3, parm4, parm5, parm6);
      }
  } else if(parm1 < CONFIG_TUX_FD_RESERVE) { // Lower parts should be delegated
    ret = tux_delegate(nbr, parm1, parm2, parm3, parm4, parm5, parm6);
  }else{
    ret = -1;
    if(linux_syscall_number_table[nbr] != (uint64_t)-1){
      ret = tux_local(nbr, parm1 - CONFIG_TUX_FD_RESERVE, parm2, parm3, parm4, parm5, parm6);
    }
  }

  return ret;
}

long tux_open_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  int ret;
  uint64_t new_flags;

  svcinfo("Open/Socket syscall %d, path: %s, flag: %llx\n", nbr, (char*)parm1, parm2);
  if(nbr == 2){
      // Nuttx has different Bit pattern in flags, we have to decode them
      new_flags = 0;
      if(parm2 & TUX_O_ACCMODE)     new_flags |= O_ACCMODE;

      if(parm2 & TUX_O_WRONLY)      new_flags |= O_WRONLY;
      else if(parm2 & TUX_O_RDWR)        new_flags |= O_RDWR;
      else new_flags |= O_RDONLY;  // TUX_O_RDONLY == 0

      if(parm2 & TUX_O_CREAT)       new_flags |= O_CREAT;
      if(parm2 & TUX_O_EXCL)        new_flags |= O_EXCL;
      if(parm2 & TUX_O_NOCTTY)      new_flags |= O_NOCTTY;
      if(parm2 & TUX_O_TRUNC)       new_flags |= O_TRUNC;
      if(parm2 & TUX_O_APPEND)      new_flags |= O_APPEND;
      if(parm2 & TUX_O_NONBLOCK)    new_flags |= O_NONBLOCK;
      if(parm2 & TUX_O_DSYNC)       new_flags |= O_DSYNC;
      if((parm2 & TUX_O_SYNC) == TUX_O_SYNC)        new_flags |= O_SYNC;
      if(parm2 & TUX_O_DIRECT)      new_flags |= O_DIRECT;
      /*if(parm2 & TUX_O_LARGEFILE)   new_flags |= O_LARGEFILE;*/
      /*if(parm2 & TUX_O_DIRECTORY)   new_flags |= O_DIRECTORY;*/
      /*if(parm2 & TUX_O_NOFOLLOW)    new_flags |= O_NOFOLLOW;*/
      /*if(parm2 & TUX_O_NOATIME)     new_flags |= O_NOATIME;*/
      /*if(parm2 & TUX_O_CLOEXEC)     new_flags |= O_CLOEXEC;*/
      if((parm2 & TUX_O_TMPFILE) == TUX_O_TMPFILE)     return -1;
      if(parm2 & TUX_O_NDELAY)      new_flags |= O_NDELAY;
      svcinfo("Local open Flags: 0x%llx\n", new_flags);
      ret = tux_local(nbr, parm1, new_flags, parm3, parm4, parm5, parm6);
      if(ret >= 0){
          return ret + CONFIG_TUX_FD_RESERVE;
      }

      svcinfo("%s\n", strerror(ret));
      ret = tux_delegate(nbr, parm1, parm2, parm3, parm4, parm5, parm6);
      svcinfo("Open/Socket fd: %d\n", ret);

      return ret;
  }else{

      ret = tux_delegate(nbr, parm1, parm2, parm3, parm4, parm5, parm6);
      svcinfo("Open/Socket fd: %d\n", ret);

      return ret;
  }

}

long tux_dup2_delegate(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6)
{
  struct tcb_s *rtcb = this_task();
  int ret;
  svcinfo("Multiplexed DUP2, fd: %d\n", parm1);

  if(parm1 < CONFIG_TUX_FD_RESERVE && parm2 < CONFIG_TUX_FD_RESERVE) {
    ret = tux_delegate(nbr, parm1, parm2, parm3, parm4, parm5, parm6);
  } else if(parm1 >= CONFIG_TUX_FD_RESERVE && parm2 >= CONFIG_TUX_FD_RESERVE) {
    ret = -1;
    ret = tux_local(nbr, parm1 - CONFIG_TUX_FD_RESERVE, parm2 - CONFIG_TUX_FD_RESERVE, parm3, parm4, parm5, parm6) + CONFIG_TUX_FD_RESERVE;
  } else if(parm1 < CONFIG_TUX_FD_RESERVE && parm2 >= CONFIG_TUX_FD_RESERVE){
    ret = -EINVAL;
  } else {
      if(parm2 >= 0 && parm2 <= 2) {
          // dup first and assign to the xcp;
          ret = dup(parm1 - CONFIG_TUX_FD_RESERVE);
          svcinfo("Fake DUPED as %d\n", ret);
          rtcb->xcp.fd[parm2] = ret;
          ret = parm2;
      } else {
        ret = -EINVAL;
      }
  }

  return ret;
}

long tux_exit(unsigned long nbr, uintptr_t parm1, uintptr_t parm2,
                          uintptr_t parm3, uintptr_t parm4, uintptr_t parm5,
                          uintptr_t parm6) {

  struct tcb_s *rtcb = this_task();

  if(!(parm5 = 0xdeadbeef && parm6 == 0xabcedf))
      tux_delegate(nbr, parm1, parm2, parm3, parm4, parm5, parm6);

  if(rtcb->xcp.is_linux == 2) {
    delete_proc_node(rtcb->xcp.linux_pid);
    close(rtcb->xcp.linux_sock);
  }else{
    delete_proc_node(rtcb->xcp.linux_tid);
  }

  tux_set_tid_callback();

  svcinfo("PID %d exiting\n", rtcb->pid);

  _exit(parm1);
}
