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
#include <string.h>

#include "up_internal.h"
#include "sched/sched.h"

#include "tux.h"

struct tux_pollfd* make_pollfds(struct tux_fd_set *r, struct tux_fd_set *w, struct tux_fd_set *e, int* rcount) {
    int i, j;
    int ret = 0;

    struct tux_fd_set clear_set;
    memset(&clear_set, 0, sizeof(clear_set));

    if(r == NULL) r = &clear_set;
    if(w == NULL) w = &clear_set;
    if(e == NULL) e = &clear_set;

    // Count number FDs
    int count = 0;

    // Those set fits
    for(i = 0; i < (CONFIG_TUX_FD_RESERVE + FD_SETSIZE) / TUX_NFDBITS; i++) {
      count += __builtin_popcount((r->__fds_bits[i] | w->__fds_bits[i] | e->__fds_bits[i]));
    }

    // Remaining bits in the last set
    // Mask and popcount, make sure to preserve the size after masking
    count += __builtin_popcount((typeof(r->__fds_bits[i]))((r->__fds_bits[i] | w->__fds_bits[i] | e->__fds_bits[i]) & ((1ULL << ((CONFIG_TUX_FD_RESERVE + FD_SETSIZE) % TUX_NFDBITS)) - 1)));

    struct tux_pollfd* tux_fds = NULL;

    int k = 0;
    if(count) {
      tux_fds = (struct tux_pollfd*)kmm_malloc(sizeof(struct tux_pollfd) * (count));
      if(!tux_fds) {
        _err("Failed to allocate tux_fds!\n");
        return -ENOMEM;
      }

      memset(tux_fds, 0, sizeof(struct tux_pollfd) * (count));

      for(i = 0; i < (CONFIG_TUX_FD_RESERVE + FD_SETSIZE) / TUX_NFDBITS; i++) {
        for(j = 0; j < TUX_NFDBITS; j++) {

          if(((r->__fds_bits[i] | w->__fds_bits[i] | e->__fds_bits[i]) >> j) & 0x1) {
            tux_fds[k].fd = i * TUX_NFDBITS + j;
            if(r->__fds_bits[i] >> j)
              tux_fds[k].events |= TUX_POLLIN;
            if(w->__fds_bits[i] >> j)
              tux_fds[k].events |= TUX_POLLOUT;
            if(e->__fds_bits[i] >> j)
              tux_fds[k].events |= TUX_POLLERR;
            k++;
          }
        }
      }

      for(j = 0; j < (CONFIG_TUX_FD_RESERVE + FD_SETSIZE) % TUX_NFDBITS; j++) {
        if(((r->__fds_bits[i] | w->__fds_bits[i] | e->__fds_bits[i]) >> j) & 0x1) {
          tux_fds[k].fd = i * TUX_NFDBITS + j;
          if(r->__fds_bits[i] >> j)
            tux_fds[k].events |= TUX_POLLIN;
          if(w->__fds_bits[i] >> j)
            tux_fds[k].events |= TUX_POLLOUT;
          if(e->__fds_bits[i] >> j)
            tux_fds[k].events |= TUX_POLLERR;
          k++;
        }
      }
    }

    ASSERT(k == count);

    *rcount = count;

    return tux_fds;
}

int recover_fdset(struct tux_fd_set* r, struct tux_fd_set* w, struct tux_fd_set* e, struct tux_pollfd* in, int count){
    int i, j;

    int ret = 0;

    if(!in)
        return -EINVAL;

    struct tux_fd_set clear_set;
    memset(&clear_set, 0, sizeof(clear_set));

    if(r == NULL) r = &clear_set;
    if(w == NULL) w = &clear_set;
    if(e == NULL) e = &clear_set;

    for(i = 0; i < count; i++) {
        if(in[i].revents & TUX_POLLIN) {
            r->__fds_bits[(in[i].fd) / TUX_NFDBITS] |=  1 << (in[i].fd) % TUX_NFDBITS;
            ret++;
        } else {
            r->__fds_bits[(in[i].fd) / TUX_NFDBITS] &=  ~(1 << (in[i].fd) % TUX_NFDBITS);
        }

        if(in[i].revents & TUX_POLLOUT) {
            w->__fds_bits[(in[i].fd) / TUX_NFDBITS] |=  1 << (in[i].fd) % TUX_NFDBITS;
            ret++;
        } else {
            w->__fds_bits[(in[i].fd) / TUX_NFDBITS] &=  ~(1 << (in[i].fd) % TUX_NFDBITS);
        }

        if(in[i].revents & TUX_POLLERR) {
            e->__fds_bits[(in[i].fd) / TUX_NFDBITS] |=  1 << (in[i].fd) % TUX_NFDBITS;
            ret++;
        } else {
            e->__fds_bits[(in[i].fd) / TUX_NFDBITS] &=  ~(1 << (in[i].fd) % TUX_NFDBITS);
        }
    }

    return ret;
}

long tux_select (unsigned long nbr, int fd, struct tux_fd_set *r, struct tux_fd_set *w, struct tux_fd_set *e, struct timeval *timeout)
{
  int ret;

  svcinfo("Select syscall %d, fd: %d\n", nbr, fd);

  int count;
  struct tux_pollfd* pfd = make_pollfds(r, w, e, &count);

  int msec;
  if (timeout) {
    msec = timeout->tv_sec * 1000 + timeout->tv_usec / 1000;
  } else {
    msec = -1;
  }

  ret = tux_poll(7, pfd, count, msec);

  svcinfo("poll ret: %d\n", ret);

  ret = recover_fdset(r, w, e, pfd, count);

  return ret;
}
