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

#include <nuttx/kmalloc.h>

#include "up_internal.h"
#include "sched/sched.h"

#include "tux.h"

int pollfd_translate2local(struct pollfd* out, struct tux_pollfd* in, tux_nfds_t nfds){
    int i;

    if(nfds == 0)
        return 0;

    if(!in || !out)
        return -1;

    for(i = 0; i < nfds; i++){
        // Copy FD
        out[i].fd = in[i].fd - CONFIG_TUX_FD_RESERVE;

        // Copy events
        short int events = in[i].events;
        if(events & TUX_POLLIN) {

            out[i].events |= POLLIN;

            events &= ~TUX_POLLIN;
        }

        if(events & TUX_POLLPRI) {

            out[i].events |= POLLIN;

            events &= ~TUX_POLLPRI;
        }

        if(events & TUX_POLLRDNORM) {

            out[i].events |= POLLRDNORM;

            events &= ~TUX_POLLRDNORM;
        }

        if(events & TUX_POLLRDBAND) {

            out[i].events |= POLLRDBAND;

            events &= ~TUX_POLLRDBAND;
        }

        if(events & TUX_POLLOUT) {

            out[i].events |= POLLOUT;

            events &= ~TUX_POLLOUT;
        }

        if(events & TUX_POLLWRNORM) {

            out[i].events |= POLLWRNORM;

            events &= ~TUX_POLLWRNORM;
        }

        if(events & TUX_POLLWRBAND) {

            out[i].events |= POLLWRBAND;

            events &= ~TUX_POLLWRBAND;
        }

        events &= ~TUX_POLLERR;
        events &= ~TUX_POLLHUP;
        events &= ~TUX_POLLNVAL;

        if(events){
            svcerr("Polling #%d with some ambiguous local_flags 0x%x -> 0x%x\n", i, in[i].events, events);
            return -1;
        }

        out[i].events |= POLLFD;

        svcerr("Polling #%d fd: %d with local_flags 0x%x\n", i, out[i].fd, out[i].events);
    }

    return 0;
}

int pollfd_translate2tux(struct tux_pollfd* out, struct pollfd* in, tux_nfds_t nfds){
    int i;

    if(nfds == 0)
        return 0;

    if(!in || !out)
        return -1;

    for(i = 0; i < nfds; i++){

        // Decode events
        uint8_t revents = in[i].revents;
        if(revents & POLLIN) {

            out[i].revents |= TUX_POLLIN;

            revents &= ~POLLIN;
        }

        if(revents & POLLOUT) {

            out[i].revents |= TUX_POLLOUT;

            revents &= ~POLLOUT;
        }

        if(revents & POLLERR) {

            out[i].revents |= TUX_POLLERR;

            revents &= ~POLLERR;
        }

        if(revents & POLLHUP) {

            out[i].revents |= TUX_POLLHUP;

            revents &= ~POLLHUP;
        }

        if(revents & POLLNVAL) {

            out[i].revents |= TUX_POLLNVAL;

            revents &= ~POLLNVAL;
        }

        if(revents) {
            svcerr("Poll #%d returned with some ambiguous local_flags 0x%x -> 0x%x\n", i, in[i].revents, revents);
            return -1;
        }

        svcerr("Polled #%d with local_flags 0x%x\n", i, in[i].events);
    }

    return 0;
}

long tux_poll(unsigned long nbr, struct tux_pollfd *fds, tux_nfds_t nfds, int timeout) {
  int ret;
  int i, j, k;
  struct tcb_s* rtcb = this_task();

  int local_count = 0;
  int tux_count = 0;
  int mixing = 0;

  svcinfo("Poll on %d FDs\n", nfds);
  for(i = 0; i < nfds; i++)
    {
        svcinfo("FD #%d: %d\n", i, fds[i].fd);
        // If user is mixing the fds
        if(((fds[i].fd > 2) && (fds[i].fd < CONFIG_TUX_FD_RESERVE)) ||
                 ((fds[i].fd >= 0) && (fds[i].fd <= 2) && (rtcb->xcp.fd[fds[i].fd] == fds[i].fd)))
        {
              tux_count++;
        }
    }

  for(i = 0; i < nfds; i++)
    {
        if(fds[i].fd >= CONFIG_TUX_FD_RESERVE) {
          local_count++;
        } else if(fds[i].fd >= 0 && fds[i].fd <= 2) {
            if(rtcb->xcp.fd[fds[i].fd] != fds[i].fd) {
                local_count++;
            }
        }
    }

  if(local_count && tux_count)
    {
      svcwarn("WARN: Poll mixing fd!\n");
      local_count++;
      tux_count++;
      mixing = 1;
    }

  struct tux_pollfd* tux_fds = NULL;
  struct tux_pollfd* tux_local_fds = NULL;
  struct pollfd* local_fds = NULL;

  ret = -ENOMEM;

  // Allocating necessary memory for separating the translating the fds
  if(tux_count) {
      tux_fds = (struct tux_pollfd*)kmm_malloc(sizeof(struct tux_pollfd) * (tux_count));
      if(!tux_fds) {
        _err("Failed to allocate tux_fds!\n");
        goto out;
      }

      memset(tux_fds, 0, sizeof(struct tux_pollfd) * (tux_count));
  }

  if(local_count) {
      tux_local_fds = (struct tux_pollfd*)kmm_malloc(sizeof(struct tux_pollfd) * (local_count));
      if(!tux_local_fds) {
        _err("Failed to allocate %dx tux_local_fds!\n", local_count);
        goto out;
      }

      local_fds = (struct pollfd*)kmm_malloc(sizeof(struct pollfd) * (local_count));
      if(!local_fds) {
        _err("Failed to allocate local_fds!\n");
        goto out;
      }

      memset(tux_local_fds, 0, sizeof(struct tux_pollfd) * (local_count));
      memset(local_fds, 0, sizeof(struct pollfd) * (local_count));
  }

  // Separate the fds according to the realm it belongs to
  for(i = 0, j = 0, k = 0; i < nfds; i++)
    {
        if(fds[i].fd >= CONFIG_TUX_FD_RESERVE) {
          memcpy(tux_local_fds + j++, fds + i, sizeof(fds[i]));
        } else if(fds[i].fd >= 0 && fds[i].fd <= 2) {
            if(rtcb->xcp.fd[fds[i].fd] != fds[i].fd) {
                memcpy(tux_local_fds + j, fds + i, sizeof(fds[i]));

                // This require some faking
                tux_local_fds[j++].fd = rtcb->xcp.fd[fds[i].fd];
            } else {
                // Straight forward implementation
                memcpy(tux_fds + k++, fds + i, sizeof(fds[i]));
           }
        } else {
            memcpy(tux_fds + k++, fds + i, sizeof(fds[i]));
        }
    }

  if(pollfd_translate2local(local_fds, tux_local_fds, local_count))
    {
        ret = -EINVAL;
        goto out;
    }

  uint64_t params[7];

  if(tux_count) {
    // Has tux fd
    // Do some mixing fd hack

    params[0] = nbr;
    params[1] = (uintptr_t)tux_fds;
    params[2] = (uintptr_t)tux_count;

    // Don't let Linux handle time if mixing
    if(mixing)
        params[3] = (uintptr_t)-1;
    else
        params[3] = (uintptr_t)timeout;

    // Clear these, just in-case
    params[4] = 0;
    params[5] = 0;
    params[6] = 0;

    // Let shadow process block and poll
    ret = write(rtcb->xcp.linux_sock, params, sizeof(params));
    /*return tux_delegate(nbr, , (uintptr_t)nfds, (uintptr_t)timeout, 0, 0, 0);*/
  }

  if(local_count) {
    if(mixing) {
      // Poll on the shadow process locally
      local_fds[local_count - 1].fd = rtcb->xcp.linux_sock;
      local_fds[local_count - 1].events = POLLIN;
    }

    // Nuttx local poll
    ret = tux_local(nbr, (uintptr_t)local_fds, (uintptr_t)(local_count), (uintptr_t)timeout, 0, 0, 0);
    if(ret < 0)
      goto out;
  }

  // Either what the user want to poll have returned locally or remotely
  if(tux_count) {
      uint64_t rret;

      // Some remote fds are involved, but none of them are polled!
      if(mixing && !(local_fds[local_count - 1].revents & POLLIN)){

        // The shadow process was yet blocking, we need to do something about it
        // However, it might be unblocked now
        // Try to unblock it

        params[0] = nbr;
        params[1] = 0;
        params[2] = 0;
        params[3] = 0;
        params[4] = 0xdeadbeef;
        params[5] = 0xdeadbeef;
        params[6] = 0xdeadbeef;

        svcinfo("canceling poll\n");
        ret = write(rtcb->xcp.linux_sock, params, sizeof(params));

        // The cancellation will generate an additional packet
        // Furthermore, having a single buffer, but a semaphore is used
        // Read once is not enough, need to read twice to clear the semaphore
        // This looks idiotic, try to make the shadow not transmitting the additional packet XXX

        svcinfo("Wait for cancellation\n");
        read(rtcb->xcp.linux_sock, &rret, sizeof(uint64_t));
      }

      svcinfo("Wait for ret\n");

      // This is from the original poll remote system call
      read(rtcb->xcp.linux_sock, &rret, sizeof(uint64_t));

      // The shadow process should now be freed
  }

  // Translate the local structure back to Linux structure
  pollfd_translate2tux(tux_local_fds, local_fds, local_count);

  ret = 0;

  // Merge the fds back, this must conserve the order given by the user
  for(i = 0, j = 0, k = 0; i < nfds; i++)
    {
        fds[i].revents = 0;

        if(fds[i].fd >= CONFIG_TUX_FD_RESERVE) {
            fds[i].revents = tux_local_fds[j++].revents;
        } else if(fds[i].fd >= 0 && fds[i].fd <= 2) {
            if(rtcb->xcp.fd[fds[i].fd] != fds[i].fd) {
                fds[i].revents = tux_local_fds[j++].revents;
            } else {
                // Straight forward implementation
                fds[i].revents = tux_fds[k++].revents;
            }
        } else {
            fds[i].revents = tux_fds[k++].revents;
        }

        if(fds[i].revents) ret++;
    }

out:
  // Recycle the memory
  if(tux_fds)
      kmm_free(tux_fds);
  if(tux_local_fds)
      kmm_free(tux_local_fds);
  if(local_fds)
      kmm_free(local_fds);

  return ret;
}
