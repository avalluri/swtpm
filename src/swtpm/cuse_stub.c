#include "logging.h"
#include "tpm_ioctl.h"

#include <fuse/cuse_lowlevel.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>



static int parentfd = 0;
static int ioctlfd = 3;
static void *buffer = 0;
static size_t buflen = 0;

static ssize_t from_parent(int fd)
{
    int msgsize;
    if (ioctl(fd, FIONREAD, &msgsize)) {
        return -2;
    }
    if (msgsize > 0) {
        if ((size_t)msgsize > buflen) {
            /* leave some room for future, larger messages */
            size_t newbuflen = msgsize * 2;
            void *newbuf = realloc(buffer, newbuflen);
            if (!newbuf) {
                logprintf(STDERR_FILENO,
                          "Error: allocating OOB buffer failed\n");
                errno = ENOMEM;
                return -2;
            }
            buffer = newbuf;
            buflen = newbuflen;
        }
        msgsize = recv(fd, buffer, buflen, MSG_DONTWAIT);
    }

    if (msgsize < 0) {
        switch (errno) {
        case EAGAIN:
            msgsize = 0;
            break;
        case ENOTSOCK:
            msgsize = -1;
            logprintf(STDERR_FILENO,
                      "Error: must be invoked with stdin connected to Unix domain datagram socket\n");
        default:
            msgsize = -1;
            logprintf(STDERR_FILENO,
                      "Error: reading from parent failed: %s\n",
                      strerror(errno));
        }
    }

    return msgsize;
}

int cuse_lowlevel_main(int argc, char *argv[], const struct cuse_info *ci,
                       const struct cuse_lowlevel_ops *clop, void *userdata)
{
    int ret;
    fd_set readfds;
    ssize_t msgsize;
    int cmd;
    void *input;
    size_t input_size;
    size_t out_bufsz;

    logprintf(STDOUT_FILENO, "%s running\n", argv[0]);
    clop->open(0, NULL);

    while (1) {
        /* wait for requests */
        FD_ZERO(&readfds);
        FD_SET(parentfd, &readfds);
        FD_SET(ioctlfd, &readfds);
        ret = select((parentfd > ioctlfd ? parentfd : ioctlfd) + 1,
                     &readfds, NULL, NULL, NULL);
        if (ret < 0) {
            logprintf(STDERR_FILENO,
                      "Error: select on parent fd failed: %s\n",
                      strerror(errno));
            goto error;
        }

        /* always process out-of-band requests (= ioctl) first */
        while (1) {
            msgsize = from_parent(ioctlfd);
            switch (msgsize) {
            case 0:
                break;
            case -1:
                goto error;
            default:
                if ((size_t)msgsize < sizeof(int)) {
                    logprintf(STDERR_FILENO,
                              "Error: illegal OOB request: input size %lld\n",
                              (long long)msgsize);
                    goto error;
                }
                cmd = *(int *)buffer;
                input = (int *)buffer + 1;
                input_size = msgsize - sizeof(int);
                logprintf(STDOUT_FILENO,
                          " ioctl: %d, size %lld\n",
                          cmd, (long long)input_size);
                /*
                 * Input data was already sent. Output data will
                 * be provided via fuse_reply_ioctl(). However,
                 * we must pretend that the output buffer
                 * was already prepared, because cuse_tpm.c
                 * checks that, depending on the ioctl,
                 * and we need to know the expected size for
                 * that.
                 */
                switch (cmd) {
                case PTM_GET_CAPABILITY:
                    out_bufsz = sizeof(ptm_cap);
                    break;
                case PTM_GET_TPMESTABLISHED:
                    out_bufsz = sizeof(ptm_est);
                    break;
                case PTM_GET_CONFIG:
                    out_bufsz = sizeof(ptm_getconfig);
                    break;
                default:
                    out_bufsz = 0;
                }
                clop->ioctl((void *)&cmd, cmd, userdata, NULL, 0,
                            input, input_size,
                            out_bufsz);
            }
            break;
        }

        /* now deal with one regular write before checking out-of-band again */
        msgsize = from_parent(parentfd);
        switch (msgsize) {
        case 0:
            if (FD_ISSET(parentfd, &readfds)) {
                /*
                 * There should have been at least one message. There's none,
                 * which implies that the fd was ready for reading due to
                 * connection loss.
                 */
                logprintf(STDERR_FILENO,
                          "Error: connection to parent lost\n");
                goto error;
            }
            break;
        case -1:
            goto error;
        default:
            if ((size_t)msgsize < sizeof(int)) {
                logprintf(STDERR_FILENO,
                          "Error: illegal request: msg size %lld\n",
                          (long long)msgsize);
                goto error;
            }
            cmd = *(int *)buffer;
            switch (cmd) {
            case SWTPM_READ_REQUEST: {
                struct swtpm_read_request *request = buffer;
                if ((size_t)msgsize < sizeof(*request)) {
                    logprintf(STDERR_FILENO,
                              "Error: illegal read request: msg size %lld\n",
                              (long long)msgsize);
                    goto error;
                }
                logprintf(STDOUT_FILENO,
                          " read: %lld\n",
                          (long long)request->size);
                clop->read(0, request->size, 0, NULL);
                break;
            }
            case SWTPM_WRITE_REQUEST:
                input = (int *)buffer + 1;
                input_size = msgsize - sizeof(int);
                logprintf(STDOUT_FILENO,
                          " write: %lld\n",
                          (long long)input_size);
                clop->write(0, input, input_size,
                            0, NULL);
                break;
            default:
                logprintf(STDERR_FILENO,
                          "Error: illegal request: cmd %x, msg size %lld\n",
                          cmd, (long long)msgsize);
                goto error;
                break;
            }
            break;
        }
    }

 error:
    if (buffer) {
        free(buffer);
        buffer = 0;
        buflen = 0;
    }
    return 1;
}

static int reply_errno_data(int result, const char *buf, size_t size, int fd)
{
    struct iovec iov[2] = {
        { &result, sizeof(result) },
        { (void *)buf, size }
    };
    struct msghdr msg = {
        .msg_iov = iov,
        .msg_iovlen = 2
    };
    ssize_t written;
    logprintf(STDOUT_FILENO,
              " errno data: %s, errno %d size %lld\n",
              fd == parentfd ? "data" :
              fd == ioctlfd ? "ioctl" :
              "???",
              result,
              (long long)size);
    written = sendmsg(fd, &msg, 0);
    if (written < 0) {
        logprintf(STDERR_FILENO,
                  "Error: sending ioctl result failed: %s\n",
                  strerror(errno));
        return -errno;
    } else if ((size_t)written != sizeof(result) + size) {
        logprintf(STDERR_FILENO,
                  "Error: ioctl result truncated\n");
        return -EPIPE;
    } else {
        return 0;
    }
}

int fuse_reply_buf(fuse_req_t req, const char *buf, size_t size)
{
    return reply_errno_data(0, buf, size, parentfd);
}

int fuse_reply_write(fuse_req_t req, size_t count)
{
    struct swtpm_write_response response = {
        .eno = 0,
        .written = count
    };
    ssize_t written;

    logprintf(STDOUT_FILENO,
              " write: %lld done\n",
              (long long)count);
    written = send(parentfd, &response, sizeof(response), 0);
    if (written < 0) {
        logprintf(STDERR_FILENO,
                  "Error: sending write result failed: %s\n",
                  strerror(errno));
        return -errno;
    } else if ((size_t)written != sizeof(response)) {
        logprintf(STDERR_FILENO,
                  "Error: write result truncated\n");
        return -EPIPE;
    } else {
        return 0;
    }
}


int fuse_reply_err(fuse_req_t req, int err)
{
    ssize_t written;

    logprintf(STDOUT_FILENO,
              " error: %d\n",
              err);
    written = send(parentfd, &err, sizeof(err), 0);
    if (written < 0) {
        logprintf(STDERR_FILENO,
                  "Error: sending result failed: %s\n",
                  strerror(errno));
        return -errno;
    } else if ((size_t)written != sizeof(err)) {
        logprintf(STDERR_FILENO,
                  "Error: result truncated\n");
        return -EPIPE;
    } else {
        return 0;
    }
    return 0;
}

int fuse_reply_ioctl_retry(fuse_req_t req,
			   const struct iovec *in_iov, size_t in_count,
			   const struct iovec *out_iov, size_t out_count)
{
    logprintf(STDERR_FILENO,
              "Error: ioctl %d needs additional data, internal error!\n",
              *(int *)req);
    return -EINVAL;
}

int fuse_reply_ioctl(fuse_req_t req, int result, const void *buf, size_t size)
{
    return reply_errno_data(result, buf, size, ioctlfd);
}

int fuse_reply_open(fuse_req_t req, const struct fuse_file_info *fi)
{
    return 0;
}
