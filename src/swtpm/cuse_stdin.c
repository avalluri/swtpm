/********************************************************************************/
/*                                                                              */
/*                            CUSE TPM                                          */
/*                     IBM Thomas J. Watson Research Center                     */
/*                                                                              */
/* (c) Copyright IBM Corporation 2014-2015.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/*
 * Authors:
 *     Eric Richter, erichte@us.ibm.com
 *     Stefan Berger, stefanb@us.ibm.com
 *     David Safford, safford@us.ibm.com
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>
#include <limits.h>
#include <errno.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <fuse/cuse_lowlevel.h>

#include <glib.h>

#include "swtpm.h"
#include "common.h"
#include "tpmstate.h"
#include "pidfile.h"
#include "logging.h"
#include "tpm_ioctl.h"
#include "swtpm_nvfile.h"
#include "tpmlib.h"
#include "main.h"
#include "utils.h"

static int datafd = -1, ioctlfd = -1;
static pid_t child = 0;


#if GLIB_MAJOR_VERSION >= 2
# if GLIB_MINOR_VERSION >= 32

GMutex file_ops_lock;
#  define FILE_OPS_LOCK &file_ops_lock

# else

GMutex *file_ops_lock;
#  define FILE_OPS_LOCK file_ops_lock

# endif
#else

#error Unsupport glib version

#endif

static struct cuse_param {
    char *logging;
    char *command;
} param;


/*********************************** data *************************************/

static const char *usage =
"usage: %s %s [options]\n"
"\n"
"The following options are supported:\n"
"\n"
"-n NAME|--name=NAME :  device name (mandatory)\n"
"-M MAJ|--maj=MAJ    :  device major number\n"
"-m MIN|--min=MIN    :  device minor number\n"
"--key file=<path>[,mode=aes-cbc][,format=hex|binary][,remove=[true|false]]\n"
"                    :  use an AES key for the encryption of the TPM's state\n"
"                       files; use the given mode for the block encryption;\n"
"                       the key is to be provided as a hex string or in binary\n"
"                       format; the keyfile can be automatically removed using\n"
"                       the remove parameter\n"
"--key pwdfile=<path>[,mode=aes-cbc][,remove=[true|false]]\n"
"                    :  provide a passphrase in a file; the AES key will be\n"
"                       derived from this passphrase\n"
"--migration-key file=<path>[,mode=aes-cbc][,format=hex|binary][,remove=[true|false]]\n"
"                    :  use an AES key for the encryption of the TPM's state\n"
"                       when it is retrieved from the TPM via ioctls;\n"
"                       Setting this key ensures that the TPM's state will always\n"
"                       be encrypted when migrated\n"
"--migration-key pwdfile=<path>[,mode=aes-cbc][,remove=[true|false]]\n"
"                    :  provide a passphrase in a file; the AES key will be\n"
"                       derived from this passphrase\n"
"--log file=<path>|fd=<filedescriptor>\n"
"                    :  write the TPM's log into the given file rather than\n"
"                       to the console; provide '-' for path to avoid logging\n"
"--pid file=<path>   :  write the process ID into the given file\n"
"--tpmstate dir=<dir>\n"
"                    :  set the directory where the TPM's state will be written\n"
"                       into; the TPM_PATH environment variable can be used\n"
"                       instead\n"
"-r|--runas <user>   :  after creating the CUSE device, change to the given\n"
"                       user\n"
""
"-h|--help           :  display this help screen and terminate\n"
"\n";



/*
 * ptm_read: interface to POSIX read()
 *
 * @req: fuse_req_t
 * @size: number of bytes to read
 * @off: offset (not used)
 * @fi: fuse_file_info (not used)
 *
 * Depending on the current state of the transfer interface (read/write)
 * return either the results of TPM commands or a data of a TPM state blob.
 */
static void ptm_read(fuse_req_t req, size_t size, off_t off,
                     struct fuse_file_info *fi)
{
    struct swtpm_read_request request = {
        SWTPM_READ_REQUEST,
        size
    };
    ssize_t transferred;
    char *buf;

    logprintf(STDOUT_FILENO, "  read, child %lld, fds %d/%d, %lld bytes\n",
              (long long)child, datafd, ioctlfd, (long long)size);

    /* prevent other threads from writing or doing ioctls */
    g_mutex_lock(FILE_OPS_LOCK);
    buf = malloc(size);

    if (!buf) {
        logprintf(STDOUT_FILENO,
                  "Error: read out of memory\n");
        fuse_reply_err(req, ENOMEM);
    } else {
        logprintf(STDOUT_FILENO,
                  "   read: sending %lld\n",
                  (long long)sizeof(request));
        transferred = send(datafd, &request, sizeof(request), 0);
        logprintf(STDOUT_FILENO,
                  "   read: sent %lld, %s\n",
                  (long long)transferred,
                  transferred < 0 ? strerror(errno) : "okay");
        if (transferred < 0) {
            logprintf(STDERR_FILENO,
                      "Error: sending read failed: %s\n",
                      strerror(errno));
            fuse_reply_err(req, errno);
        } else if ((size_t)transferred != sizeof(request)) {
            logprintf(STDERR_FILENO,
                      "Error: sending read truncated\n");
            fuse_reply_err(req, errno);
        } else {
            int eno;
            struct iovec iov[2] = {
                { &eno, sizeof(eno) },
                { buf, size }
            };
            struct msghdr msg = {
                .msg_iov = iov,
                .msg_iovlen = 2
            };

            logprintf(STDOUT_FILENO,
                      "   read: expecting %lld\n",
                      (long long)(sizeof(eno) + size));
            transferred = recvmsg(datafd, &msg, 0);
            logprintf(STDOUT_FILENO,
                      "   read: received %lld, %s\n",
                      (long long)transferred,
                      transferred < 0 ? strerror(errno) : "okay");
            if (transferred < 0) {
                logprintf(STDERR_FILENO,
                          "Error: receiving read response failed: %s\n",
                          strerror(errno));
                fuse_reply_err(req, errno);
            } else if ((size_t)transferred < sizeof(eno)) {
                logprintf(STDERR_FILENO,
                          "Error: receiving read response truncated\n");
                fuse_reply_err(req, EPIPE);
            } else if (eno) {
                logprintf(STDOUT_FILENO,
                          "  read: %s\n",
                          strerror(eno));
                fuse_reply_err(req, eno);
            } else {
                size_t read = transferred - sizeof(eno);
                logprintf(STDOUT_FILENO,
                          "  read: %llu\n",
                          (long long)read);
                fuse_reply_buf(req, buf, read);
            }
        }
    }

    free(buf);
    g_mutex_unlock(FILE_OPS_LOCK);
}



/*
 * ptm_write: low-level write() interface
 */
static void ptm_write(fuse_req_t req, const char *buf, size_t size,
                      off_t off, struct fuse_file_info *fi)
{
    static int cmd = SWTPM_WRITE_REQUEST;
    struct iovec iov[2] = {
        { &cmd, sizeof(cmd) },
        { (void *)buf, size }
    };
    struct msghdr msg = {
        .msg_iov = iov,
        .msg_iovlen = 2
    };
    struct swtpm_write_response response;
    ssize_t transferred;

    logprintf(STDOUT_FILENO, "  write, child %lld, fds %d/%d, %lld bytes\n",
              (long long)child, datafd, ioctlfd, (long long)size);

    /* prevent other threads from writing or doing ioctls */
    g_mutex_lock(FILE_OPS_LOCK);

    logprintf(STDOUT_FILENO,
              "   write: sending %lld\n",
              (long long)(sizeof(cmd) + size));
    transferred = sendmsg(datafd, &msg, 0);
    logprintf(STDOUT_FILENO,
              "   write: sent %lld, %s\n",
              (long long)transferred,
              transferred < 0 ? strerror(errno) : "okay");
    if (transferred < 0) {
        logprintf(STDERR_FILENO,
                  "Error: sending write failed: %s\n",
                  strerror(errno));
        fuse_reply_err(req, errno);
    } else if ((size_t)transferred != sizeof(cmd) + size) {
        logprintf(STDERR_FILENO,
                  "Error: sending write truncated\n");
        fuse_reply_err(req, errno);
    } else {
        logprintf(STDOUT_FILENO,
                  "   write: expecting %lld\n",
                  (long long)sizeof(response));
        transferred = recv(datafd, &response, sizeof(response), 0);
        logprintf(STDOUT_FILENO,
                  "   write: received %lld, %s\n",
                  (long long)transferred,
                  transferred < 0 ? strerror(errno) : "okay");
        if (transferred < 0) {
            logprintf(STDERR_FILENO,
                      "Error: receiving write response failed: %s\n",
                      strerror(errno));
            fuse_reply_err(req, errno);
        } else if (transferred != sizeof(response)) {
            logprintf(STDERR_FILENO,
                      "Error: receiving write response truncated\n");
            fuse_reply_err(req, errno);
        } else if (response.eno) {
            logprintf(STDOUT_FILENO,
                      "  write: %s\n",
                      strerror(response.eno));
            fuse_reply_err(req, response.eno);
        } else {
            logprintf(STDOUT_FILENO,
                      "  write: %lld\n",
                      (long long)response.written);
            fuse_reply_write(req, response.written);
        }
    }

    g_mutex_unlock(FILE_OPS_LOCK);
}

/*
 * ptm_open: interface to POSIX open()
 */
static void ptm_open(fuse_req_t req, struct fuse_file_info *fi)
{
    int fds[4] = { -1, -1, -1, -1 };
    int i;

    logprintf(STDOUT_FILENO, "  opening, child %lld, fds %d/%d\n", (long long)child, datafd, ioctlfd);

    /* Can be opened at most once at a time. */
    if (datafd >= 0) {
        logprintf(STDOUT_FILENO, "  already in use\n");
        errno = EBUSY;
        goto error;
    }

    /*
     * We want to preserve the message boundaries *and* detect connection loss,
     * hence SEQPACKET.
     */
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) ||
        socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds + 2)) {
        logprintf(STDOUT_FILENO, "  socketpair: %s\n", strerror(errno));
        goto error;
    }
    logprintf(STDOUT_FILENO, "  starting: %s\n", param.command);
    child = fork();
    if (child < 0) {
        logprintf(STDOUT_FILENO, "   fork: %s\n", strerror(errno));
        goto error;
    } else if (!child) {
        /* Close parent sides, move to fds where expected by child (0 and 3). */
        close(fds[0]);
        dup2(fds[1], 0);
        close(fds[1]);
        close(fds[2]);
        dup2(fds[3], 3);
        close(fds[3]);
        execl("/bin/sh", "swtpm_cuse_stdin", "-c", param.command, NULL);
        exit(1);
    }
    logprintf(STDOUT_FILENO, "   child %lld ready\n", (long long)child);
    datafd = fds[0];
    close(fds[1]);
    ioctlfd = fds[2];
    close(fds[3]);
    fuse_reply_open(req, fi);
    return;

 error:
    for (i = 0; i < 4; i++ ) {
        if (fds[i] >= 0) {
            close(fds[i]);
        }
    }
    fuse_reply_err(req, errno);
}

/*
 * ptm_release: interface to POSIX close()
 */
static void ptm_release(fuse_req_t req, struct fuse_file_info *fi)
{
    logprintf(STDOUT_FILENO, "  closing, child %lld, fds %d/%d\n", (long long)child, datafd, ioctlfd);
    if (datafd >= 0) {
        close(datafd);
        datafd = -1;
    }
    if (ioctlfd >= 0) {
        close(ioctlfd);
        ioctlfd = -1;
    }
    if (child) {
        waitpid(child, NULL, 0);
        child = 0;
    }
    fuse_reply_err(req, 0);
}


static void do_ioctl(fuse_req_t req, int cmd,
                     const void *in_buf, size_t in_bufsz,
                     void *out_buf, size_t out_bufsz)
{
    int result;
    struct iovec request_iov[2] = {
        { &cmd, sizeof(cmd) },
        { (void *)in_buf, in_bufsz }
    };
    struct msghdr request_msg = {
        .msg_iov = request_iov,
        .msg_iovlen = 2
    };
    ssize_t transferred;
    logprintf(STDOUT_FILENO,
              "   ioctl sending %lld\n",
              (long long)(sizeof(cmd) + in_bufsz));
    transferred = sendmsg(ioctlfd, &request_msg, 0);
    if (transferred < 0) {
        logprintf(STDERR_FILENO,
                  "Error: sending ioctl failed: %s",
                  strerror(errno));
        result = errno;
    } else if ((size_t)transferred != sizeof(cmd) + in_bufsz) {
        logprintf(STDERR_FILENO,
                  "Error: ioctl truncated\n");
        result = EPIPE;
    } else {
        struct iovec response_iov[2] = {
            { &result, sizeof(result) },
            { out_buf, out_bufsz }
        };
        struct msghdr response_msg = {
            .msg_iov = response_iov,
            .msg_iovlen = 2
        };
        logprintf(STDOUT_FILENO,
                  "   ioctl receiving %lld\n",
                  (long long)(sizeof(result) + out_bufsz));
        transferred = recvmsg(ioctlfd, &response_msg, 0);
        if (transferred < 0) {
            logprintf(STDERR_FILENO,
                      "Error: receiving ioctl failed: %s\n",
                      strerror(errno));
            result = errno;
        } else if ((size_t)transferred != sizeof(result) + out_bufsz) {
            logprintf(STDERR_FILENO,
                      "Error: ioctl response truncated\n");
            result = EPIPE;
        } else {
            logprintf(STDOUT_FILENO,
                      "  ioctl done, %d\n",
                      result);
        }

    }
    fuse_reply_ioctl(req, result, out_buf, out_bufsz);
}

/*
 * ptm_ioctl : ioctl execution
 *
 * req: the fuse_req_t used to send response with
 * cmd: the ioctl request code
 * arg: the pointer the application used for calling the ioctl (3rd param)
 * fi:
 * flags: some flags provided by fuse
 * in_buf: the copy of the input buffer
 * in_bufsz: size of the input buffer; provided by fuse and has size of
 *           needed buffer
 * out_bufsz: size of the output buffer; provided by fuse and has size of
 *            needed buffer
 */
static void ptm_ioctl(fuse_req_t req, int cmd, void *arg,
                      struct fuse_file_info *fi, unsigned flags,
                      const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
    if (flags & FUSE_IOCTL_COMPAT) {
        fuse_reply_err(req, ENOSYS);
        return;
    }

    logprintf(STDOUT_FILENO, "  ioctl %d %lld/%lld, child %lld, fds %d/%d\n",
              cmd, (long long)in_bufsz, (long long)out_bufsz,
              (long long)child, datafd, ioctlfd);

    /* prevent other threads from writing or doing ioctls */
    g_mutex_lock(FILE_OPS_LOCK);

    switch (cmd) {
    case PTM_GET_CAPABILITY:
        if (out_bufsz != sizeof(ptm_cap)) {
            struct iovec iov = { arg, sizeof(uint8_t) };
            fuse_reply_ioctl_retry(req, NULL, 0, &iov, 1);
        } else {
            ptm_cap ptm_caps;
            do_ioctl(req, cmd, NULL, 0, &ptm_caps, sizeof(ptm_caps));
        }
        break;

    case PTM_INIT:
        if (in_bufsz != sizeof(ptm_init)) {
            struct iovec iov = { arg, sizeof(uint8_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_init *init_p = (void *)in_buf;
            do_ioctl(req, cmd, init_p, sizeof(*init_p), init_p, sizeof(*init_p));
        }
        break;

    case PTM_STOP:
    case PTM_SHUTDOWN:
    case PTM_HASH_START:
    case PTM_HASH_END:
    case PTM_CANCEL_TPM_CMD:
    case PTM_STORE_VOLATILE:
        if (out_bufsz != sizeof(TPM_RESULT)) {
            struct iovec iov = { arg, sizeof(TPM_RESULT) };
            fuse_reply_ioctl_retry(req, NULL, 0, &iov, 1);
        } else {
            TPM_RESULT res;
            do_ioctl(req, cmd, NULL, 0, &res, sizeof(res));
        }
        break;

    case PTM_GET_TPMESTABLISHED:
        if (out_bufsz != sizeof(ptm_est)) {
            struct iovec iov = { arg, sizeof(ptm_est) };
            fuse_reply_ioctl_retry(req, NULL, 0, &iov, 1);
        } else {
            ptm_est te;
            do_ioctl(req, cmd, NULL, 0, &te, sizeof(te));
        }
        break;

    case PTM_RESET_TPMESTABLISHED:
        if (in_bufsz != sizeof(ptm_reset_est)) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            TPM_RESULT res;
            do_ioctl(req, cmd, in_buf, in_bufsz, &res, sizeof(res));
        }
        break;

    case PTM_SET_LOCALITY:
        if (in_bufsz != sizeof(ptm_loc)) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_loc *l = (ptm_loc *)in_buf;
            do_ioctl(req, cmd, in_buf, in_bufsz, l, sizeof(*l));
        }
        break;

    case PTM_HASH_DATA:
        if (in_bufsz != sizeof(ptm_hdata)) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_hdata *data = (ptm_hdata *)in_buf;
            do_ioctl(req, cmd, in_buf, in_bufsz, data, sizeof(*data));
        }
        break;

    case PTM_GET_STATEBLOB:
        if (in_bufsz != sizeof(ptm_getstate)) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_getstate *pgs = (void *)in_buf;
            do_ioctl(req, cmd, in_buf, in_bufsz, pgs, sizeof(pgs->u.resp));
        }
        break;

    case PTM_SET_STATEBLOB:
        if (in_bufsz != sizeof(ptm_setstate)) {
            struct iovec iov = { arg, sizeof(uint32_t) };
            fuse_reply_ioctl_retry(req, &iov, 1, NULL, 0);
        } else {
            ptm_setstate *pss = (void *)in_buf;
            /* yes, sizeof(pss) instead of sizeof(pss->resp) - SET/GET are handled differently */
            do_ioctl(req, cmd, in_buf, in_bufsz, pss, sizeof(pss));
        }
        break;

    case PTM_GET_CONFIG:
        if (out_bufsz != sizeof(ptm_getconfig)) {
            struct iovec iov = { arg, sizeof(ptm_getconfig) };
            fuse_reply_ioctl_retry(req, NULL, 0, &iov, 1);
        } else {
            ptm_getconfig pgs;
            do_ioctl(req, cmd, NULL, 0, &pgs, sizeof(pgs));
        }
        break;

    default:
        fuse_reply_err(req, EINVAL);
    }

    g_mutex_unlock(FILE_OPS_LOCK);
}

static const struct cuse_lowlevel_ops clops = {
    .open = ptm_open,
    .release = ptm_release,
    .read = ptm_read,
    .write = ptm_write,
    .ioctl = ptm_ioctl,
};

int main(int argc, char **argv)
{
    const char *prgname = argv[0];
    const char *iface = "";
    int opt, longindex = 0;
    static struct option longopts[] = {
        {"maj"           , required_argument, 0, 'M'},
        {"min"           , required_argument, 0, 'm'},
        {"name"          , required_argument, 0, 'n'},
        {"log"           , required_argument, 0, 'l'},
        {"command"       , required_argument, 0, 'c'},
        {"help"          ,       no_argument, 0, 'h'},
        {"version"       ,       no_argument, 0, 'v'},
        {NULL            , 0                , 0, 0  },
    };
    struct cuse_info cinfo;
    const char *devname = NULL;
    char *cinfo_argv[1];
    unsigned int num;
    int n, tpmfd;
    char path[PATH_MAX];

    memset(&cinfo, 0, sizeof(cinfo));
    memset(&param, 0, sizeof(param));

    while (true) {
        opt = getopt_long(argc, argv, "M:m:n:l:c:hv", longopts, &longindex);

        if (opt == -1)
            break;

        switch (opt) {
        case 'M': /* major */
            if (sscanf(optarg, "%u", &num) != 1) {
                fprintf(stderr, "Could not parse major number\n");
                return -1;
            }
            if (num > 65535) {
                fprintf(stderr, "Major number outside valid range [0 - 65535]\n");
                return -1;
            }
            cinfo.dev_major = num;
            break;
        case 'm': /* minor */
            if (sscanf(optarg, "%u", &num) != 1) {
                fprintf(stderr, "Could not parse major number\n");
                return -1;
            }
            if (num > 65535) {
                fprintf(stderr, "Major number outside valid range [0 - 65535]\n");
                return -1;
            }
            cinfo.dev_minor = num;
            break;
        case 'n': /* name */
            if (!cinfo.dev_info_argc) {
                cinfo_argv[0] = calloc(1, strlen("DEVNAME=") + strlen(optarg) + 1);
                if (!cinfo_argv[0]) {
                    fprintf(stderr, "Out of memory\n");
                    return -1;
                }
                devname = optarg;

                strcpy(cinfo_argv[0], "DEVNAME=");
                strcat(cinfo_argv[0], optarg);

                cinfo.dev_info_argc = 1;
                cinfo.dev_info_argv = (const char **)cinfo_argv;
            }
            break;
        case 'l': /* log */
            param.logging = optarg;
            break;
        case 'c': /* command */
            param.command = optarg;
            break;
        case 'h': /* help */
            fprintf(stdout, usage, prgname, iface);
            return 0;
        case 'v': /* version */
            fprintf(stdout, "TPM emulator CUSE interface version %d.%d.%d, "
                    "Copyright (c) 2014-2015 IBM Corp.\n",
                    SWTPM_VER_MAJOR,
                    SWTPM_VER_MINOR,
                    SWTPM_VER_MICRO);
            return 0;
        }
    }

    if (!cinfo.dev_info_argv) {
        fprintf(stderr, "Error: device name missing\n");
        return -2;
    }

    if (!param.command || !param.command[0]) {
        fprintf(stderr, "Error: swtpm_stdin command missing\n");
        return -2;
    }

    if (handle_log_options(param.logging) < 0)
        return -3;

    n = snprintf(path, sizeof(path), "/dev/%s", devname);
    if (n < 0) {
        fprintf(stderr,
                "Error: Could not create device file name\n");
        return -1;
    }
    if (n >= (int)sizeof(path)) {
        fprintf(stderr,
                "Error: Buffer too small to create device file name\n");
        return -1;
    }

    tpmfd = open(path, O_RDWR);
    if (tpmfd >= 0) {
        close(tpmfd);
        fprintf(stderr,
                "Error: A device '%s' already exists.\n",
                path);
        return -1;
    }

#if GLIB_MINOR_VERSION >= 32
    g_mutex_init(FILE_OPS_LOCK);
#else
    FILE_OPS_LOCK = g_mutex_new();
#endif

    logprintf(STDOUT_FILENO, " ready to run\n");
    return cuse_lowlevel_main(1, argv, &cinfo, &clops, &param);
}
