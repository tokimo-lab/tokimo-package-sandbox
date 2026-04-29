/*
 * vsock9p — minimal vsock-based 9p mount helper for Windows HCS.
 * Vendored from tokimo-lab/tokimo-package-rootfs.
 *
 * Usage: vsock9p <target_dir> <port> <aname>
 *
 * Connects to AF_VSOCK port=<port> on the host CID, then issues a 9p mount
 * over that fd at <target_dir> with aname=<aname>.
 *
 * Compile: gcc -static -O2 -o vsock9p vsock9p.c
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <unistd.h>

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif
#ifndef VMADDR_CID_HOST
#define VMADDR_CID_HOST 2
#endif

struct sockaddr_vm {
    unsigned short svm_family;
    unsigned short svm_reserved1;
    unsigned int   svm_port;
    unsigned int   svm_cid;
    unsigned char  svm_zero[sizeof(struct sockaddr) -
                            sizeof(unsigned short) -
                            sizeof(unsigned short) -
                            sizeof(unsigned int) -
                            sizeof(unsigned int)];
};

int main(int argc, char *argv[])
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <target> <port> <aname>\n", argv[0]);
        return 64;
    }
    const char *target = argv[1];
    unsigned int port  = (unsigned int)strtoul(argv[2], NULL, 10);
    const char *aname  = argv[3];

    int fd = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "vsock9p: socket(AF_VSOCK) errno=%d (%s)\n",
                errno, strerror(errno));
        return 1;
    }

    struct sockaddr_vm sa;
    memset(&sa, 0, sizeof(sa));
    sa.svm_family = AF_VSOCK;
    sa.svm_cid    = VMADDR_CID_HOST;
    sa.svm_port   = port;

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "vsock9p: connect cid=%u port=%u errno=%d (%s)\n",
                sa.svm_cid, sa.svm_port, errno, strerror(errno));
        close(fd);
        return 2;
    }

    char opts[512];
    snprintf(opts, sizeof(opts),
             "trans=fd,rfdno=%d,wfdno=%d,msize=262144,aname=%s,cache=mmap",
             fd, fd, aname);

    if (mount("none", target, "9p",
              MS_NOATIME | MS_NOSUID | MS_NODEV, opts) < 0) {
        fprintf(stderr, "vsock9p: mount 9p target=%s errno=%d (%s) opts=%s\n",
                target, errno, strerror(errno), opts);
        close(fd);
        return 3;
    }

    close(fd);
    return 0;
}
