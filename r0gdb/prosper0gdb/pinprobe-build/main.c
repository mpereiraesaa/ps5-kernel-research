/* pinprobe - find the working cpuset_setaffinity invocation (pure CPL3,
 * zero risk: init + syscall combinatorics + exit; nothing is patched).
 *
 * The minchain rung aborted correctly at its pre-patch pin gate:
 * cpuset_setaffinity (raw syscall 488) returned 1 with our args
 * (level=CPU_LEVEL_WHICH, which=CPU_WHICH_TID, own tid, size 16,
 * mask cpu0) - FreeBSD raw syscalls return the positive errno (1 =
 * EPERM) with CF set, which the caller must check. This probe tries
 * the argument matrix and reports raw returns + carry flags:
 *   levels: 0 (ROOT), 1 (CPUSET), 2 (WHICH)
 *   which:  1 (TID), 2 (PID)
 *   size:   16, 32, 64 (the PS5 cpuset_t size is unverified)
 * plus a getaffinity (487) read for each size to learn the native
 * cpuset layout. */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <ps5/payload.h>

#include "../r0gdb.h"
#include "../offsets.h"
#include "../../lib/r0gdb-bootstrap.h"

extern uint64_t kdata_base;

extern char __image_end[];

extern int sysctl(int *, unsigned int, void *, unsigned long *, const void *,
                  unsigned long);
int __sysctl(const int *name, unsigned int namelen, void *oldp,
             unsigned long *oldlenp, const void *newp, unsigned long newlen);
int __sysctl(const int *name, unsigned int namelen, void *oldp,
             unsigned long *oldlenp, const void *newp, unsigned long newlen)
{
    return sysctl((int *)name, namelen, oldp, oldlenp, newp, newlen);
}

/* raw syscall with the carry flag captured - FreeBSD returns the
 * positive errno with CF set on failure, 0 with CF clear on success */
static long rsc(long nr, long a, long b, long c, long d, long e, int *cf)
{
    long ret;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory", "cc");
    *cf = 0;
    /* re-sample carry via a pushfq: cheap and precise */
    unsigned long flags;
    __asm__ volatile("pushfq\n\tpopq %0\n\t" : "=r"(flags));
    *cf = (int)(flags & 1);
    return ret;
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    signal(SIGPIPE, SIG_IGN);

    payload_args_t *pargs = payload_get_args();
    if(!pargs || !pargs->sys_dynlib_dlsym || !pargs->rwpipe || !pargs->rwpair ||
       !pargs->payloadout || !pargs->kpipe_addr || !pargs->kdata_base_addr) {
        printf("[D1] FAIL: incomplete payload_args\n");
        fflush(stdout);
        return 2;
    }
    *pargs->payloadout = 1;

    struct r0gdb_bootstrap bootstrap = {
        .magic = R0GDB_BOOTSTRAP_MAGIC,
        .rwpipe = { pargs->rwpipe[0], pargs->rwpipe[1] },
        .kpipe_addr = (uint64_t)pargs->kpipe_addr,
    };

    int rc = r0gdb_init(pargs->sys_dynlib_dlsym,
                        pargs->rwpair[0], pargs->rwpair[1],
                        (uintptr_t)&bootstrap, (uintptr_t)pargs->kdata_base_addr);
    printf("[D4] r0gdb_init rc=%d (fw=0x%08x)\n",
           rc, r0gdb_get_fw_version());
    fflush(stdout);
    if(rc != 0) {
        *pargs->payloadout = rc;
        return rc;
    }
    *pargs->payloadout = 0;

    /* [P1] thr_self */
    int cf = 0;
    long tid = -1;
    long r = rsc(432, (long)&tid, 0, 0, 0, 0, &cf);
    printf("[P1] thr_self(432): ret=%ld cf=%d tid=%ld\n", r, cf, tid);
    fflush(stdout);
    if(r != 0 || tid < 0)
        return 3;

    /* [P2] getaffinity matrix (487): learn the native cpuset size */
    static unsigned char mask[64];
    for(int size = 16; size <= 64; size <<= 1) {
        memset(mask, 0, sizeof(mask));
        r = rsc(487, 2 /*LEVEL_WHICH*/, 1 /*WHICH_TID*/, tid, size,
                (long)mask, &cf);
        printf("[P2] getaffinity(487, lvl=2, tid, size=%d): ret=%ld cf=%d "
               "mask=%02x%02x%02x%02x...\n",
               size, r, cf, mask[0], mask[1], mask[2], mask[3]);
        fflush(stdout);
    }

    /* [P3] setaffinity matrix (488) */
    static const int levels[] = {0, 1, 2};
    static const int whiches[] = {1 /*TID*/, 2 /*PID*/};
    for(int li = 0; li < 3; li++) {
        for(int wi = 0; wi < 2; wi++) {
            for(int size = 16; size <= 64; size <<= 1) {
                memset(mask, 0, sizeof(mask));
                mask[0] = 1; /* cpu 0 */
                long id = (whiches[wi] == 1) ? tid : (long)getpid();
                r = rsc(488, levels[li], whiches[wi], id, size,
                        (long)mask, &cf);
                printf("[P3] setaffinity(488, lvl=%d, which=%d, id=%ld, "
                       "size=%d, cpu0): ret=%ld cf=%d\n",
                       levels[li], whiches[wi], id, size, r, cf);
                fflush(stdout);
                if(r == 0 && !cf) {
                    /* verify with a getaffinity readback */
                    memset(mask, 0, sizeof(mask));
                    long g = rsc(487, 2, 1, tid, size, (long)mask, &cf);
                    printf("[P3]   -> SUCCESS; readback ret=%ld cf=%d "
                           "mask=%02x%02x...\n",
                           g, cf, mask[0], mask[1]);
                    fflush(stdout);
                    return 0;
                }
            }
        }
    }

    printf("[PX] no working setaffinity invocation found\n");
    fflush(stdout);
    return 1;
}
