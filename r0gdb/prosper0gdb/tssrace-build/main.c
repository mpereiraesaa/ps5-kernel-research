/* tssrace - the TSS identity-rewrite race probe (port phase 2, rung 3a).
 *
 * Loops the exact r0gdb_setup TSS read-modify-write pattern - copyout the
 * whole 0x68-byte TSS per CPU, write it back IDENTICALLY via copyin - for
 * ~2 seconds across all 16 CPUs. Zero semantic change: pure timing exposure.
 *
 * The theory under test: the scheduler updates TSS rsp0 on every context
 * switch; a switch inside a copyout->copyin window writes back a stale
 * rsp0, corrupting that CPU's ring-0 entry stack. If that race is the
 * ring-0 session killer, even identity rewrites die. If it survives
 * thousands of sweeps (~1000x the single-session exposure), the pattern
 * is exonerated and the ~100-250ms session deaths are elsewhere.
 *
 * MAY KILL THE CONSOLE if the theory is right - that is the signal
 * (owner-approved). Progress prints every 100 sweeps: the last line is
 * the death marker.
 *
 * Diagnostics print to fd 1 (captured by send_elf.py):
 *   [D1] payload_args   [D3] fw version   [D4] r0gdb_init rc
 *   [T1] first full TSS read
 *   [T2] the loop (progress + sweep count)
 *   [T3] post-loop sanity (the payload completing = the machine alive)
 */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <ps5/payload.h>

#include "../r0gdb.h"
#include "../offsets.h"
#include "../../lib/r0gdb-bootstrap.h"

extern int set_offsets(void);
extern uint32_t r0gdb_get_fw_version(void);
extern uint64_t kdata_base;
extern ssize_t copyout(void *dst, uint64_t src, size_t count);
extern ssize_t copyin(uint64_t dst, const void *src, size_t count);

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

#define TSS_N 16
#define TSS_SZ 0x68
#define LOOP_SECONDS 2.0

static unsigned char tss[TSS_N * TSS_SZ];

static double now_sec(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
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

    printf("[D1] args=0x%lx rwpipe=%d,%d rwpair=%d,%d kpipe=0x%lx kdata=0x%lx\n",
           (unsigned long)pargs, pargs->rwpipe[0], pargs->rwpipe[1],
           pargs->rwpair[0], pargs->rwpair[1],
           (unsigned long)pargs->kpipe_addr,
           (unsigned long)pargs->kdata_base_addr);
    fflush(stdout);

    struct r0gdb_bootstrap bootstrap = {
        .magic = R0GDB_BOOTSTRAP_MAGIC,
        .rwpipe = { pargs->rwpipe[0], pargs->rwpipe[1] },
        .kpipe_addr = (uint64_t)pargs->kpipe_addr,
    };

    uint32_t fw = r0gdb_get_fw_version();
    printf("[D3] fw_version=0x%08x ver>>16=0x%x (12.02 expects 0x1202)\n",
           fw, fw >> 16);
    fflush(stdout);

    printf("[D4] r0gdb_init\n");
    fflush(stdout);
    int rc = r0gdb_init(pargs->sys_dynlib_dlsym,
                        pargs->rwpair[0], pargs->rwpair[1],
                        (uintptr_t)&bootstrap, (uintptr_t)pargs->kdata_base_addr);
    printf("[D4] r0gdb_init rc=%d\n", rc);
    fflush(stdout);
    if(rc != 0) {
        *pargs->payloadout = rc;
        return rc;
    }
    *pargs->payloadout = 0;

    /* [T1] the first full TSS read */
    if(copyout(tss, offsets.tss_array, sizeof(tss)) != (ssize_t)sizeof(tss)) {
        printf("[T1] copyout(tss) FAIL\n");
        fflush(stdout);
        return 3;
    }
    printf("[T1] tss read ok (16 cpus x 0x68)\n");
    fflush(stdout);

    /* [T2] the identity-rewrite loop: the exact r0gdb_setup pattern
     * (whole-TSS copyout -> copyin per CPU), identical bytes, ~2s. */
    double t0 = now_sec();
    long sweeps = 0;
    long reports = 0;
    for(;;) {
        for(int cpu = 0; cpu < TSS_N; cpu++) {
            uint64_t t = offsets.tss_array + (uint64_t)cpu * TSS_SZ;
            if(copyout(tss, t, TSS_SZ) != TSS_SZ) {
                printf("[T2] cpu%d copyout FAIL at sweep %ld\n", cpu, sweeps);
                fflush(stdout);
                return 5;
            }
            if(copyin(t, tss, TSS_SZ) != TSS_SZ) {
                printf("[T2] cpu%d copyin FAIL at sweep %ld\n", cpu, sweeps);
                fflush(stdout);
                return 6;
            }
        }
        sweeps++;
        double el = now_sec() - t0;
        if(el >= LOOP_SECONDS)
            break;
        if(sweeps % 100 == 0) {
            reports++;
            printf("[T2] sweeps=%ld elapsed=%.3fs\n", sweeps, el);
            fflush(stdout);
        }
    }
    double el = now_sec() - t0;
    printf("[T2] DONE sweeps=%ld elapsed=%.3fs (reports=%ld)\n",
           sweeps, el, reports);
    fflush(stdout);

    /* [T3] post-loop sanity: a fresh read + kernel-shaped pointers.
     * The payload completing IS the survival signal; the client verifies
     * the console afterwards (ping). */
    if(copyout(tss, offsets.tss_array, sizeof(tss)) != (ssize_t)sizeof(tss)) {
        printf("[T3] post-loop copyout FAIL\n");
        fflush(stdout);
        return 7;
    }
    uint64_t rsp0 = *(const uint64_t *)(&tss[0] + 0x04);
    uint64_t ist3 = *(const uint64_t *)(&tss[0] + 0x34);
    uint64_t ist4 = *(const uint64_t *)(&tss[0] + 0x3c);
    printf("[T3] survived; cpu0 rsp0=0x%llx ist3=0x%llx ist4=0x%llx\n",
           (unsigned long long)rsp0, (unsigned long long)ist3,
           (unsigned long long)ist4);
    fflush(stdout);

    return 0;
}
