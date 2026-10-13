/* idtdump - the IDT/TSS IST-map diagnostic (port phase 2, rung 1).
 *
 * Pure CPL3 reads via the proven copyout pipe primitive (the facs_read
 * class: zero ring-0, no IDT/TSS patching, no rest mode). Purpose:
 *
 *  (a) the IST-redirect hazard map: which of the 256 IDT gates use
 *      IST3/4/6 - the indexes r0gdb_setup redirected machine-wide
 *      (3 slots x 16 CPUs) in every ring-0 session; the leading
 *      [inference] candidate for the unexplained ~100-250ms session
 *      deaths (any such gate rerouted into the shared 2048-byte
 *      gadget_stack);
 *  (b) the port's IST selection data: which IST slots are unused by
 *      the kernel, for the minimal one-gate/one-IST/one-core hook;
 *  (c) text anchors: the exception-handler addresses (kernel text)
 *      for the vectors of interest (1, 9, 13, 179).
 *
 * Diagnostics print to fd 1 (captured by send_elf.py):
 *   [D1] payload_args values   [D3] fw version
 *   [D4] r0gdb_init rc         [I1] IDT copyout
 *   [I2] gate summary           [I3] the IST-user map
 *   [I4] key-vector detail      [I5] TSS IST slots (16 CPUs)
 *   [I6] the IST3/4/6 hazard analysis
 */
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

extern int set_offsets(void);
extern uint32_t r0gdb_get_fw_version(void);
extern uint64_t kdata_base;
extern ssize_t copyout(void *dst, uint64_t src, size_t count);

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

#define NGATES 256
#define TSS_N 16
#define TSS_SZ 0x68
/* TSS IST fields: IST1=+0x24 ... IST7=+0x54 (the layout the r0gdb_setup
 * patch fields 0x34/0x3c/0x4c correspond to IST3/IST4/IST6). */
static const int tss_ist_off[7] = {0x24, 0x2c, 0x34, 0x3c, 0x44, 0x4c, 0x54};

static unsigned char idt[NGATES * 16];
static unsigned char tss[TSS_N * TSS_SZ];

static uint64_t gate_handler(const unsigned char *g)
{
    return (uint64_t)g[0] | ((uint64_t)g[1] << 8)
         | (((uint64_t)g[6] | ((uint64_t)g[7] << 8)) << 16)
         | (((uint64_t)g[8] | ((uint64_t)g[9] << 8)
            | ((uint64_t)g[10] << 16) | ((uint64_t)g[11] << 24)) << 32);
}

static void gate_detail(const char *tag, int v)
{
    const unsigned char *g = &idt[v * 16];
    int ist = g[4] & 7;
    int type = g[5] & 0x1f;
    int dpl = (g[5] >> 5) & 3;
    int present = (g[5] >> 7) & 1;
    uint64_t h = gate_handler(g);
    printf("[%s] v%3d ist=%d type=0x%x dpl=%d p=%d h=0x%llx (kdata%+lld)\n",
           tag, v, ist, type, dpl, present,
           (unsigned long long)h, (long long)(h - kdata_base));
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

    /* [I1] the IDT */
    ssize_t n = copyout(idt, offsets.idt, sizeof(idt));
    printf("[I1] copyout(idt)=%zd/%zu\n", n, sizeof(idt));
    fflush(stdout);
    if(n != (ssize_t)sizeof(idt))
        return 3;

    /* [I2] summary */
    int present = 0, ist_users = 0;
    for(int v = 0; v < NGATES; v++) {
        if(idt[v * 16 + 5] & 0x80)
            present++;
        if(idt[v * 16 + 4] & 7)
            ist_users++;
    }
    printf("[I2] gates present=%d/%d ist_users=%d\n", present, NGATES, ist_users);
    fflush(stdout);

    /* [I3] the IST-user map - the full redirect-hazard data */
    for(int v = 0; v < NGATES; v++) {
        if(idt[v * 16 + 4] & 7)
            gate_detail("I3", v);
    }
    fflush(stdout);

    /* [I4] the key vectors */
    gate_detail("I4", 1);
    gate_detail("I4", 9);
    gate_detail("I4", 13);
    gate_detail("I4", 179);
    fflush(stdout);

    /* [I5] the TSS IST slots, all 16 CPUs */
    n = copyout(tss, offsets.tss_array, sizeof(tss));
    printf("[I5] copyout(tss)=%zd/%zu\n", n, sizeof(tss));
    fflush(stdout);
    if(n != (ssize_t)sizeof(tss))
        return 4;
    for(int cpu = 0; cpu < TSS_N; cpu++) {
        const unsigned char *t = &tss[cpu * TSS_SZ];
        uint64_t ist[7];
        for(int i = 0; i < 7; i++)
            ist[i] = *(const uint64_t *)(t + tss_ist_off[i]);
        printf("[I5] cpu%2d ist1=0x%llx ist2=0x%llx ist3=0x%llx ist4=0x%llx "
               "ist5=0x%llx ist6=0x%llx ist7=0x%llx\n",
               cpu,
               (unsigned long long)ist[0], (unsigned long long)ist[1],
               (unsigned long long)ist[2], (unsigned long long)ist[3],
               (unsigned long long)ist[4], (unsigned long long)ist[5],
               (unsigned long long)ist[6]);
    }
    fflush(stdout);

    /* [I6] the hazard analysis: every gate using IST3/4/6 - the indexes
     * r0gdb_setup redirected machine-wide in every ring-0 session. */
    int haz = 0;
    for(int v = 0; v < NGATES; v++) {
        int ist = idt[v * 16 + 4] & 7;
        if(ist == 3 || ist == 4 || ist == 6) {
            haz++;
            gate_detail("I6", v);
        }
    }
    printf("[I6] gates using IST3/4/6: %d\n", haz);
    fflush(stdout);

    /* [M] the IST-stack activity monitor (rung 2): every natural event on
     * an IST-using vector leaves a frame footprint on that IST stack.
     * Snapshot the top 1 KiB of all 7 IST stacks x 16 CPUs, sleep, snapshot
     * again, diff: the natural event rates, measured with NO patching.
     * The vector->IST map: v8->ist1, v2->ist2, v9/v13->ist3, v1->ist4,
     * v30->ist5, v179->ist6 (shared, all CPUs), v3->ist7. */
    {
#define SNAP_SZ 0x400
        static unsigned char snap_a[TSS_N * 7 * SNAP_SZ];
        static unsigned char snap_b[TSS_N * 7 * SNAP_SZ];
        for(int phase = 0; phase < 2; phase++) {
            unsigned char *dst = phase ? snap_b : snap_a;
            for(int cpu = 0; cpu < TSS_N; cpu++) {
                const unsigned char *t = &tss[cpu * TSS_SZ];
                for(int i = 0; i < 7; i++) {
                    uint64_t ist = *(const uint64_t *)(t + tss_ist_off[i]);
                    /* read the top 1 KiB BELOW the ist value (events push
                     * downward from it) */
                    if(copyout(dst + (cpu * 7 + i) * SNAP_SZ,
                               ist - SNAP_SZ, SNAP_SZ) != SNAP_SZ) {
                        printf("[M] cpu%d ist%d read FAIL at 0x%llx\n",
                               cpu, i + 1, (unsigned long long)ist);
                        fflush(stdout);
                        return 5;
                    }
                }
            }
            if(phase == 0) {
                printf("[M] baseline snapshot taken; sleeping 5s...\n");
                fflush(stdout);
                sleep(5);
            }
        }
        int reports = 0;
        for(int cpu = 0; cpu < TSS_N; cpu++) {
            for(int i = 0; i < 7; i++) {
                const unsigned char *a = snap_a + (cpu * 7 + i) * SNAP_SZ;
                const unsigned char *b = snap_b + (cpu * 7 + i) * SNAP_SZ;
                if(memcmp(a, b, SNAP_SZ) == 0)
                    continue;
                int first = -1, diffbytes = 0;
                for(int k = 0; k < SNAP_SZ; k++) {
                    if(a[k] != b[k]) {
                        if(first < 0)
                            first = k;
                        diffbytes++;
                    }
                }
                uint64_t ist = *(const uint64_t *)
                    (&tss[cpu * TSS_SZ] + tss_ist_off[i]);
                printf("[M] cpu%2d ist%d ACTIVE: %d bytes changed "
                       "(first at top-0x%x; ist=0x%llx)\n",
                       cpu, i + 1, diffbytes, SNAP_SZ - first,
                       (unsigned long long)ist);
                reports++;
            }
        }
        printf("[M] active IST stacks: %d (of %d)\n", reports, TSS_N * 7);
        fflush(stdout);
    }

    return 0;
}
