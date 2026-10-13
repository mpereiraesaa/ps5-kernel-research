/* minpatch - the minimal one-shot patch test (port phase 2, rung 4).
 *
 * Validates the port's core patch machinery live, in the port's own
 * execution model - the minimal footprint, single-qword writes only:
 *
 *   - ONE IDT gate (vector 1, #DB - measured quiet by rung 2 over 5s)
 *     re-encoded with the real port content: the kstuff pivot
 *     (swapgs_add_rsp_iret, the gate-target class proven by r0gdb_setup)
 *   - ONE TSS IST slot (cpu0's IST4 - v1's stack) via a single-qword
 *     copyin: the race-free pattern (NEVER the whole-TSS
 *     read-modify-write - rung 3a proved it lethal at ~3e-4/sweep)
 *   - the IST value points at cpu1's real IST4 stack (a valid kernel
 *     stack; nothing fires v1 naturally, so the value is never used)
 *   - hold ~1s, restore via single-qword writes, verify the restore,
 *     exit; the client then verifies the console (ping)
 *
 * Verdict logic: survives = the minimal patch class (one gate + one
 * IST + single-qword writes + a 1s hold) is validated live - the
 * port's foundation, and the session deaths are confirmed
 * gdb-session-specific rather than patch-class-wide. Dies = the
 * patch class itself is implicated and the port design needs
 * rework before any further live step.
 *
 * Gate write order: hi first, lo last (the lo carries present/ist/
 * type - it is the activation word; Byepervisor's khook does the
 * same).
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

#define VEC_DB 1
#define TSS_STRIDE 0x68
#define IST4_OFF 0x3c
#define HOLD_SECONDS 1

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

    /* [P1] save the originals */
    uint64_t db_gate = offsets.idt + (uint64_t)VEC_DB * 16;
    uint64_t ist4_cpu0 = offsets.tss_array + 0 * TSS_STRIDE + IST4_OFF;
    uint64_t ist4_cpu1 = offsets.tss_array + 1 * TSS_STRIDE + IST4_OFF;

    unsigned char gate_orig[16];
    uint64_t ist4_orig, ist4_cpu1_val;
    if(copyout(gate_orig, db_gate, 16) != 16) {
        printf("[P1] copyout(gate) FAIL\n");
        fflush(stdout);
        return 3;
    }
    if(copyout(&ist4_orig, ist4_cpu0, 8) != 8 ||
       copyout(&ist4_cpu1_val, ist4_cpu1, 8) != 8) {
        printf("[P1] copyout(ist4) FAIL\n");
        fflush(stdout);
        return 3;
    }
    uint64_t gate_orig_lo, gate_orig_hi;
    memcpy(&gate_orig_lo, gate_orig, 8);
    memcpy(&gate_orig_hi, gate_orig + 8, 8);
    uint16_t kcs = (uint16_t)(gate_orig_lo >> 16);
    uint64_t gate_orig_handler = (gate_orig_lo & 0xFFFF)
        | (((gate_orig_lo >> 48) & 0xFFFF) << 16)
        | ((gate_orig_hi & 0xFFFFFFFFULL) << 32);
    printf("[P1] saved: gate lo=0x%llx hi=0x%llx (h=0x%llx sel=0x%x); "
           "ist4_cpu0=0x%llx ist4_cpu1=0x%llx\n",
           (unsigned long long)gate_orig_lo,
           (unsigned long long)gate_orig_hi,
           (unsigned long long)gate_orig_handler, kcs,
           (unsigned long long)ist4_orig,
           (unsigned long long)ist4_cpu1_val);
    if(!kcs || !gate_orig_handler) {
        printf("[P1] FAIL: implausible original gate\n");
        fflush(stdout);
        return 4;
    }

    /* [P2] the new gate: the kstuff pivot as the target (the port's
     * real content), everything else per the original. */
    uint64_t pivot = offsets.swapgs_add_rsp_iret;
    uint64_t gate_lo, gate_hi;
    gate_encode(pivot, kcs, 4 /* ist4 */, 0xE /* interrupt gate */,
                0 /* dpl */, 1 /* present */, &gate_lo, &gate_hi);
    printf("[P2] new gate: pivot=0x%llx lo=0x%llx hi=0x%llx; "
           "ist4_cpu0 := cpu1's ist4 (0x%llx)\n",
           (unsigned long long)pivot,
           (unsigned long long)gate_lo, (unsigned long long)gate_hi,
           (unsigned long long)ist4_cpu1_val);
    fflush(stdout);

    /* [P3] the single-qword writes: gate hi first, lo last (the lo is
     * the activation word); then the IST slot. */
    if(copyin(db_gate + 8, &gate_hi, 8) != 8) {
        printf("[P3] copyin(gate_hi) FAIL\n");
        fflush(stdout);
        return 5;
    }
    if(copyin(db_gate, &gate_lo, 8) != 8) {
        printf("[P3] copyin(gate_lo) FAIL\n");
        fflush(stdout);
        return 5;
    }
    if(copyin(ist4_cpu0, &ist4_cpu1_val, 8) != 8) {
        printf("[P3] copyin(ist4) FAIL\n");
        fflush(stdout);
        return 5;
    }

    /* [P4] readback verify */
    unsigned char gate_now[16];
    uint64_t ist4_now;
    copyout(gate_now, db_gate, 16);
    copyout(&ist4_now, ist4_cpu0, 8);
    uint64_t now_lo, now_hi;
    memcpy(&now_lo, gate_now, 8);
    memcpy(&now_hi, gate_now + 8, 8);
    if(now_lo != gate_lo || now_hi != gate_hi || ist4_now != ist4_cpu1_val) {
        printf("[P4] FAIL: readback mismatch (lo 0x%llx hi 0x%llx ist4 0x%llx)\n",
               (unsigned long long)now_lo, (unsigned long long)now_hi,
               (unsigned long long)ist4_now);
        fflush(stdout);
        return 6;
    }
    printf("[P4] patch verified (gate + ist4 readback ok) - holding %ds...\n",
           HOLD_SECONDS);
    fflush(stdout);

    /* [P5] the hold: the minimal patched window, live */
    sleep(HOLD_SECONDS);

    /* [P6] restore: single-qword writes, the reverse order (lo first,
     * hi last), then the IST */
    if(copyin(db_gate, &gate_orig_lo, 8) != 8 ||
       copyin(db_gate + 8, &gate_orig_hi, 8) != 8 ||
       copyin(ist4_cpu0, &ist4_orig, 8) != 8) {
        printf("[P6] FAIL: restore copyin\n");
        fflush(stdout);
        return 7;
    }

    /* [P7] verify the restore */
    copyout(gate_now, db_gate, 16);
    copyout(&ist4_now, ist4_cpu0, 8);
    memcpy(&now_lo, gate_now, 8);
    memcpy(&now_hi, gate_now + 8, 8);
    if(now_lo != gate_orig_lo || now_hi != gate_orig_hi ||
       ist4_now != ist4_orig) {
        printf("[P7] FAIL: restore mismatch (lo 0x%llx hi 0x%llx ist4 0x%llx)\n",
               (unsigned long long)now_lo, (unsigned long long)now_hi,
               (unsigned long long)ist4_now);
        fflush(stdout);
        return 8;
    }
    printf("[P7] RESTORED + VERIFIED (gate + ist4 == originals)\n");
    fflush(stdout);

    printf("[PX] minpatch complete - the minimal patch class survived "
           "a %ds live hold; the client verifies the console next\n",
           HOLD_SECONDS);
    fflush(stdout);

    return 0;
}
