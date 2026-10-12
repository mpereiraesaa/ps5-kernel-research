/* prosper0gdb elfldr adapter, SDK-crt build (v3, verified live on console).
 *
 * Launches kstuff's prosper0gdb (r0gdb kernel GDB stub) directly from the
 * standard ps5-payload-dev/elfldr on port 9021.
 *
 * Root causes fixed in sequence (all verified on console, see
 * ps5-kernel-research docs/07-evidence.md 2026-10-09):
 *
 *  1. ET_EXEC/-no-pie links collide with the SceSpZeroConf (NPXS40112)
 *     spawn host's own eboot at ~0x400000: the elfldr maps ET_EXEC
 *     payloads with MAP_FIXED at the link base, pt_mmap fails with EINVAL
 *     and the spawn dies before main() ("Error spawning payload" on the
 *     socket; "elfldr.c:190:pt_mmap: Invalid argument" in klog). Every
 *     earlier direct prosper0gdb send died here, at spawn, not at the args.
 *     This build uses the SDK crt + toolchain: ET_DYN, first LOAD at
 *     offset 0x4000/vaddr 0 -- the layout every working SDK payload uses.
 *
 *  2. The kstuff crt-elf/stub layer bootstraps its raw syscall stubs
 *     through addr__dynlib_dlsym, which crt-elf leaves holding the
 *     payload_args pointer; any stub call before repairing it jumps into
 *     the struct and dies. This build drops the kstuff crt and stub layer
 *     entirely: all syscalls go through the SDK crt/libc.
 *
 *  3. The stub's real_dbg_enter() accepts exactly ONE connection and
 *     requires '+' as its first byte; a port probe consumes the listener.
 *     Attach with a client that sends '+' immediately (rsp_proxy.py).
 *
 * prosper0gdb.o (r0gdb+run+offsets, built from this clone) and dbg.o (the
 * GDB stub, compiled against kstuff's freebsd-headers) link as plain
 * objects; their undefined symbols resolve against the SDK libc. _end is
 * bridged via the linker (--defsym,_end=__image_end) and __sysctl is
 * bridged to the SDK sysctl below.
 *
 * Diagnostics print to fd 1 (captured by send_elf.py):
 *   [D1] payload_args values
 *   [D3] fw version raw / >>16 (12.02 must decode to 0x1202)
 *   [D4] r0gdb_init rc
 *   [D5] failure isolation: set_offsets() rc + sysents-kdata (expect 0x1af4d0)
 *   [D6] kread8(allproc head) -- proves socket+pipe primitive stack
 *   [D7] sysent[165].sy_call (sysarch) - kdata_base
 *        (expect 0xffffffffff5c3788 = -0xa3c878; stride 48, sy_call +8,
 *        dump-derived and confirmed live)
 *   [B1] bind probe on port 1234 (raw returns; positive = errno)
 *   [D8] dbg_enter(): binds first free port from 1234, accepts one GDB
 *        session, first byte must be '+'.
 *
 * Console notes: Syscore serializes spawns during game launches -- a
 * payload send can queue behind them (elfldr blocks in kevent/waitpid;
 * send_elf.py reports "timed out; execution result is unknown"). Wait for
 * the game to exit and the spawn completes on its own, or re-send.
 */
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <signal.h>
#include <ps5/payload.h>

#include "../r0gdb.h"
#include "../offsets.h"
#include "../../lib/r0gdb-bootstrap.h"
#include "../../gdb_stub/dbg.h"

extern int set_offsets(void);
extern uint32_t r0gdb_get_fw_version(void);
extern uint64_t kdata_base;

/* prosper0gdb.o (built against kstuff's freebsd-headers) references _end
 * and __sysctl. The SDK ldscript provides __image_end (mapped to _end via
 * the linker --defsym in the Makefile); the SDK libc exports sysctl (not
 * __sysctl). Bridge __sysctl here. */
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

#define SYSENT_STRIDE 48
#define SYSENT_SYSCALL_OFF 8
#define SYSARCH_NUM 165
/* sysent[SYSARCH_NUM].sy_call - kdata_base: sysarch 0xffffffff887d3788 at
 * dump kdata 0xffffffff89210000 (stride 48, sy_call at +8, re-derived
 * against every anchor in payloads/kalias_sweep/runs/sysent_anchors.txt
 * and confirmed live on console 2026-10-09). */
#define EXPECT_SYSARCH_DELTA UINT64_C(0xffffffffff5c3788)

static void bind_probe(void)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    printf("[B1] socket()=%d\n", sock);
    if(sock < 0)
        return;
    int reuse = 1;
    int rc = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    printf("[B1] setsockopt()=%d", rc);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(1234);
    sa.sin_addr.s_addr = 0;
    rc = bind(sock, (struct sockaddr *)&sa, sizeof(sa));
    printf(" bind()=%d", rc);
    if(rc == 0) {
        rc = listen(sock, 1);
        printf(" listen()=%d", rc);
    }
    printf("\n");
    fflush(stdout);
    close(sock);
}

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    /* Block SIGPIPE: the elfldr pipe disconnects after send_elf.py times
     * out, and any subsequent write to stdout (from libc internals, exit
     * handlers, or the SDK crt) would kill the process with SIGPIPE. */
    signal(SIGPIPE, SIG_IGN);

    payload_args_t *pargs = payload_get_args();
    if(!pargs || !pargs->sys_dynlib_dlsym || !pargs->rwpipe || !pargs->rwpair ||
       !pargs->payloadout || !pargs->kpipe_addr || !pargs->kdata_base_addr) {
        printf("[D1] FAIL: incomplete payload_args: pargs=%p dlsym=%p rwpipe=%p "
               "rwpair=%p payloadout=%p kpipe=0x%lx kdata=0x%lx\n",
               (void *)pargs,
               pargs ? (void *)pargs->sys_dynlib_dlsym : NULL,
               pargs ? (void *)pargs->rwpipe : NULL,
               pargs ? (void *)pargs->rwpair : NULL,
               pargs ? (void *)pargs->payloadout : NULL,
               pargs ? (unsigned long)pargs->kpipe_addr : 0,
               pargs ? (unsigned long)pargs->kdata_base_addr : 0);
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
        int orc = set_offsets();
        printf("[D5] isolated set_offsets() rc=%d sysents-kdata=0x%lx "
               "(expect 0x1af4d0)\n",
               orc, (unsigned long)(offsets.sysents - kdata_base));
        fflush(stdout);
        return rc;
    }

    *pargs->payloadout = 0;

    printf("[D6] allproc head=0x%llx\n",
           (unsigned long long)kread8(offsets.allproc));
    fflush(stdout);

    uint64_t sysarch = kread8(offsets.sysents + SYSARCH_NUM * SYSENT_STRIDE +
                              SYSENT_SYSCALL_OFF);
    printf("[D7] sysarch sy_call=0x%llx delta=0x%llx (expect 0x%llx)\n",
           (unsigned long long)sysarch,
           (unsigned long long)(sysarch - kdata_base),
           (unsigned long long)EXPECT_SYSARCH_DELTA);
    fflush(stdout);

    bind_probe();

    /* [D9] GS/TLS diagnostic: the value save_user_gsbase() captured, whether
     * it is usable (valid), and the live FS/GS bases. If valid=0 the GS
     * restore in r0gdb() is a silent no-op and the GS-corruption theory's
     * precondition never held; if FS and GS differ, the errno TLS register
     * matters and restoring the wrong one would not fix anything. */
    printf("[D9] gsbase_saved=0x%llx valid=%d fsbase=0x%llx gsbase=0x%llx\n",
           (unsigned long long)r0gdb_saved_gsbase(),
           r0gdb_saved_gsbase_valid(),
           (unsigned long long)r0gdb_read_fsbase(),
           (unsigned long long)r0gdb_read_gsbase());
    fflush(stdout);

    printf("[D8] dbg_enter: binding first free port from 1234\n");
    fflush(stdout);
    dbg_enter();
    return 0;
}
