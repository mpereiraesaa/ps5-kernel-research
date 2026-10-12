#pragma once

#include <signal.h>

void dbg_enter(void);
long gdb_remote_syscall(const char* name, int nargs, int* ern, ...);
int gdbstub_session_lock(sigset_t* oldmask);
void gdbstub_session_unlock(const sigset_t* oldmask);
