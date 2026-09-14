/* The PSP under entropy.c, on the host. The clock is simulated: sim.c moves
   it one frame at a time, 16667 microseconds plus the jitter a real frame
   has, and every read of it advances it by the microsecond or few a syscall
   takes. With sim_broken set there is no jitter at all -- every run of the
   same input reads the same clock -- which is the deliberately broken pool
   of the report. Files are real files. */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "pspiofilemgr.h"
#include "pspkernel.h"
#include "psprtc.h"
#include "sim.h"

uint64_t sim_clock_us = 1234567;
int sim_broken;
int sim_hash_fail;
static uint64_t rng_state = 0x9E3779B97F4A7C15ull;

void sim_seed_rng(uint64_t seed) { rng_state = seed ? seed : 1; }

uint64_t sim_rand(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return rng_state = x;
}

void sim_frame(void) {
    sim_clock_us += 16667;
    if (!sim_broken) sim_clock_us += sim_rand() % 301 - 150;
}

unsigned int sceKernelGetSystemTimeLow(void) {
    sim_clock_us += sim_broken ? 1 : 1 + sim_rand() % 3;
    return (unsigned int)sim_clock_us;
}

int sceRtcGetCurrentTick(u64 *tick) {
    *tick = sim_broken ? 63900000000000000ull : 63900000000000000ull + sim_rand() % 1000000000ull;
    return 0;
}

SceUID sceKernelCreateSema(const char *name, unsigned attr, int init, int max, void *opt) {
    (void)name; (void)attr; (void)init; (void)max; (void)opt;
    static int next = 1;
    return next++;
}
int sceKernelWaitSema(SceUID id, int signal, unsigned *timeout) { (void)id; (void)signal; (void)timeout; return 0; }
int sceKernelSignalSema(SceUID id, int signal) { (void)id; (void)signal; return 0; }

SceUID sceIoOpen(const char *path, int flags, int mode) {
    int f = (flags & PSP_O_WRONLY) ? O_WRONLY : O_RDONLY;
    if (flags & PSP_O_CREAT) f |= O_CREAT;
    if (flags & PSP_O_TRUNC) f |= O_TRUNC;
    int fd = open(path, f, mode);
    return fd < 0 ? -1 : fd;
}
int sceIoRead(SceUID fd, void *buf, SceSize n) { return (int)read(fd, buf, n); }
int sceIoWrite(SceUID fd, const void *buf, SceSize n) { return (int)write(fd, buf, n); }
int sceIoClose(SceUID fd) { return close(fd); }
int sceIoGetstat(const char *path, SceIoStat *st) {
    struct stat s;
    if (stat(path, &s) < 0) return -1;
    st->st_mode = (int)s.st_mode;
    return 0;
}
/* Like the PSP's: the new name is a bare name in the old file's folder. */
int sceIoRename(const char *oldname, const char *newname) {
    char to[512];
    const char *slash = strrchr(oldname, '/');
    int dir = slash ? (int)(slash - oldname) + 1 : 0;
    snprintf(to, sizeof(to), "%.*s%s", dir, oldname, newname);
    return rename(oldname, to) < 0 ? -1 : 0;
}
int sceIoRemove(const char *path) { return unlink(path) < 0 ? -1 : 0; }
int sceIoSync(const char *device, unsigned int unk) { (void)device; (void)unk; return 0; }
