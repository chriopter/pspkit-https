/* Host stand-ins for the PSP kernel calls entropy.c makes. */
#ifndef SIM_PSPKERNEL_H
#define SIM_PSPKERNEL_H
#include <stddef.h>
#include <stdint.h>
typedef int SceUID;
typedef unsigned int SceSize;
typedef uint64_t u64;
unsigned int sceKernelGetSystemTimeLow(void);
SceUID sceKernelCreateSema(const char *name, unsigned attr, int init, int max, void *opt);
int sceKernelWaitSema(SceUID id, int signal, unsigned *timeout);
int sceKernelSignalSema(SceUID id, int signal);
#endif
