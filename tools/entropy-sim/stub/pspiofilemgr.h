#ifndef SIM_PSPIOFILEMGR_H
#define SIM_PSPIOFILEMGR_H
#include "pspkernel.h"
#define PSP_O_RDONLY 0x0001
#define PSP_O_WRONLY 0x0002
#define PSP_O_CREAT  0x0200
#define PSP_O_TRUNC  0x0400
typedef struct { int st_mode; } SceIoStat;
SceUID sceIoOpen(const char *path, int flags, int mode);
int sceIoRead(SceUID fd, void *buf, SceSize n);
int sceIoWrite(SceUID fd, const void *buf, SceSize n);
int sceIoClose(SceUID fd);
int sceIoGetstat(const char *path, SceIoStat *st);
int sceIoRename(const char *oldname, const char *newname);
int sceIoRemove(const char *path);
int sceIoSync(const char *device, unsigned int unk);
#endif
