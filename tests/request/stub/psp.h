/* The PSP SDK as far as src/https.c reaches into it, for the host. Every
   header it includes is this one; main.c defines what is called. */
#ifndef REQUEST_STUB_PSP_H
#define REQUEST_STUB_PSP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef int SceUID;
typedef unsigned int SceSize;
typedef uint64_t u64;
typedef int64_t SceInt64;

#define PSP_THREAD_ATTR_USER 0x80000000
#define PSP_NET_MODULE_COMMON 1
#define PSP_NET_MODULE_INET 2

int sceKernelDelayThread(unsigned usec);
SceInt64 sceKernelGetSystemTimeWide(void);
SceUID sceKernelCreateThread(const char *name, int (*entry)(SceSize, void *), int priority,
                             int stack, unsigned attr, void *option);
int sceKernelStartThread(SceUID thread, SceSize args, void *argp);
int sceKernelDeleteThread(SceUID thread);
int sceKernelWaitThreadEnd(SceUID thread, unsigned *timeout);

int sceUtilityLoadNetModule(int module);
int sceUtilityUnloadNetModule(int module);

int sceNetInit(int pool, int calloutpri, int calloutstack, int netintrpri, int netintrstack);
int sceNetTerm(void);
int sceNetInetInit(void);
int sceNetInetTerm(void);
int sceNetInetSocket(int domain, int type, int protocol);
int sceNetInetConnect(int s, const struct sockaddr *addr, socklen_t len);
size_t sceNetInetRecv(int s, void *buf, size_t len, int flags);
size_t sceNetInetSend(int s, const void *buf, size_t len, int flags);
int sceNetInetClose(int s);
int sceNetInetGetErrno(void);
int sceNetResolverInit(void);
int sceNetResolverTerm(void);
int sceNetResolverCreate(int *rid, void *buf, SceSize len);
int sceNetResolverDelete(int rid);
int sceNetResolverStartNtoA(int rid, const char *host, struct in_addr *addr, unsigned timeout,
                            int retry);
int sceNetApctlInit(int stack, int priority);
int sceNetApctlTerm(void);
int sceNetApctlConnect(int index);
int sceNetApctlDisconnect(void);
int sceNetApctlGetState(int *state);

int scePowerGetBatteryVolt(void);
int scePowerGetBatteryElec(void);
int scePowerGetBatteryTemp(void);
int scePowerGetBatteryLifeTime(void);

#endif
