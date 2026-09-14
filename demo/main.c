/* The library on one screen: a sweep of the analog stick in ASCII, the seed
   kept beside the EBOOT for the next start, then one HTTPS request and what
   the handshake agreed on. */

#include <pspkernel.h>
#include <pspctrl.h>
#include <pspdebug.h>
#include <pspdisplay.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "pspkit-https/entropy.h"
#include "pspkit-https/https.h"
#include "pspkit-https/sweep.h"

PSP_MODULE_INFO("pspkit-https demo", 0, 1, 0);
PSP_MAIN_THREAD_ATTR(THREAD_ATTR_USER);
PSP_HEAP_SIZE_KB(8 * 1024);

#define URL "https://raw.githubusercontent.com/chriopter/pspkit-https/master/README.md"

static char g_seed_file[256];

static int exit_callback(int arg1, int arg2, void *common) {
    (void)arg1; (void)arg2; (void)common;
    sceKernelExitGame();
    return 0;
}

static int callback_thread(SceSize args, void *argp) {
    (void)args; (void)argp;
    int id = sceKernelCreateCallback("exit", exit_callback, NULL);
    sceKernelRegisterExitCallback(id);
    sceKernelSleepThreadCB();
    return 0;
}

/* Files in the EBOOT's own folder: argv[0] is the path it was loaded from. */
static void beside(const char *eboot, const char *name, char *out, size_t size) {
    const char *slash = eboot ? strrchr(eboot, '/') : NULL;
    if (!slash || snprintf(out, size, "%.*s/%s", (int)(slash - eboot), eboot, name) >= (int)size)
        snprintf(out, size, "ms0:/PSP/GAME/pspkit-demo/%s", name);
}

/* The library's log, while a request runs: kept for the screen to print,
   since the request runs on a thread of its own and the screen is the main
   thread's. */
#define LOG_LINES 8
static char g_log[LOG_LINES][60];
static int g_log_count;
static pthread_mutex_t g_screen_lock = PTHREAD_MUTEX_INITIALIZER;

static void log_to_screen(const char *text) {
    pthread_mutex_lock(&g_screen_lock);
    int n = g_log_count;
    if (n < LOG_LINES) {
        snprintf(g_log[n], sizeof(g_log[n]), "%.56s", text);
        g_log_count = n + 1;
    }
    pthread_mutex_unlock(&g_screen_lock);
}

static unsigned wait_press(unsigned mask) {
    SceCtrlData pad;
    do sceCtrlReadBufferPositive(&pad, 1); while (pad.Buttons & mask);
    do sceCtrlReadBufferPositive(&pad, 1); while (!(pad.Buttons & mask));
    return pad.Buttons & mask;
}

static int count(void *ctx, const void *data, size_t len) {
    (void)data;
    *(size_t *)ctx += len;
    return 0;
}

/* One fetch, on a thread of its own so the screen can show how far it has
   got and O can call it off. */
static struct {
    int done, cancelled, rc, no_network;
    size_t got;
    struct https_result result;
} g_fetch;

static int fetch_thread(SceSize args, void *argp) {
    (void)args; (void)argp;
    if (https_net_connect() < 0) {
        g_fetch.no_network = 1;
    } else {
        pthread_mutex_lock(&g_screen_lock);
        int cancelled = g_fetch.cancelled;
        pthread_mutex_unlock(&g_screen_lock);
        if (cancelled) goto done;
        g_fetch.got = 0;
        g_fetch.rc = https_get(URL, count, &g_fetch.got, NULL, NULL, &g_fetch.result);
    }
done:
    pthread_mutex_lock(&g_screen_lock);
    g_fetch.done = 1;
    pthread_mutex_unlock(&g_screen_lock);
    return 0;
}

/* Runs one request and shows it until it is over; 0 when O called it off. */
static int run_request(void) {
    memset(&g_fetch, 0, sizeof(g_fetch));
    pthread_mutex_lock(&g_screen_lock);
    g_log_count = 0;
    pthread_mutex_unlock(&g_screen_lock);
    https_set_log(log_to_screen);
    SceUID thread = sceKernelCreateThread("fetch", fetch_thread, 0x20, 256 * 1024, PSP_THREAD_ATTR_USER, NULL);
    if (thread >= 0 && sceKernelStartThread(thread, 0, NULL) < 0) {
        sceKernelDeleteThread(thread);
        thread = -1;
    }
    if (thread < 0) {
        g_fetch.rc = -1;
        g_fetch.done = 1;
    }
    unsigned start = sceKernelGetSystemTimeLow();
    int shown = -1;
    SceCtrlData pad;
    do sceCtrlReadBufferPositive(&pad, 1); while (pad.Buttons & PSP_CTRL_CIRCLE);
    for (;;) {
        pthread_mutex_lock(&g_screen_lock);
        int done = g_fetch.done;
        pthread_mutex_unlock(&g_screen_lock);
        if (done) break;
        sceCtrlReadBufferPositive(&pad, 1);
        if ((pad.Buttons & PSP_CTRL_CIRCLE) && !g_fetch.cancelled) {
            pthread_mutex_lock(&g_screen_lock);
            g_fetch.cancelled = 1;
            pthread_mutex_unlock(&g_screen_lock);
            https_abort();
        }
        pspDebugScreenSetXY(0, 3);
        pspDebugScreenPrintf("  %-12s %3u s   %s          \n", https_get_phase(),
                             (sceKernelGetSystemTimeLow() - start) / 1000000,
                             g_fetch.cancelled ? "cancelling..." : "O to cancel");
        pthread_mutex_lock(&g_screen_lock);
        if (g_log_count != shown) {
            shown = g_log_count;
            pspDebugScreenSetXY(0, 5);
            for (int i = 0; i < shown; i++) pspDebugScreenPrintf("  %s\n", g_log[i]);
        }
        pthread_mutex_unlock(&g_screen_lock);
    }
    if (thread >= 0) {
        sceKernelWaitThreadEnd(thread, NULL);
        sceKernelDeleteThread(thread);
    }
    https_set_log(NULL);
    pspDebugScreenSetXY(0, 5);
    pthread_mutex_lock(&g_screen_lock);
    for (int i = 0; i < g_log_count; i++) pspDebugScreenPrintf("  %s\n", g_log[i]);
    pthread_mutex_unlock(&g_screen_lock);
    return !g_fetch.cancelled;
}

static void fetch(void) {
    for (;;) {
        pspDebugScreenClear();
        pspDebugScreenPrintf("\n  GET %.52s\n", URL + 8);
        if (!run_request()) {
            pspDebugScreenPrintf("\n  Cancelled.\n");
            return;
        }
        if (g_fetch.no_network) {
            pspDebugScreenPrintf("\n  No access point. Is WLAN on, and profile 1 set up?\n");
            return;
        }
        char host[128];
        enum https_doubt doubt = https_doubt_take(host, sizeof(host));
        if (g_fetch.rc < 0 && doubt != HTTPS_DOUBT_NONE) {
            pspDebugScreenPrintf("\n  The certificate of %.40s %s.\n", host,
                                 doubt == HTTPS_DOUBT_EXPIRED ? "has run out" : "comes from an unknown issuer");
            pspDebugScreenPrintf("  [] connect anyway   O leave it\n");
            if (wait_press(PSP_CTRL_SQUARE | PSP_CTRL_CIRCLE) & PSP_CTRL_SQUARE) {
                https_doubt_accept();
                continue;
            }
            return;
        }
        struct https_info tls;
        https_get_last_info(&tls);
        pspDebugScreenPrintf("\n  rc %d, HTTP %ld, %u bytes\n", g_fetch.rc, g_fetch.result.status,
                             (unsigned)g_fetch.got);
        if (g_fetch.rc >= 0)
            pspDebugScreenPrintf("  %s, %s, handshake %u ms\n", tls.cipher, tls.group, tls.handshake_ms);
        return;
    }
}

int main(int argc, char *argv[]) {
    SceUID cb = sceKernelCreateThread("callbacks", callback_thread, 0x11, 0xFA0, 0, 0);
    if (cb >= 0) sceKernelStartThread(cb, 0, 0);
    beside(argc > 0 ? argv[0] : NULL, "seed.bin", g_seed_file, sizeof(g_seed_file));

    entropy_init();
    entropy_set_seed_file(g_seed_file);
    int loaded = entropy_load();
    if (!loaded) sweep_ascii_run();
    entropy_save(0);

    for (;;) {
        pspDebugScreenInit();
        pspDebugScreenClear();
        pspDebugScreenPrintf("\n  pspkit-https demo\n\n");
        pspDebugScreenPrintf("  Seed: %d bits, %s\n\n", entropy_get_bits(),
                             loaded ? "from the stick" : "swept just now");
        pspDebugScreenPrintf("  X   fetch a file over HTTPS\n");
        pspDebugScreenPrintf("  []  sweep again\n");
        pspDebugScreenPrintf("  O   quit\n");
        unsigned b = wait_press(PSP_CTRL_CROSS | PSP_CTRL_SQUARE | PSP_CTRL_CIRCLE);
        if (b & PSP_CTRL_CROSS) {
            fetch();
            pspDebugScreenPrintf("\n  O to go back.\n");
            wait_press(PSP_CTRL_CIRCLE);
        } else if (b & PSP_CTRL_SQUARE) {
            /* No connection outlives the seed it was made under. */
            https_close_idle();
            entropy_stash();
            entropy_init();
            if (sweep_ascii_run() == 0) entropy_restore();
            else loaded = 0;
            entropy_save(0);
        } else {
            break;
        }
    }
    https_net_disconnect();
    sceKernelExitGame();
    return 0;
}
