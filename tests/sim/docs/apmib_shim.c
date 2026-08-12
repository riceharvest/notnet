/* apmib shim for the Realtek Boa under qemu (#126).
 * LD_PRELOAD'd into the MIPS boa: satisfies the libapmib API with
 * defaults so asp_init() passes without a real flash/MIB. The
 * hw-setting header (sig=Hf, ver=0, len=16) is synthesized by
 * flash_read_raw_mib so the boa's own signature check passes. */
#include <string.h>

int apmib_init(void) { return 0; }
int apmib_lock(void) { return 0; }
int apmib_unlock(void) { return 0; }
int apmib_sem_lock(void) { return 0; }
int apmib_sem_unlock(void) { return 0; }
int apmib_shm_free(void) { return 0; }

int apmib_get(int code, void *value) {
    if (!value) return -1;
    memset(value, 0, 64);
    return 0;
}

int apmib_getDef(int code, void *value) {
    if (!value) return -1;
    memset(value, 0, 64);
    return 0;
}

int apmib_set(int code, void *value) { (void)code; (void)value; return 0; }
int apmib_setDef(int code, void *value) { (void)code; (void)value; return 0; }
int apmib_update(int id) { (void)id; return 0; }
int apmib_updateFlash(int id) { (void)id; return 0; }

int flash_read_raw_mib(void *buf, unsigned int len) {
    if (!buf) return -1;
    memset(buf, 0, len);
    if (len >= 8) {
        /* sig "Hf", ver 0, len 16 — the hw-setting header the boa checks */
        unsigned char hdr[8] = { 'H', 'f', 0x00, 0x00, 0x10, 0x00, 0x00, 0x00 };
        memcpy(buf, hdr, 8);
    }
    return 0;
}
int flash_write_raw_mib(void *buf, unsigned int len) { (void)buf; (void)len; return 0; }
unsigned int mib_get_flash_offset(void) { return 0x6000; }
int apmib_load_csconf(void) { return 0; }
int apmib_load_dsconf(void) { return 0; }
int apmib_save_wlanIdx(void) { return 0; }
int apmib_recov_wlanIdx(void) { return 0; }
