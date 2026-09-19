#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/moduleparam.h>
#include <linux/delay.h>

/* GhostLock diagnostic trace (see ksu.h). Loader passes ghost_trace_phys; each
 * step stores to p[0] and waits for the userspace spinner to ack via p[1]. */
unsigned long long ksu_ghost_trace_phys;
module_param_named(ghost_trace_phys, ksu_ghost_trace_phys, ullong, 0600);
void ksu_ghost_trace(unsigned long long step)
{
    volatile unsigned long long *p;
    int i;

    if (!ksu_ghost_trace_phys)
        return;
    p = (volatile unsigned long long *)__va(ksu_ghost_trace_phys);
    p[0] = step;
    mb();
    for (i = 0; i < 5000; i++) {
        if (p[1] == step)
            return;
        udelay(1);
    }
}

#include "policy/allowlist.h"
#include "ksu_samsung_kdp.h"
#include "policy/app_profile.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"
#include "hook/syscall_hook_manager.h"
#include "hook/lsm_hook.h"
#include "runtime/ksud.h"
#include "runtime/ksud_boot.h"
#include "feature/sulog.h"
#include "supercall/supercall.h"
#include "ksu.h"
#include "infra/file_wrapper.h"
#include "selinux/selinux.h"
#include "hook/syscall_hook.h"
#include "feature/adb_root.h"
#include "feature/selinux_hide.h"
#include "infra/symbol_resolver.h"
#include "compat/samsung_defex.h"

#if defined(__x86_64__)
#include <asm/cpufeature.h>
#include <linux/version.h>
#ifndef X86_FEATURE_INDIRECT_SAFE
#error "FATAL: Your kernel is missing the indirect syscall bypass patches!"
#endif
#endif

// workaround for A12-5.10 kernel
// Some third-party kernel (e.g. linegaeOS) uses wrong toolchain, which supports
// CC_HAVE_STACKPROTECTOR_SYSREG while gki's toolchain doesn't.
// Therefore, ksu lkm, which uses gki toolchain, requires this __stack_chk_guard,
// while those third-party kernel can't provide.
// Thus, we manually provide it instead of using kernel's
#if defined(CONFIG_STACKPROTECTOR) &&                                                                                  \
    (defined(CONFIG_ARM64) && defined(MODULE) && !defined(CONFIG_STACKPROTECTOR_PER_TASK))
#include <linux/stackprotector.h>
#include <linux/random.h>
unsigned long __stack_chk_guard __ro_after_init __attribute__((visibility("hidden")));

__attribute__((no_stack_protector)) void __init ksu_setup_stack_chk_guard()
{
    unsigned long canary;

    /* Try to get a semi random initial value. */
    get_random_bytes(&canary, sizeof(canary));
    canary ^= LINUX_VERSION_CODE;
    canary &= CANARY_MASK;
    __stack_chk_guard = canary;
}

__attribute__((naked)) int __init kernelsu_init_early(void)
{
    asm("mov x19, x30;\n"
        "bl ksu_setup_stack_chk_guard;\n"
        "mov x30, x19;\n"
        "b kernelsu_init;\n");
}
#define NEED_OWN_STACKPROTECTOR 1
#else
#define NEED_OWN_STACKPROTECTOR 0
#endif

struct cred *ksu_cred;
bool ksu_late_loaded;

/* See ksu.h: false until kernelsu_init() has finished; gates live hooks so they
 * cannot fire into a half-initialized module during a late load. */
bool ksu_hooks_live __read_mostly = false;

#ifdef CONFIG_KSU_DEBUG
bool allow_shell = true;
#else
bool allow_shell = false;
#endif
module_param(allow_shell, bool, 0);

#include "manager/manager_identity.h"

static int manager_uid;
static int set_manager_uid(const char *val, const struct kernel_param *kp)
{
	int rv = param_set_int(val, kp);

	if (!rv && manager_uid > 0) {
		ksu_set_manager_appid((uid_t)manager_uid);
		pr_info("manager_uid param: crowned %d\n", manager_uid);
	}
	return rv;
}
static const struct kernel_param_ops manager_uid_ops = {
	.set = set_manager_uid,
	.get = param_get_int,
};
module_param_cb(manager_uid, &manager_uid_ops, &manager_uid, 0644);

bool ksu_no_custom_rc = false;
module_param_named(norc, ksu_no_custom_rc, bool, 0);

int __init kernelsu_init(void)
{
    int ret;

#if defined(__x86_64__)
    // If the kernel has the hardening patch, X86_FEATURE_INDIRECT_SAFE must be set
    if (!boot_cpu_has(X86_FEATURE_INDIRECT_SAFE)) {
        pr_alert("*************************************************************");
        pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
        pr_alert("**                                                         **");
        pr_alert("**        X86_FEATURE_INDIRECT_SAFE is not enabled!        **");
        pr_alert("**      KernelSU will abort initialization to prevent      **");
        pr_alert("**                     kernel panic.                       **");
        pr_alert("**                                                         **");
        pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
        pr_alert("*************************************************************");
        return -ENOSYS;
    }
#endif

#ifdef MODULE
    ksu_late_loaded = (current->pid != 1);
#else
    ksu_late_loaded = false;
#endif

#ifdef CONFIG_KSU_DEBUG
    pr_alert("*************************************************************");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("**                                                         **");
    pr_alert("**         You are running KernelSU in DEBUG mode          **");
    pr_alert("**                                                         **");
    pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
    pr_alert("*************************************************************");
#endif
    if (allow_shell) {
        pr_alert("shell is allowed at init!");
    }

#ifdef CONFIG_KSU_SAMSUNG_KDP
    pr_info("Samsung KDP credential reference handling enabled\n");
#endif

    ksu_init_symbol_resolver();
    ret = ksu_samsung_kdp_init();
    if (ret)
        return ret;

    ksu_cred = prepare_creds();
    if (!ksu_cred) {
        pr_err("prepare cred failed!\n");
        ksu_samsung_kdp_exit();
        return -ENOSYS;
    }

    ret = ksu_samsung_defex_init();
    if (ret) {
        ksu_put_cred(ksu_cred);
        ksu_samsung_kdp_exit();
        return ret;
    }

    ksu_syscall_hook_init();

    ksu_feature_init();
    ksu_sulog_init();
    ksu_adb_root_init();
    ksu_lsm_hook_init();
    ksu_selinux_hide_init();

    ksu_supercalls_init();

    if (ksu_late_loaded) {
        pr_info("late load mode, skipping kprobe hooks\n");

        apply_kernelsu_rules();
        cache_sid();
        setup_ksu_cred();

        // Grant current process (ksud late-load) root
        // with KSU SELinux domain before enforcing SELinux, so it
        // can continue to access /data/app etc. after enforcement.
        escape_to_root_for_init();

        ksu_allowlist_init();
        ksu_load_allow_list();

        ksu_syscall_hook_manager_init();

        ksu_throne_tracker_init();
        ksu_observer_init();
        ksu_file_wrapper_init();

        ksu_boot_completed = true;
        if (manager_uid > 0)
            ksu_set_manager_appid((uid_t)manager_uid);
        track_throne(false);

        if (!getenforce()) {
            pr_info("Permissive SELinux, enforcing\n");
            setenforce(true);
        }

    } else {
        ksu_syscall_hook_manager_init();

        ksu_allowlist_init();

        ksu_throne_tracker_init();

        ksu_ksud_init();

        ksu_file_wrapper_init();
    }

    /*
     * Every init step above is done: on the late-load path the SELinux policy
     * swap, sid cache, cred escape, allowlist, syscall-hook manager, throne and
     * observer are all set up and enforcement is on. Only now let KSU hooks act.
     * Release ordering pairs with the acquire load in the hook fast paths so
     * they observe all of the above before they start processing traffic.
     */
    smp_store_release(&ksu_hooks_live, true);

    /*
     * GhostLock KDP diagnostic: when loaded via koload with a trace page, run
     * the real grant-root path once here — while the koload spinner is alive to
     * fsync each step — so a Samsung KDP/RKP panic in the credential install
     * leaves the last-reached step in the panic-surviving log. escape_with_root_
     * profile() is traced internally (steps 41-49) and the worker (90-99); the
     * euid==0 early-abort is skipped under ghost_trace so the KDP commit runs.
     * 0xFFFF means the whole grant path survived with no panic.
     */
    if (ksu_ghost_trace_phys) {
        ksu_ghost_trace(40);
        escape_with_root_profile();
        ksu_ghost_trace(0xFFFF);
    }

#ifdef MODULE
#ifndef CONFIG_KSU_DEBUG
    /* Keep sysfs on late-load so ksud can write manager_uid after DEFEX is
     * bypassed. Hidden for normal boot LKM to avoid leaking the module. */
    if (!ksu_late_loaded)
        kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif
    return 0;
}

void __exit kernelsu_exit(void)
{
    // Phase 1: Stop all hooks first to prevent new callbacks
    ksu_syscall_hook_manager_exit();

    ksu_supercalls_exit();

    if (!ksu_late_loaded)
        ksu_ksud_exit();

    // Wait for any in-flight RCU readers (e.g. handler traversing allow_list)
    synchronize_rcu();

    // Phase 2: Now safe to release data structures
    ksu_observer_exit();

    ksu_throne_tracker_exit();

    ksu_allowlist_exit();

    ksu_selinux_hide_exit();
    ksu_lsm_hook_exit();
    ksu_adb_root_exit();
    ksu_sulog_exit();
    ksu_feature_exit();

    ksu_samsung_defex_exit();
    ksu_put_cred(ksu_cred);
    ksu_samsung_kdp_exit();
}

#if NEED_OWN_STACKPROTECTOR
module_init(kernelsu_init_early);
#else
module_init(kernelsu_init);
#endif
module_exit(kernelsu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("weishu");
MODULE_DESCRIPTION("Android KernelSU");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
