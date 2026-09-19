#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/pid.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include "uapi/supercall.h"
#include "supercall/internal.h"
#include "arch.h"
#include "util.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "manager/manager_identity.h"
#include "infra/seccomp_cache.h"
#include <linux/seccomp.h>
#include <asm/unistd.h>

struct ksu_install_fd_tw {
    struct callback_head cb;
    int __user *outp;
};

static int anon_ksu_release(struct inode *inode, struct file *filp)
{
    pr_info("ksu fd released\n");
    return 0;
}

static long anon_ksu_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    return ksu_supercall_handle_ioctl(cmd, (void __user *)arg);
}

static const struct file_operations anon_ksu_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = anon_ksu_ioctl,
    .compat_ioctl = anon_ksu_ioctl,
    .release = anon_ksu_release,
};

int ksu_install_fd(void)
{
    struct file *filp;
    int fd;

    /* No O_CLOEXEC: the manager execs libksud.so for `debug su`, and that
     * child must inherit [ksu_driver]. With CLOEXEC it falls back to
     * reboot(DEADBEEF) which Android app seccomp kills (SIGSYS syscall 142). */
    fd = get_unused_fd_flags(0);
    if (fd < 0) {
        pr_err("ksu_install_fd: failed to get unused fd\n");
        return fd;
    }

    filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL, O_RDWR);
    if (IS_ERR(filp)) {
        pr_err("ksu_install_fd: failed to create anon inode file\n");
        put_unused_fd(fd);
        return PTR_ERR(filp);
    }

    fd_install(fd, filp);
    pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);
    return fd;
}

static void ksu_install_fd_tw_func(struct callback_head *cb)
{
    struct ksu_install_fd_tw *tw = container_of(cb, struct ksu_install_fd_tw, cb);
    int fd = ksu_install_fd();

    pr_info("[%d] install ksu fd: %d\n", current->pid, fd);
    if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
        pr_err("install ksu fd reply err\n");
        ksu_close_fd(fd);
    }

    kfree(tw);
}

static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    int magic1 = (int)PT_REGS_PARM1(real_regs);
    int magic2 = (int)PT_REGS_PARM2(real_regs);

    if (magic1 == KSU_INSTALL_MAGIC1 && magic2 == KSU_INSTALL_MAGIC2) {
        struct ksu_install_fd_tw *tw;
        unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);

        tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
        if (!tw)
            return 0;

        tw->outp = (int __user *)arg4;
        tw->cb.func = ksu_install_fd_tw_func;

        if (task_work_add(current, &tw->cb, TWA_RESUME)) {
            kfree(tw);
            pr_warn("install fd add task_work failed\n");
        }
    }

    return 0;
}

static struct kprobe reboot_kp = {
    .symbol_name = REBOOT_SYMBOL,
    .pre_handler = reboot_handler_pre,
};

/* Official manager JNI never reboot()-installs [ksu_driver]. It scans fds,
 * then falls back to prctl(0xDEADBEEF, 2, &version, &flags, &result).
 * This LKM had no prctl handler, so isManager stayed false after late-load. */
struct ksu_prctl_info_tw {
    struct callback_head cb;
    s32 __user *verp;
    s32 __user *flagsp;
};

static void ksu_prctl_info_tw_func(struct callback_head *cb)
{
    struct ksu_prctl_info_tw *tw = container_of(cb, struct ksu_prctl_info_tw, cb);
    s32 version = KERNEL_SU_VERSION;
    s32 flags = 0;

    if (current->seccomp.mode == SECCOMP_MODE_FILTER)
        ksu_seccomp_allow_cache(current->seccomp.filter, __NR_reboot);
    ksu_install_fd();

#ifdef MODULE
    flags |= KSU_GET_INFO_FLAG_LKM;
#endif
    if (is_manager())
        flags |= KSU_GET_INFO_FLAG_MANAGER;
    if (ksu_late_loaded)
        flags |= KSU_GET_INFO_FLAG_LATE_LOAD;
#ifdef EXPECTED_SIZE2
    flags |= KSU_GET_INFO_FLAG_PR_BUILD;
#endif

    if (tw->verp && copy_to_user(tw->verp, &version, sizeof(version)))
        pr_err("prctl info: version copy_to_user failed\n");
    if (tw->flagsp && copy_to_user(tw->flagsp, &flags, sizeof(flags)))
        pr_err("prctl info: flags copy_to_user failed\n");
    kfree(tw);
}

static int prctl_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    struct ksu_prctl_info_tw *tw;
    unsigned long option = PT_REGS_PARM1(real_regs);
    unsigned long cmd = PT_REGS_PARM2(real_regs);

    if (option != KSU_INSTALL_MAGIC1 || cmd != 2)
        return 0;
    if (!is_manager())
        return 0;

    tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
    if (!tw)
        return 0;

    tw->verp = (s32 __user *)PT_REGS_PARM3(real_regs);
    tw->flagsp = (s32 __user *)PT_REGS_SYSCALL_PARM4(real_regs);
    tw->cb.func = ksu_prctl_info_tw_func;

    if (task_work_add(current, &tw->cb, TWA_RESUME)) {
        kfree(tw);
        pr_warn("prctl info add task_work failed\n");
    }
    return 0;
}

static struct kprobe prctl_kp = {
    .symbol_name = PRCTL_SYMBOL,
    .pre_handler = prctl_handler_pre,
};

void __init ksu_supercalls_init(void)
{
    int rc;

    ksu_supercall_dump_commands();

    rc = register_kprobe(&reboot_kp);
    if (rc) {
        pr_err("reboot kprobe failed: %d\n", rc);
    } else {
        pr_info("reboot kprobe registered successfully\n");
    }

    rc = register_kprobe(&prctl_kp);
    if (rc) {
        pr_err("prctl kprobe failed: %d\n", rc);
    } else {
        pr_info("prctl kprobe registered successfully\n");
    }
}

void __exit ksu_supercalls_exit(void)
{
    unregister_kprobe(&prctl_kp);
    unregister_kprobe(&reboot_kp);
    ksu_supercall_cleanup_state();
}
