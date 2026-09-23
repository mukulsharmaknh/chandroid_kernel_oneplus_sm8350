#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs_def.h>
#endif // #ifdef CONFIG_KSU_SUSFS

#include "feature/kernel_umount.h"
#include "klog.h" // IWYU pragma: keep
#include "compat/kernel_compat.h"
#include "policy/allowlist.h"
#include "selinux/selinux.h"
#include "policy/feature.h"
#include "runtime/ksud_boot.h"
#include "ksu.h"
#include "feature/sucompat.h"

static bool ksu_kernel_umount_enabled = true;

static int kernel_umount_feature_get(u64 *value)
{
    *value = ksu_kernel_umount_enabled ? 1 : 0;
    return 0;
}

static int kernel_umount_feature_set(u64 value)
{
    bool enable = value != 0;
    ksu_kernel_umount_enabled = enable;
    pr_info("kernel_umount: set to %d\n", enable);
    return 0;
}

static const struct ksu_feature_handler kernel_umount_handler = {
    .feature_id = KSU_FEATURE_KERNEL_UMOUNT,
    .name = "kernel_umount",
    .get_handler = kernel_umount_feature_get,
    .set_handler = kernel_umount_feature_set,
};

extern int path_umount(struct path *path, int flags);
static void ksu_umount_mnt(const char *mnt, struct path *path, int flags)
{
    int err = path_umount(path, flags);
    if (err) {
        pr_info("umount %s failed: %d\n", mnt, err);
    }
}

void try_umount(const char *mnt, int flags)
{
    struct path path;
    int err = kern_path(mnt, 0, &path);
    if (err) {
        return;
    }

    if (path.dentry != path.mnt->mnt_root) {
        // it is not root mountpoint, maybe umounted by others already.
        path_put(&path);
        return;
    }

    ksu_umount_mnt(mnt, &path, flags);
}

#ifdef CONFIG_KSU_SUSFS
extern struct work_struct susfs_extra_works;
#endif

static void do_umount_for_current_task()
{
    const struct cred *saved = override_creds(ksu_cred);
    struct mount_entry *entry;
    down_read(&mount_list_lock);
    list_for_each_entry (entry, &mount_list, list) {
        pr_info("%s: unmounting: %s flags: 0x%x\n", __func__, entry->umountable, entry->flags);
        try_umount(entry->umountable, entry->flags);
    }
    up_read(&mount_list_lock);

    revert_creds(saved);
}

int ksu_handle_umount(uid_t old_uid, uid_t new_uid)
{
    const struct cred *saved;
    struct mount_entry *entry;

    // There are 6 scenarios:
    // 1. Normal app: zygote -> appuid
    // 2. Isolated process forked from zygote: zygote -> isolated_process
    // 3. App zygote forked from zygote: zygote -> appuid
    // 4. Webview zygote forked from zygote: zygote -> webview_zygote
    // 5. Isolated process forked from app zygote: appuid -> isolated_process (already handled by 3)
    // 6. Isolated process forked from webview zygote (already handled by 4)
    if (!is_appuid(new_uid) && new_uid != WEBVIEW_ZYGOTE_UID && !is_isolated_process(new_uid)) {
        return 0;
    }

    if (!ksu_uid_should_umount(new_uid) && !is_isolated_process(new_uid)) {
        return 0;
    }

    // no need to check zygote here, because we already check it in the setuid call.

    // in susfs's implementation, ksu_kernel_umount is ignored, so this keeps the same behavior.
    if (!ksu_kernel_umount_enabled) {
        goto skip_umount_task;
    }

    // if there isn't any module mounted, just ignore it!
    if (!ksu_module_mounted) {
        goto skip_umount_task;
    }

    // umount the target mnt
    pr_info("handle umount for uid: %d, pid: %d\n", new_uid, current->pid);

    saved = override_creds(ksu_cred);

    down_read(&mount_list_lock);
    list_for_each_entry (entry, &mount_list, list) {
        pr_info("%s: unmounting: %s flags 0x%x\n", __func__, entry->umountable, entry->flags);
        try_umount(entry->umountable, entry->flags);
    }
    up_read(&mount_list_lock);

    revert_creds(saved);

skip_umount_task:
    // do susfs setuid when susfs enabled
#ifdef CONFIG_KSU_SUSFS
    if (!work_pending(&susfs_extra_works))
        schedule_work(&susfs_extra_works);
    susfs_set_current_proc_umounted();
#endif

    return 0;
}

void __init ksu_kernel_umount_init(void)
{
    if (ksu_register_feature_handler(&kernel_umount_handler)) {
        pr_err("Failed to register kernel_umount feature handler\n");
    }
}

void __exit ksu_kernel_umount_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_KERNEL_UMOUNT);
}

// Mukul 9RT: SUSFS v2.1.0 compat stubs.
// The v4.2 driver expects v2.3.0-era susfs symbols that our v2.1.0 tree
// doesn't export. v2.1.0 tracks proc state itself (uid_scheme, its own
// exec hooks), so these are safe no-ops by design.
#ifdef CONFIG_KSU_SUSFS
static void susfs_extra_works_stub(struct work_struct *work)
{
}

struct work_struct susfs_extra_works = __WORK_INITIALIZER(susfs_extra_works, susfs_extra_works_stub);

// susfs_set_current_proc_umounted comes from <linux/susfs_def.h> (static
// inline, sets TIF_PROC_UMOUNTED) — do NOT define it here, v2.1.0 owns it.

void susfs_set_current_proc_umounted_for_zygote_next(void)
{
}

void susfs_set_current_proc_no_su(void)
{
}

void susfs_clear_current_proc_no_su(void)
{
}

bool susfs_is_current_proc_no_su(void)
{
    return false;
}

// v2.1.0-era stub kept from June build: our patched fs/statfs.c calls this
// and always dput/mntput the returned vfsmount, so we must take references.
struct vfsmount *susfs_get_non_sus_vfsmnt_from_vfsmnt(struct vfsmount *vfsmnt)
{
    mntget(vfsmnt);
    dget(vfsmnt->mnt_root);
    return vfsmnt;
}
#endif
