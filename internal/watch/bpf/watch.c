// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
//
// Hyperion Trace watch: observe-only eBPF programs. They report writes,
// creations, renames, deletions and attribute changes (chmod, chown,
// truncate) under the watched directories, with who made them. fentry
// programs cannot block or change anything; they only read.
//
// The kernel requires a GPL-compatible license for the helpers used here,
// so this file is dual-licensed (the rest of Hyperion is Apache-2.0).

#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Only the kernel fields we read are declared. preserve_access_index makes
// clang emit CO-RE relocations, so the loader fixes field offsets for each
// running kernel (no full vmlinux.h needed).
typedef struct {
	__u32 val;
} kuid_t;

typedef struct {
	__u32 val;
} kgid_t;

struct qstr {
	const unsigned char *name;
} __attribute__((preserve_access_index));

struct super_block {
	__u32 s_dev;
} __attribute__((preserve_access_index));

struct inode {
	unsigned long i_ino;
	struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct dentry {
	struct dentry *d_parent;
	struct qstr d_name;
	struct inode *d_inode;
} __attribute__((preserve_access_index));

struct path {
	void *mnt;
	struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
	unsigned int f_mode;
} __attribute__((preserve_access_index));

struct iattr {
	unsigned int ia_valid;
	unsigned short ia_mode;
	kuid_t ia_uid;
	kgid_t ia_gid;
} __attribute__((preserve_access_index));

struct cred {
	kuid_t euid;
} __attribute__((preserve_access_index));

struct task_struct {
	int tgid;
	struct task_struct *real_parent;
	const struct cred *cred;
	kuid_t loginuid;
} __attribute__((preserve_access_index));

#define FMODE_WRITE 0x2
#define FMODE_CREATED 0x100000
#define ATTR_MODE (1 << 0)
#define ATTR_UID (1 << 1)
#define ATTR_GID (1 << 2)
#define ATTR_SIZE (1 << 3)
#define TASK_COMM_LEN 16
#define AUDIT_UID_UNSET 0xffffffff

// Path components stored per side, nearest the file first. Deeper files
// still match (the walk goes up to MAX_WALK levels); only their names
// beyond MAX_NAMES are elided.
#define MAX_NAMES 10
#define NAME_LEN 64
#define MAX_WALK 32

enum op {
	OP_WRITE = 1,
	OP_CREATE = 2,
	OP_RENAME = 3,
	OP_DELETE = 4,
	OP_ATTR = 5,
};

struct side {
	__u32 root;    // index of the watched directory, or ROOT_NONE
	__u32 depth;   // components between the file and the watched directory
	__u8 names[MAX_NAMES][NAME_LEN];
};

#define ROOT_NONE 0xffffffff

struct event {
	__u64 time_ns;
	__u32 op;
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u32 euid;
	__u32 loginuid;
	__u32 attr_valid;
	__u32 attr_mode;
	__u32 attr_uid;
	__u32 attr_gid;
	__u8 comm[TASK_COMM_LEN];
	struct side src; // the file (for a rename: the old name)
	struct side dst; // rename only: the new name
};

// Prevent bpf2go from dropping the type: userspace decodes this struct.
const struct event *unused_event __attribute__((unused));

struct dir_key {
	__u64 ino;
	__u32 dev; // kernel dev_t encoding (major << 20 | minor)
	__u32 pad;
};

// Watched directories, set by userspace: (dev, ino) -> index in its list.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct dir_key);
	__type(value, __u32);
} watched SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22); // 4 MiB: bounded memory, drops are counted
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

// Set by the loader to the scanner's own pid so its reads never loop back.
volatile const __u32 self_pid = 0;

// resolve walks from d up towards the filesystem root, recording names,
// until it meets a watched directory. It works across mount points because
// watched directories are matched by (device, inode), not by path text.
static __always_inline int resolve(struct dentry *d, struct side *s)
{
	struct dir_key key = {};
	s->root = ROOT_NONE;
	s->depth = 0;
	for (int i = 0; i < MAX_WALK; i++) {
		struct dentry *parent = BPF_CORE_READ(d, d_parent);
		if (!parent || parent == d)
			return 0; // reached the root without a match
		struct inode *dir = BPF_CORE_READ(parent, d_inode);
		if (!dir)
			return 0;
		// Index with the loop counter (always equal to the depth here): the
		// verifier can prove it is in bounds, unlike a value read from memory.
		if (i < MAX_NAMES) {
			const unsigned char *name = BPF_CORE_READ(d, d_name.name);
			bpf_probe_read_kernel_str(s->names[i], NAME_LEN, name);
		}
		s->depth = i + 1;
		key.ino = BPF_CORE_READ(dir, i_ino);
		key.dev = BPF_CORE_READ(dir, i_sb, s_dev);
		__u32 *idx = bpf_map_lookup_elem(&watched, &key);
		if (idx) {
			s->root = *idx;
			return 1;
		}
		d = parent;
	}
	return 0;
}

static __always_inline struct event *begin(__u32 op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if ((__u32)(pid_tgid >> 32) == self_pid)
		return 0;
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__u32 zero = 0;
		__u64 *n = bpf_map_lookup_elem(&dropped, &zero);
		if (n)
			__sync_fetch_and_add(n, 1);
		return 0;
	}
	e->op = op;
	e->pid = pid_tgid >> 32;
	e->attr_valid = 0;
	e->dst.root = ROOT_NONE;
	e->dst.depth = 0;
	return e;
}

static __always_inline void finish(struct event *e)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->time_ns = bpf_ktime_get_ns();
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->euid = BPF_CORE_READ(task, cred, euid.val);
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->loginuid = AUDIT_UID_UNSET;
	if (bpf_core_field_exists(task->loginuid))
		e->loginuid = BPF_CORE_READ(task, loginuid.val);
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
}

SEC("fentry/security_file_open")
int BPF_PROG(on_file_open, struct file *file)
{
	unsigned int mode = BPF_CORE_READ(file, f_mode);
	if (!(mode & FMODE_WRITE))
		return 0;
	struct event *e = begin((mode & FMODE_CREATED) ? OP_CREATE : OP_WRITE);
	if (!e)
		return 0;
	if (!resolve(BPF_CORE_READ(file, f_path.dentry), &e->src)) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	finish(e);
	return 0;
}

SEC("fentry/security_inode_rename")
int BPF_PROG(on_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry)
{
	struct event *e = begin(OP_RENAME);
	if (!e)
		return 0;
	int from = resolve(old_dentry, &e->src);
	int to = resolve(new_dentry, &e->dst);
	if (!from && !to) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	finish(e);
	return 0;
}

SEC("fentry/security_inode_unlink")
int BPF_PROG(on_unlink, struct inode *dir, struct dentry *dentry)
{
	struct event *e = begin(OP_DELETE);
	if (!e)
		return 0;
	if (!resolve(dentry, &e->src)) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	finish(e);
	return 0;
}

// notify_change(idmap/user_ns, dentry, attr, delegated_inode): dentry is the
// second argument since Linux 5.12. The loader checks the running kernel's
// BTF and only attaches this program when that holds.
SEC("fentry/notify_change")
int BPF_PROG(on_setattr, void *ns, struct dentry *dentry, struct iattr *attr)
{
	unsigned int valid = BPF_CORE_READ(attr, ia_valid);
	if (!(valid & (ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_SIZE)))
		return 0;
	struct event *e = begin(OP_ATTR);
	if (!e)
		return 0;
	if (!resolve(dentry, &e->src)) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	e->attr_valid = valid & (ATTR_MODE | ATTR_UID | ATTR_GID | ATTR_SIZE);
	e->attr_mode = BPF_CORE_READ(attr, ia_mode);
	e->attr_uid = BPF_CORE_READ(attr, ia_uid.val);
	e->attr_gid = BPF_CORE_READ(attr, ia_gid.val);
	finish(e);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
