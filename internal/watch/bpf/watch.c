// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
//
// Hyperion Trace watch: observe-only eBPF program. It reports files under
// /etc opened for writing, with who opened them. fentry programs cannot
// block or change anything; they only read.
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
struct path {
	void *mnt;
	void *dentry;
} __attribute__((preserve_access_index));

struct file {
	struct path f_path;
	unsigned int f_mode;
} __attribute__((preserve_access_index));

typedef struct {
	__u32 val;
} kuid_t;

struct task_struct {
	kuid_t loginuid;
} __attribute__((preserve_access_index));

#define FMODE_WRITE 0x2
#define PATH_MAX_LEN 256
#define TASK_COMM_LEN 16
#define AUDIT_UID_UNSET 0xffffffff

enum op {
	OP_OPEN_WRITE = 1,
};

struct event {
	__u64 time_ns;
	__u32 pid;      // thread group id (what userspace calls the pid)
	__u32 tid;
	__u32 uid;      // real uid
	__u32 loginuid; // audit login uid: the user who logged in, kept across sudo
	__u32 op;
	char comm[TASK_COMM_LEN];
	char path[PATH_MAX_LEN];
};

// Prevent bpf2go from dropping the type: userspace decodes this struct.
const struct event *unused_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); // 1 MiB: bounded memory, drops are counted
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

// Set by the loader to the scanner's own pid so its reads never loop back.
volatile const __u32 self_pid = 0;

static __always_inline int under_etc(const char *p)
{
	return p[0] == '/' && p[1] == 'e' && p[2] == 't' && p[3] == 'c' && p[4] == '/';
}

SEC("fentry/security_file_open")
int BPF_PROG(on_file_open, struct file *file)
{
	if (!(BPF_CORE_READ(file, f_mode) & FMODE_WRITE))
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	if (pid == self_pid)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		__u32 zero = 0;
		__u64 *n = bpf_map_lookup_elem(&dropped, &zero);
		if (n)
			__sync_fetch_and_add(n, 1);
		return 0;
	}

	long len = bpf_d_path(&file->f_path, e->path, sizeof(e->path));
	if (len < 5 || !under_etc(e->path)) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	e->loginuid = AUDIT_UID_UNSET;
	if (bpf_core_field_exists(task->loginuid))
		e->loginuid = BPF_CORE_READ(task, loginuid.val);

	e->time_ns = bpf_ktime_get_ns();
	e->pid = pid;
	e->tid = (__u32)pid_tgid;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->op = OP_OPEN_WRITE;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
