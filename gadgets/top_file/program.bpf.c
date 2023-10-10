/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
/* Copyright (c) 2023 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/mntns_filter.h>
#include <gadget/types.h>
#include <gadget/macros.h>

// START: filetop.h
#define PATH_MAX 4096
#define TASK_COMM_LEN 16
#define TYPE_LEN 1

enum op {
	READ,
	WRITE,
};

struct file_id {
	__u64 inode;
	__u32 dev;
	__u32 pid;
	__u32 tid;
};

struct file_stat {
	mnt_ns_id_t mntns_id;
	__u64 reads;
	__u64 rbytes;
	__u64 writes;
	__u64 wbytes;
	__u32 pid;
	__u32 tid;
	__u8 file[PATH_MAX];
	__u8 comm[TASK_COMM_LEN];
	// file type: R, S, O. Using byte array to force parsing as string.
	__u8 t[TYPE_LEN];
};

// END: filetop.h

// START: stat.h

/* From include/uapi/linux/stat.h */

#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFLNK 0120000
#define S_IFREG 0100000
#define S_IFBLK 0060000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFIFO 0010000
#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000

#define S_ISLNK(m) (((m)&S_IFMT) == S_IFLNK)
#define S_ISREG(m) (((m)&S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m)&S_IFMT) == S_IFDIR)
#define S_ISCHR(m) (((m)&S_IFMT) == S_IFCHR)
#define S_ISBLK(m) (((m)&S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m)&S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m)&S_IFMT) == S_IFSOCK)

// END: stat.h

#define MAX_ENTRIES 10240

const volatile pid_t target_pid = 0;
const volatile bool regular_file_only = true;
static struct file_stat zero_value = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct file_id);
	__type(value, struct file_stat);
} stats SEC(".maps");

// Describes the type produced by this program.
GADGET_STATS_MAP(stats);

static void get_file_path(struct file *file, __u8 *buf, size_t size)
{
	struct qstr dname;

	dname = BPF_CORE_READ(file, f_path.dentry, d_name);
	bpf_probe_read_kernel(buf, size, dname.name);
}

static int probe_entry(struct pt_regs *ctx, struct file *file, size_t count,
		       enum op op)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	__u32 tid = (__u32)pid_tgid;
	int mode;
	struct file_id key = {};
	struct file_stat *valuep;
	u64 mntns_id;

	if (target_pid && target_pid != pid)
		return 0;

	mntns_id = gadget_get_mntns_id();

	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	mode = BPF_CORE_READ(file, f_inode, i_mode);
	if (regular_file_only && !S_ISREG(mode))
		return 0;

	key.dev = BPF_CORE_READ(file, f_inode, i_rdev);
	key.inode = BPF_CORE_READ(file, f_inode, i_ino);
	key.pid = pid;
	key.tid = tid;
	valuep = bpf_map_lookup_elem(&stats, &key);
	if (!valuep) {
		bpf_map_update_elem(&stats, &key, &zero_value, BPF_ANY);
		valuep = bpf_map_lookup_elem(&stats, &key);
		if (!valuep)
			return 0;
		valuep->pid = pid;
		valuep->tid = tid;
		valuep->mntns_id = mntns_id;
		bpf_get_current_comm(&valuep->comm, sizeof(valuep->comm));
		get_file_path(file, valuep->file, sizeof(valuep->file));
		if (S_ISREG(mode)) {
			valuep->t[0] = 'R';
		} else if (S_ISSOCK(mode)) {
			valuep->t[0] = 'S';
		} else {
			valuep->t[0] = 'O';
		}
	}
	if (op == READ) {
		valuep->reads++;
		valuep->rbytes += count;
	} else { /* op == WRITE */
		valuep->writes++;
		valuep->wbytes += count;
	}
	return 0;
};

SEC("kprobe/vfs_read")
int BPF_KPROBE(ig_topfile_rd_e, struct file *file, char *buf, size_t count,
	       loff_t *pos)
{
	return probe_entry(ctx, file, count, READ);
}

SEC("kprobe/vfs_write")
int BPF_KPROBE(ig_topfile_wr_e, struct file *file, const char *buf,
	       size_t count, loff_t *pos)
{
	return probe_entry(ctx, file, count, WRITE);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
