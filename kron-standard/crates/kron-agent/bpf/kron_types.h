/* kron_types.h — shared types between eBPF programs and userspace.
 *
 * MUST stay in sync with src/bpf_types.rs.
 * Every struct is __attribute__((packed)) and padded manually to ensure
 * identical layout on all kernel versions.
 */
#pragma once

#include <linux/types.h>

#define PATH_LEN      256
#define COMM_LEN       64
#define USERNAME_LEN   32
#define ARGV_COUNT     16
#define ARGV_ITEM_LEN  64

/* Event kind discriminants — must match BpfEventKind in bpf_types.rs */
#define KRON_EVENT_PROCESS_CREATE  1
#define KRON_EVENT_NETWORK_CONNECT 2
#define KRON_EVENT_FILE_ACCESS     3

/* Common header prepended to every ring buffer record (32 bytes). */
struct bpf_event_header {
    __u32 kind;         /* KRON_EVENT_* discriminant */
    __u64 ktime_ns;     /* ktime_get_ns() — nanoseconds since boot */
    __u32 pid;
    __u32 uid;
    __u32 gid;
    __u32 netns_ino;    /* network namespace inode */
    __u64 _pad;
} __attribute__((packed));

/* Process creation event */
struct bpf_process_create_event {
    struct bpf_event_header header;
    __u8  comm[COMM_LEN];
    __u8  exe_path[PATH_LEN];
    __u8  cwd[PATH_LEN];
    __u8  username[USERNAME_LEN];
    __u32 ppid;
    __u32 argc;
    __u8  argv[ARGV_COUNT][ARGV_ITEM_LEN];
} __attribute__((packed));

/* Outbound TCP connection event */
struct bpf_network_connect_event {
    struct bpf_event_header header;
    __u8  comm[COMM_LEN];
    __u32 src_ip;       /* network byte order */
    __u32 dst_ip;       /* network byte order */
    __u16 src_port;     /* host byte order */
    __u16 dst_port;     /* host byte order */
    __u8  proto;        /* IPPROTO_TCP=6 or IPPROTO_UDP=17 */
    __u8  _pad[7];
} __attribute__((packed));

/* File access event */
struct bpf_file_access_event {
    struct bpf_event_header header;
    __u8  comm[COMM_LEN];
    __u8  path[PATH_LEN];
    __s32 flags;        /* openat(2) flags argument */
    __u32 _pad;
} __attribute__((packed));
