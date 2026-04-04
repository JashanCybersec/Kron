/* file_access.bpf.c
 *
 * eBPF tracepoint attached to sys_enter_openat.
 * Captures file access events on sensitive paths and writes to KRON_EVENTS.
 *
 * Path filtering is performed in userspace (src/ebpf/linux.rs) because the
 * sensitive path list is configurable and too large to store efficiently in
 * eBPF maps with string prefix matching. The eBPF program emits ALL openat
 * calls; userspace filters by prefix.
 *
 * args[1] = pathname (const char __user *)
 * args[2] = flags    (int)
 * args[3] = mode     (umode_t)
 */

#include "vmlinux.h"
#include "kron_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
} KRON_EVENTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct bpf_file_access_event);
} scratch_file SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int kron_file_access(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    struct bpf_file_access_event *ev;

    ev = bpf_map_lookup_elem(&scratch_file, &key);
    if (!ev)
        return 0;

    __builtin_memset(ev, 0, sizeof(*ev));

    ev->header.kind     = KRON_EVENT_FILE_ACCESS;
    ev->header.ktime_ns = bpf_ktime_get_ns();
    ev->header.pid      = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    ev->header.uid      = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->header.gid      = bpf_get_current_uid_gid() >> 32;

    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    /* args[1] is the pathname pointer. */
    const char *pathname = (const char *)ctx->args[1];
    bpf_probe_read_user_str(ev->path, sizeof(ev->path), pathname);

    /* args[2] is the flags. */
    ev->flags = (__s32)ctx->args[2];

    bpf_ringbuf_output(&KRON_EVENTS, ev, sizeof(*ev), 0);
    return 0;
}
