/* process_create.bpf.c
 *
 * eBPF tracepoint program attached to sys_enter_execve.
 * Captures process creation events and writes them to the KRON_EVENTS ring buffer.
 *
 * CO-RE: compiled with clang + BTF; runs on kernel 5.4+ without recompilation.
 */

#include "vmlinux.h"
#include "kron_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* Shared ring buffer map — KRON_EVENTS.
 * All three eBPF programs write to this single map.
 * Userspace reads from it via aya's RingBuf API.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024); /* 64 MB; overridden by EbpfManager */
} KRON_EVENTS SEC(".maps");

/* Per-CPU scratch space for the large event struct.
 * Using a per-CPU map avoids stack size limits (512 bytes in eBPF). */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct bpf_process_create_event);
} scratch_process SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int kron_process_create(struct trace_event_raw_sys_enter *ctx)
{
    __u32 key = 0;
    struct bpf_process_create_event *ev;

    ev = bpf_map_lookup_elem(&scratch_process, &key);
    if (!ev)
        return 0;

    /* Zero the scratch buffer before use. */
    __builtin_memset(ev, 0, sizeof(*ev));

    /* Populate header. */
    ev->header.kind      = KRON_EVENT_PROCESS_CREATE;
    ev->header.ktime_ns  = bpf_ktime_get_ns();
    ev->header.pid       = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    ev->header.uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->header.gid       = bpf_get_current_uid_gid() >> 32;

    /* Process name from task_struct->comm. */
    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    /* Executable path from argv[0] (ctx->args[0] = *filename).
     * Safety: bpf_probe_read_user_str returns <=PATH_LEN and NUL-terminates. */
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(ev->exe_path, sizeof(ev->exe_path), filename);

    /* Parent PID. */
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ev->ppid = BPF_CORE_READ(task, parent, tgid);

    /* Capture up to ARGV_COUNT argv strings. */
    const char * const *argv = (const char * const *)ctx->args[1];
    __u32 i;

    /* Unrolled loop for eBPF verifier (must be bounded). */
    #pragma unroll
    for (i = 0; i < ARGV_COUNT; i++) {
        const char *arg = NULL;
        if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) < 0)
            break;
        if (!arg)
            break;
        bpf_probe_read_user_str(ev->argv[i], sizeof(ev->argv[i]), arg);
        ev->argc = i + 1;
    }

    /* Submit event to ring buffer. */
    bpf_ringbuf_output(&KRON_EVENTS, ev, sizeof(*ev), 0);
    return 0;
}
