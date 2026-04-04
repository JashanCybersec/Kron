/* network_connect.bpf.c
 *
 * eBPF kprobe attached to tcp_v4_connect.
 * Captures outbound TCP connection attempts and writes to KRON_EVENTS.
 *
 * Note: tcp_v4_connect is called before the TCP handshake completes.
 * The connection may still fail after this event is emitted; the outcome
 * is not captured here (follow-up kretprobe would be needed).
 */

#include "vmlinux.h"
#include "kron_types.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* Reference to the shared ring buffer defined in process_create.bpf.c.
 * All three object files are linked together before loading. */
extern struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
} KRON_EVENTS SEC(".maps");

/* Per-CPU scratch for the network event struct. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct bpf_network_connect_event);
} scratch_net SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int kron_network_connect(struct pt_regs *ctx)
{
    __u32 key = 0;
    struct bpf_network_connect_event *ev;

    ev = bpf_map_lookup_elem(&scratch_net, &key);
    if (!ev)
        return 0;

    __builtin_memset(ev, 0, sizeof(*ev));

    /* The first argument to tcp_v4_connect is struct sock *sk. */
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

    ev->header.kind     = KRON_EVENT_NETWORK_CONNECT;
    ev->header.ktime_ns = bpf_ktime_get_ns();
    ev->header.pid      = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    ev->header.uid      = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    ev->header.gid      = bpf_get_current_uid_gid() >> 32;

    bpf_get_current_comm(ev->comm, sizeof(ev->comm));

    /* Read source and destination IPs/ports via CO-RE. */
    ev->src_ip   = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    ev->dst_ip   = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    ev->dst_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    /* skc_num is in host byte order; skc_dport is in network byte order.
     * We standardise both to host byte order in userspace. */
    ev->src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    ev->proto    = 6; /* IPPROTO_TCP */

    bpf_ringbuf_output(&KRON_EVENTS, ev, sizeof(*ev), 0);
    return 0;
}
