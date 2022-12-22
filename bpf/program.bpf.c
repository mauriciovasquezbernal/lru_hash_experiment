#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


#define MAX_REQ_TS_MAP_ENTRIES 256
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_REQ_TS_MAP_ENTRIES);
	__type(key, __u32);   // ID field of the DNS packet
	__type(value, __u64); // Timestamp for when the DNS request was sent.
} mymap SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_open")
int open_tracepoint(void* ctx)
{
	__u32 r = bpf_get_prandom_u32();
	__u64 val = 1;

	bpf_map_update_elem(&mymap, &r, &val, BPF_ANY);

	return 0;
}

char __license[] SEC("license") = "GPL";