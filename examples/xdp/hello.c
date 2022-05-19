#include <linux/bpf.h>
#include <bpf/libbpf.h>

#ifdef HELLO_XDP
  #define RET XDP_PASS

#else
  #define RET 0

#endif

SEC("hello")
int main(void *ctx) {
    char fmt[] = "Hello, World!\n";
    bpf_trace_printk(fmt, sizeof(fmt));

    return RET;
}

char _license[] SEC("license") = "Dual MIT/GPL";
