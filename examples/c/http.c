#include "http.skel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <bpf/bpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv){
    struct http_bpf *skel;
    int err;
    libbpf_set_print(libbpf_print_fn);

    /* Open load and verify BPF application */
    skel = http_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Attach xdp handler */
    err = http_bpf__attach_xdp(skel, 4);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    while (1) {
        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    http_bpf__destroy(skel);
    return -err;
}
