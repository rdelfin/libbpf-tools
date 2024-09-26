// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "filesnoop.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} open_events SEC(".maps");

// name: sys_enter_open
// ID: 692
// format:
//         field:unsigned short common_type;       offset:0;       size:2; signed:0;
//         field:unsigned char common_flags;       offset:2;       size:1; signed:0;
//         field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
//         field:int common_pid;   offset:4;       size:4; signed:1;
//
//         field:int __syscall_nr; offset:8;       size:4; signed:1;
//         field:const char * filename;    offset:16;      size:8; signed:0;
//         field:int flags;        offset:24;      size:8; signed:0;
//         field:umode_t mode;     offset:32;      size:8; signed:0;
//
// print fmt: "filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))

SEC("tp/syscalls/sys_enter_open")
int handle_open_enter(struct trace_event_raw_sys_enter *ctx)
{
    /* reserve sample from BPF ringbuf */
    struct open_event* event = bpf_ringbuf_reserve(&open_events, sizeof(struct open_event), 0);
    if (!event) return 0;

    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    uint64_t ts = bpf_ktime_get_ns();


    /* fill out the sample with data */
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();

    event->pid = pid;
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_probe_read_str(&event->filename, sizeof(event->filename), (void*)ctx->args[0]);

    /* send data to user-space for post-processing */
    bpf_ringbuf_submit(event, 0);
    return 0;
}
