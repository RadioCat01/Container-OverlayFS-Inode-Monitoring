# Container-OverlayFS-Inode-Monitoring
#### bpftraceV1
```
#!/bin/bash

if [ -d /sys/fs/cgroup/kubepods.slice ]; then
  ROOT=/sys/fs/cgroup/kubepods.slice
elif [ -d /sys/fs/cgroup/unified/kubepods.slice ]; then
  ROOT=/sys/fs/cgroup/unified/kubepods.slice
elif [ -d /sys/fs/cgroup/kubepods ]; then
  ROOT=/sys/fs/cgroup/kubepods
else
  echo "kubepods path not found under /sys/fs/cgroup. Inspect /sys/fs/cgroup manually."; exit 1
fi
echo "Using ROOT = $ROOT"

IDS=$(sudo find "$ROOT" -type d -printf '%i ' 2>/dev/null)

if [ -z "$IDS" ]; then
  echo "No descendant cgroup inodes found under $ROOT"
  echo "Try running: sudo find $ROOT -type d -printf '%i %p\n' to inspect"
  exit 1
fi

PRED=$(echo $IDS | awk '{for(i=1;i<=NF;i++){ if(i>1) printf " || "; printf "cgroup == %s", $i }}')

sudo bpftrace -e "
tracepoint:syscalls:sys_enter_mkdir,
tracepoint:syscalls:sys_enter_mkdirat
/ ($PRED) /
{
    printf(\"[mkdir] pid=%d cgid=%llu comm=%s pathname=%s mode=%d\\n\",
           pid, cgroup, comm, str(args->pathname), args->mode);
}
tracepoint:syscalls:sys_enter_open,
tracepoint:syscalls:sys_enter_openat
/ ($PRED) && (args->flags & 0x40) /
{
    printf(\"[open] pid=%d cgid=%llu comm=%s pathname=%s flags=%d mode=%d\\n\",
           pid, cgroup, comm, str(args->filename), args->flags, args->mode);
}
tracepoint:syscalls:sys_enter_mknod,
tracepoint:syscalls:sys_enter_mknodat
/ ($PRED) /
{
    printf(\"[mknod] pid=%d cgid=%llu comm=%s pathname=%s mode=%d dev=%d\\n\",
           pid, cgroup, comm, str(args->filename), args->mode, args->dev);
}
tracepoint:syscalls:sys_enter_symlink,
tracepoint:syscalls:sys_enter_symlinkat
/ ($PRED) /
{
    printf(\"[symlink] pid=%d cgid=%llu comm=%s target=%s linkpath=%s\\n\",
           pid, cgroup, comm, str(args->oldname), str(args->newname));
}
"
```

# Go - Daemon
```
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/aquasecurity/libbpfgo"
)

type event struct {
	Type   [8]byte
	Cgroup uint64
	Mode   uint32
}

func main() {
	candidates := []string{
		"/sys/fs/cgroup/kubepods.slice",
		"/sys/fs/cgroup/unified/kubepods.slice",
		"/sys/fs/cgroup/kubepods",
	}
	var root string
	for _, path := range candidates {
		if info, err := os.Stat(path); err == nil && info.IsDir() {
			root = path
			break
		}
	}
	if root == "" {
		fmt.Println("kubepods path not found under /sys/fs/cgroup. Inspect /sys/fs/cgroup manually.")
		os.Exit(1)
	}
	fmt.Println("Using ROOT =", root)

	var ids []uint64
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			info, err := d.Info()
			if err != nil {
				return nil // Skip on error
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if ok {
				ids = append(ids, stat.Ino)
			}
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	if len(ids) == 0 {
		fmt.Println("No descendant cgroup inodes found under", root)
		fmt.Println("Try running: sudo find", root, "-type d -printf '%i %p\\n' to inspect")
		os.Exit(1)
	}

	// Load eBPF module
	module, err := libbpfgo.NewModuleFromFile("trace.bpf.o")
	if err != nil {
		fmt.Println("Error loading eBPF object:", err)
		os.Exit(1)
	}
	defer module.Close()

	// Load the eBPF object into the kernel
	err = module.BPFLoadObject()
	if err != nil {
		fmt.Println("Error loading BPF object into kernel:", err)
		os.Exit(1)
	}

	// Get and update cgroup map
	cgroupMap, err := module.GetMap("cgroup_filter")
	if err != nil {
		fmt.Println("Error getting map:", err)
		os.Exit(1)
	}
	dummy := uint32(1)
	for _, id := range ids {
		err = cgroupMap.Update(unsafe.Pointer(&id), unsafe.Pointer(&dummy))
		if err != nil {
			fmt.Println("Error updating map:", err)
		}
	}
	fmt.Println("Cgroup map updated with", len(ids), "IDs")

	// Attach to all tracepoints
	tracepoints := []string{
		"mkdir", "mkdirat",
		"open", "openat",
		"mknod", "mknodat",
		"symlink", "symlinkat",
	}
	for _, tp := range tracepoints {
		prog, err := module.GetProgram("trace_" + tp)
		if err != nil {
			fmt.Println("Error getting program:", err)
			continue
		}
		_, err = prog.AttachTracepoint("syscalls", "sys_enter_"+tp)
		if err != nil {
			fmt.Println("Error attaching sys_enter_"+tp+":", err)
		}
	}

	// Initialize ring buffer
	eventsChan := make(chan []byte, 1024)
	rb, err := module.InitRingBuf("events", eventsChan)
	if err != nil {
		fmt.Println("Error initializing ringbuf:", err)
		os.Exit(1)
	}
	rb.Start()
	defer rb.Stop()

	fmt.Println("Tracing started. Press Ctrl+C to stop.")

	for {
		select {
		case data := <-eventsChan:
			var e event
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &e)
			if err != nil {
				fmt.Println("Error parsing event:", err)
				continue
			}
			typ := strings.TrimRight(string(e.Type[:]), "\x00")
			fmt.Printf("[%s] cgid=%llu mode=%d\n", typ, e.Cgroup, e.Mode)
		}
	}
}
```
# C eBPF Code
```
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct event {
    char type[8];  // e.g., "open", "mkdir"
    u64 cgroup;
    u32 mode;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);  // Sufficient for typical pod counts
    __type(key, u64);           // cgroup ID
    __type(value, u32);         // dummy value (e.g., 1)
} cgroup_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

#define O_CREAT 0x40

// Helper macro for common filtering and reservation
#define FILTER_AND_RESERVE \
    u64 cg = bpf_get_current_cgroup_id(); \
    u32 *val = bpf_map_lookup_elem(&cgroup_filter, &cg); \
    if (!val) return 0; \
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0); \
    if (!e) return 0; \
    e->cgroup = cg;

SEC("tracepoint/syscalls/sys_enter_mkdir")
int trace_mkdir(struct trace_event_raw_sys_enter *ctx) {
    FILTER_AND_RESERVE
    e->mode = BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_str(e->type, sizeof(e->type), "mkdir");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mkdirat")
int trace_mkdirat(struct trace_event_raw_sys_enter *ctx) {
    FILTER_AND_RESERVE
    e->mode = BPF_CORE_READ(ctx, args[2]);
    bpf_probe_read_str(e->type, sizeof(e->type), "mkdirat");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx) {
    u64 flags = BPF_CORE_READ(ctx, args[1]);
    if (!(flags & O_CREAT)) return 0;
    FILTER_AND_RESERVE
    e->mode = BPF_CORE_READ(ctx, args[2]);
    bpf_probe_read_str(e->type, sizeof(e->type), "open");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    u64 flags = BPF_CORE_READ(ctx, args[2]);
    if (!(flags & O_CREAT)) return 0;
    FILTER_AND_RESERVE
    e->mode = BPF_CORE_READ(ctx, args[3]);
    bpf_probe_read_str(e->type, sizeof(e->type), "openat");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknod")
int trace_mknod(struct trace_event_raw_sys_enter *ctx) {
    FILTER_AND_RESERVE
    e->mode = BPF_CORE_READ(ctx, args[1]);
    bpf_probe_read_str(e->type, sizeof(e->type), "mknod");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_mknodat")
int trace_mknodat(struct trace_event_raw_sys_enter *ctx) {
    FILTER_AND_RESERVE
    e->mode = BPF_CORE_READ(ctx, args[2]);
    bpf_probe_read_str(e->type, sizeof(e->type), "mknodat");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlink")
int trace_symlink(struct trace_event_raw_sys_enter *ctx) {
    FILTER_AND_RESERVE
    e->mode = 0;
    bpf_probe_read_str(e->type, sizeof(e->type), "symlink");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_symlinkat")
int trace_symlinkat(struct trace_event_raw_sys_enter *ctx) {
    FILTER_AND_RESERVE
    e->mode = 0;
    bpf_probe_read_str(e->type, sizeof(e->type), "symlinkat");
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```
