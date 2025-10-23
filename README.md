# Container-OverlayFS-Inode-Monitoring
#### bpftraceV1
```
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
tracepoint:syscalls:sys_enter_mkdir / ($PRED) /
{
    printf(\"[mkdir] pid=%d cgid=%llu comm=%s pathname=%s mode=%d\\n\",
           pid, cgroup, comm, str(args->pathname), args->mode);
}
"

```
