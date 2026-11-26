import { OperationError } from "../db/mcp-operations";

const maxCommandBytes = 4096;
const maxTimeoutMs = 600_000;
const bwrapPaths = ["/usr/bin/bwrap", "/bin/bwrap", "/usr/libexec/flatpak-bwrap"];
const busyboxPaths = ["/usr/bin/busybox", "/bin/busybox", "/usr/bin/busybox.static", "/bin/busybox.static"];

export function validateWorkspaceCommand(value: unknown): string {
  if (typeof value !== "string" || !value.trim() || /[\u0000\uD800-\uDFFF]/u.test(value)) {
    throw new OperationError("Expected a nonempty UTF-8 workspace command", 400);
  }
  if (new TextEncoder().encode(value).length > maxCommandBytes) {
    throw new OperationError("Workspace command exceeds 4096 bytes", 413);
  }
  return value;
}

// This fixed launcher runs on the SSH host. The only variable argument is
// data for the inner shell. All setup finishes before that shell can start.
const launcher = String.raw`
import base64
import ctypes as C
import errno
import os
import resource
import stat
import struct
import subprocess
import sys

# The outer shell has a fixed inventory for an interpreter that cannot run
# this launcher, including stripped installations missing extension modules.
if (sys.version_info < (3, 7)
        or not all(hasattr(os, name) for name in ("memfd_create", "MFD_CLOEXEC", "getxattr", "getresuid",
                   "getresgid", "setresuid", "setresgid", "setgroups", "set_inheritable"))
        or not all(hasattr(resource, name) for name in ("RLIMIT_NPROC", "RLIMIT_NOFILE", "RLIMIT_AS",
                   "RLIMIT_FSIZE", "RLIMIT_CORE", "RLIMIT_CPU"))):
    sys.exit(126)

BWRAP = ${JSON.stringify(bwrapPaths)}
BUSYBOX = ${JSON.stringify(busyboxPaths)}
APPLETS = "sh ash awk basename cat chmod cp cut date dirname echo env expr false grep head id ls mkdir mv printf pwd rm rmdir sed seq sha256sum sleep sort tail tee test touch tr true uname uniq uptime wc xargs".split()

def unavailable(reason, inventory=None):
    os.write(2, ("ternssh: isolated workspace unavailable (" + reason + ")\n").encode())
    if inventory is not None:
        os.write(2, ("ternssh: prerequisites v1 " + " ".join(k + "=" + v for k, v in inventory.items()) + "\n").encode())
    sys.exit(125)

def trusted_path(path):
    # Only the standard usr-merge /bin link is accepted. All other directories
    # and the executable itself must be real, root-owned nodes. This also
    # rules out lookup through a trusted final name in a writable parent.
    try:
        if path.startswith("/bin/") and stat.S_ISLNK(os.lstat("/bin").st_mode):
            if os.lstat("/bin").st_uid != 0 or os.readlink("/bin") not in ("usr/bin", "/usr/bin"):
                return None, "unsafe"
            path = "/usr" + path
        parent = os.path.dirname(path)
        while True:
            node = os.lstat(parent)
            if not stat.S_ISDIR(node.st_mode) or node.st_uid != 0 or node.st_mode & 0o022:
                return None, "unsafe"
            if parent == "/":
                break
            parent = os.path.dirname(parent)
        node = os.lstat(path)
        if not stat.S_ISREG(node.st_mode) or node.st_uid != 0 or node.st_mode & 0o6022 or not os.access(path, os.X_OK):
            return None, "unsafe"
        try:
            os.getxattr(path, "security.capability", follow_symlinks=False)
        except OSError as e:
            if e.errno != errno.ENODATA:
                return None, "unsafe"
        else:
            return None, "unsafe"
        return path, "ready"
    except FileNotFoundError:
        return None, "missing"
    except OSError:
        return None, "unsafe"

def native_elf(path, static):
    # The shell has no dynamic loader in its filesystem. Bwrap may use the
    # host loader but must be a native executable before the fixed help probe.
    with open(path, "rb") as f:
        header = f.read(64)
        if len(header) != 64 or header[:7] != b"\x7fELF\x02\x01\x01":
            return False
        kind, machine = struct.unpack_from("<HH", header, 16)
        if kind not in (2, 3) or machine != {"x86_64": 62, "aarch64": 183}.get(os.uname().machine):
            return False
        position = struct.unpack_from("<Q", header, 32)[0]
        size, count = struct.unpack_from("<HH", header, 54)
        if size != 56 or count == 0 or count > 128 or position + size * count > os.fstat(f.fileno()).st_size:
            return False
        f.seek(position)
        headers = f.read(size * count)
        if len(headers) != size * count:
            return False
        segments = {struct.unpack_from("<I", headers, i * size)[0] for i in range(count)}
        return 1 in segments and (not static or 3 not in segments)

def select_runtime(paths, compatible):
    rejected = set()
    for path in paths:
        candidate, state = trusted_path(path)
        if candidate is not None:
            try:
                if compatible(candidate):
                    return candidate, "ready"
            except (OSError, subprocess.TimeoutExpired):
                pass
            state = "incompatible"
        rejected.add(state)
    return None, next(state for state in ("unsafe", "incompatible", "missing") if state in rejected)

def drop_privileges():
    if os.getuid() == 0:
        os.setgroups([])
        os.setresgid(65534, 65534, 65534)
        os.setresuid(65534, 65534, 65534)
    if 0 in (*os.getresuid(), *os.getresgid(), *os.getgroups()):
        unavailable("privilege_drop_failed")
    libc = C.CDLL(None)
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        unavailable("no_new_privileges")
    with open("/proc/self/status", encoding="ascii") as f:
        state = dict(line.rstrip().split(":", 1) for line in f if ":" in line)
    if state["NoNewPrivs"].strip() != "1" or any(int(state[k], 16) for k in ("CapPrm", "CapEff", "CapInh", "CapAmb")):
        unavailable("privilege_drop_failed")

def verify_scope():
    # tmpfs's byte limit does not bound all inode metadata. Check the actual
    # aggregate kernel limits inherited by the complete process tree as well.
    with open("/proc/self/cgroup", encoding="ascii") as f:
        membership = next((line[3:].strip() for line in f if line.startswith("0::")), "")
    if not membership.endswith(".scope"):
        unavailable("resource_scope_unavailable")
    group = os.path.join("/sys/fs/cgroup", membership.lstrip("/"))
    def read(name):
        with open(os.path.join(group, name), encoding="ascii") as f:
            return f.read().strip()
    try:
        cpu, period = map(int, read("cpu.max").split())
        if not (0 < int(read("memory.max")) <= (192 << 20) and int(read("memory.swap.max")) == 0
                and 0 < int(read("pids.max")) <= 24 and 0 < 2 * cpu <= period):
            unavailable("resource_scope_unavailable")
    except (OSError, ValueError):
        unavailable("resource_scope_unavailable")

def syscall_filter(lib):
    pointer = C.c_void_p
    lib.seccomp_init.argtypes = [C.c_uint32]
    lib.seccomp_init.restype = pointer
    lib.seccomp_syscall_resolve_name.argtypes = [C.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = C.c_int
    class Compare(C.Structure):
        _fields_ = [("arg", C.c_uint), ("op", C.c_uint), ("a", C.c_uint64), ("b", C.c_uint64)]
    lib.seccomp_rule_add_array.argtypes = [pointer, C.c_uint32, C.c_int, C.c_uint, C.POINTER(Compare)]
    lib.seccomp_export_bpf.argtypes = [pointer, C.c_int]
    lib.seccomp_release.argtypes = [pointer]
    ctx = lib.seccomp_init(0x00050000 | errno.ENOSYS)  # SCMP_ACT_ERRNO
    if not ctx:
        unavailable("seccomp_unavailable")
    # Native ABI only. No socket families, namespace/mount APIs, IPC to the
    # host, keyring, device requests, tracing, or asynchronous I/O interfaces.
    names = """
        read write readv writev close close_range lseek pread64 pwrite64 open openat creat access faccessat faccessat2
        stat lstat fstat newfstatat statx getdents getdents64 readlink readlinkat getcwd chdir fchdir
        mkdir mkdirat unlink unlinkat rmdir rename renameat renameat2 link linkat symlink symlinkat chmod
        fchmod fchmodat fchmodat2 truncate ftruncate fsync fdatasync umask utime utimes utimensat
        dup dup2 dup3 pipe pipe2 fcntl sendfile copy_file_range poll ppoll select pselect6
        mmap mremap mprotect munmap brk madvise rt_sigaction rt_sigprocmask rt_sigreturn sigaltstack
        getpid getppid gettid getuid geteuid getgid getegid getgroups getpgid getpgrp setpgid wait4 waitid kill tgkill
        clock_gettime clock_nanosleep gettimeofday nanosleep time times execve exit exit_group fork vfork clone
        arch_prctl set_tid_address set_robust_list rseq futex getrandom getrlimit getrusage uname sysinfo prlimit64
    """.split()
    for name in names:
        nr = lib.seccomp_syscall_resolve_name(name.encode())
        if nr < 0:
            continue  # Not a native syscall on this architecture.
        rule = None
        if name == "clone":
            # Only normal fork/vfork flags and an exit signal. Arg 0 is flags
            # on the two supported 64-bit architectures.
            normal = 0xff | 0x100 | 0x4000 | 0x100000 | 0x200000 | 0x1000000
            rule = Compare(0, 7, 0xffffffffffffffff ^ normal, 0)  # SCMP_CMP_MASKED_EQ
        if name == "prlimit64":
            rule = Compare(2, 4, 0, 0)  # SCMP_CMP_EQ; queries only
        if lib.seccomp_rule_add_array(ctx, 0x7fff0000, nr, int(rule is not None), C.byref(rule) if rule else None) != 0:
            unavailable("seccomp_filter_failed")
    fd = os.memfd_create("ternssh-workspace-filter", os.MFD_CLOEXEC)
    if lib.seccomp_export_bpf(ctx, fd) != 0:
        unavailable("seccomp_filter_failed")
    lib.seccomp_release(ctx)
    os.lseek(fd, 0, os.SEEK_SET)
    os.set_inheritable(fd, True)
    return fd

def sandbox_args(bwrap, busybox, filter_fd):
    args = [bwrap, "--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-net", "--unshare-uts",
            "--disable-userns", "--hostname", "workspace", "--uid", "65534", "--gid", "65534",
            "--new-session", "--die-with-parent", "--cap-drop", "ALL", "--clearenv",
            "--setenv", "PATH", "/bin", "--setenv", "HOME", "/work", "--setenv", "LC_ALL", "C",
            "--setenv", "TMPDIR", "/work", "--ro-bind", busybox, "/bin/busybox",
            "--dev-bind", "/dev/null", "/dev/null", "--ro-bind", "/proc/uptime", "/proc/uptime",
            "--perms", "0777", "--size", str(8 << 20), "--tmpfs", "/work", "--chdir", "/work"]
    for name in APPLETS:
        args.extend(["--symlink", "busybox", "/bin/" + name])
    return args + ["--remount-ro", "/", "--seccomp", str(filter_fd)]

def bwrap_supports_args(path):
    if not native_elf(path, False):
        return False
    help_text = subprocess.run([path, "--help"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, env={"LC_ALL": "C"}, timeout=2, close_fds=True)
    available = {line.split()[0] for line in help_text.stdout.splitlines() if line.strip()}
    required = {arg.encode() for arg in sandbox_args(path, "busybox", 0) if arg.startswith("--")}
    return help_text.returncode == 0 and required <= available

def static_busybox_has_shell(path):
    if not native_elf(path, True):
        return False
    applets = subprocess.run(["busybox", "--list"], executable=path, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, env={"LC_ALL": "C"}, timeout=2, close_fds=True)
    return applets.returncode == 0 and b"sh" in applets.stdout.splitlines()

def runtimes(inspect):
    has_systemd = os.access("/usr/bin/systemd-run", os.X_OK)
    has_timeout = os.access("/usr/bin/timeout", os.X_OK)
    has_cgroup = os.path.isfile("/sys/fs/cgroup/cgroup.controllers")
    try:
        seccomp = C.CDLL("libseccomp.so.2")
    except OSError:
        seccomp = None
    arch = os.uname().machine
    base_ready = has_systemd and has_timeout and has_cgroup and seccomp is not None and arch in ("x86_64", "aarch64")
    if inspect and base_ready:
        # On the common path only check metadata before entering the scope.
        # The actual executable/option checks below run inside its deadline.
        if any(trusted_path(path)[0] for path in BWRAP) and any(trusted_path(path)[0] for path in BUSYBOX):
            return None, None, seccomp
    bwrap, bwrap_state = select_runtime(BWRAP, bwrap_supports_args)
    busybox, busybox_state = select_runtime(BUSYBOX, static_busybox_has_shell)
    if bwrap and busybox and base_ready:
        return bwrap, busybox, seccomp
    if arch not in ("x86_64", "aarch64"):
        reason = "unsupported_platform"
    elif not bwrap:
        reason = "missing_bwrap" if bwrap_state == "missing" else "unusable_bwrap"
    elif not busybox:
        reason = "missing_static_busybox" if busybox_state == "missing" else "unusable_static_busybox"
    elif not has_systemd or not has_timeout:
        reason = "missing_runtime"
    elif seccomp is None:
        reason = "missing_libseccomp"
    else:
        reason = "resource_scope_unavailable"
    unavailable(reason, dict(python3="ok", systemd_run="present" if has_systemd else "missing",
                timeout="present" if has_timeout else "missing", arch=arch if arch in ("x86_64", "aarch64") else "unsupported",
                bwrap=bwrap_state, busybox=busybox_state, libseccomp="loadable" if seccomp is not None else "unavailable",
                cgroup_v2="present" if has_cgroup else "missing",
                scope="unverified", namespaces="unverified"))

def start():
    inspect = sys.argv[1] == "--inspect"
    if not inspect:
        verify_scope()
    os.chdir("/")
    drop_privileges()
    bwrap, busybox, seccomp = runtimes(inspect)
    if inspect:
        return
    for entry in os.listdir("/proc/self/fd"):
        fd = int(entry)
        if fd > 2:
            try:
                os.close(fd)
            except OSError:
                pass
    # The command has no stdin, no SSH agent socket, and no inherited
    # descriptors beyond its output pipes.
    with open("/dev/null", "rb") as stdin:
        os.dup2(stdin.fileno(), 0)
    filter_fd = syscall_filter(seccomp)
    for kind, ceiling in ((resource.RLIMIT_NPROC, 16), (resource.RLIMIT_NOFILE, 64),
                          (resource.RLIMIT_AS, 64 << 20), (resource.RLIMIT_FSIZE, 8 << 20),
                          (resource.RLIMIT_CORE, 0), (resource.RLIMIT_CPU, 30)):
        _, hard = resource.getrlimit(kind)
        limit = ceiling if hard == resource.RLIM_INFINITY else min(ceiling, hard)
        resource.setrlimit(kind, (limit, limit))
    args = sandbox_args(bwrap, busybox, filter_fd)
    command = base64.b64decode(sys.argv[1], validate=True)
    args.extend(["--", "/bin/sh", "-c", command])
    os.execve(bwrap, args, {})

try:
    start()
except (OSError, ValueError, KeyError, AttributeError, MemoryError):
    unavailable("sandbox_setup_failed")
`.trim();

function quoteShellArg(arg: string) {
  return "'" + arg.replaceAll("'", "'\\''") + "'";
}

// Only fixed presence checks are possible without a working host interpreter.
const noPythonReport = `
candidate_state() {
  for f do
    if [ -e "$f" ] || [ -L "$f" ]; then printf unverified; return; fi
  done
  printf missing
}
bwrap=$(candidate_state ${bwrapPaths.join(" ")})
busybox=$(candidate_state ${busyboxPaths.join(" ")})
systemd_run=missing; [ ! -x /usr/bin/systemd-run ] || systemd_run=present
timeout=missing; [ ! -x /usr/bin/timeout ] || timeout=present
cgroup=missing; [ ! -f /sys/fs/cgroup/cgroup.controllers ] || cgroup=present
reason=missing_runtime
if [ "$bwrap" = missing ]; then reason=missing_bwrap; elif [ "$busybox" = missing ]; then reason=missing_static_busybox; fi
printf 'ternssh: isolated workspace unavailable (%s)\\n' "$reason" >&2
printf 'ternssh: prerequisites v1 python3=%s systemd_run=%s timeout=%s arch=unverified bwrap=%s busybox=%s libseccomp=unverified cgroup_v2=%s scope=unverified namespaces=unverified\\n' "$python_state" "$systemd_run" "$timeout" "$bwrap" "$busybox" "$cgroup" >&2
exit 125
`.trim();

export function workspaceShellCommand(value: string, timeoutMs = 120_000): string {
  const command = validateWorkspaceCommand(value);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > maxTimeoutMs) {
    throw new OperationError("Invalid workspace timeout", 400);
  }
  const payload = btoa(String.fromCharCode(...new TextEncoder().encode(command)));
  // timeout is independent of the Worker. If its lease expires, bubblewrap's
  // parent-death chain kills the process tree, including background tasks.
  const duration = (timeoutMs / 1000).toFixed(3);
  return "ternssh_launcher=" + quoteShellArg(launcher) + "; " +
    'python_state=missing; if [ -x /usr/bin/python3 ]; then ' +
    'inspection=$(/usr/bin/env -i LC_ALL=C /usr/bin/python3 -BIS -c "$ternssh_launcher" --inspect 2>&1); ' +
    'case $? in 0) python_state=ok;; 125) printf \'%s\\n\' "$inspection" >&2; exit 125;; *) python_state=incompatible;; esac; fi; ' +
    'if [ "$python_state" != ok ]; then\n' + noPythonReport + "\nfi; " +
    'uid=$(/usr/bin/id -u) || exit 125; if [ "$uid" = 0 ]; then set --; else set -- --user; fi; ' +
    'exec /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C XDG_RUNTIME_DIR=/run/user/"$uid" ' +
    '/usr/bin/systemd-run "$@" --scope --quiet --collect --no-ask-password --description="ternssh isolated workspace" ' +
    "-p MemoryMax=192M -p MemorySwapMax=0 -p TasksMax=24 -p CPUQuota=50% " +
    "-p TimeoutStopSec=1s -p RuntimeMaxSec=" + (Math.ceil(timeoutMs / 1000) + 2) + "s " +
    "/usr/bin/timeout --kill-after=1s " +
    duration + 's /usr/bin/python3 -BIS -c "$ternssh_launcher" ' + quoteShellArg(payload);
}
