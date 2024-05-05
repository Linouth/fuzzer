const std = @import("std");
const linux = std.os.linux;

const UserRegs = struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
    fs_base: u64,
    gs_base: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = try std.process.argsAlloc(std.heap.page_allocator);
    std.debug.print("{s}\n", .{args});
    if (args.len < 2) {
        std.debug.print("Missing fuzzee.\n", .{});
        std.process.exit(1);
    }

    const pid = try std.posix.fork();
    std.debug.print("pid: {}\n", .{pid});

    if (pid == 0) {
        std.debug.print("Execve {any}\n", .{args[1..]});
        try std.posix.ptrace(linux.PTRACE.TRACEME, pid, 0, 0);

        // TODO: Replace this call to a direct execvpeZ call (heap allocations)
        const e = std.process.execve(allocator, args[1..], null);
        //const e = std.posix.execvpeZ(args[1], &.{args[1..], null}, &.{null});
        std.debug.panic("Execve err: {s}\n", .{ @errorName(e) });
    }

    const running = true;
    var regs: UserRegs = undefined;

    var map = std.AutoHashMap(u64, u32).init(allocator);
    var syscalls = std.AutoHashMap(u64, u64).init(allocator);

    var timer = try std.time.Timer.start();
    var t0: u64 = 0;

    const SyscallState = enum {
        undefined,
        entry,
        exit,
    };
    var syscall_state: SyscallState = .undefined;

    const WaitStatus = union(enum) {
        const Self = @This();

        Exited: u8,
        Signaled: u32,
        Stopped: u32,

        fn parse(status: u32) Self {
            return if (linux.W.IFEXITED(status))
                Self{ .Exited = linux.W.EXITSTATUS(status) }
            else if (linux.W.IFSIGNALED(status))
                Self{ .Signaled = linux.W.TERMSIG(status) }
            else if (linux.W.IFSTOPPED(status))
                Self{ .Stopped = linux.W.STOPSIG(status) }
            else unreachable;
        }
    };

    while (running) {
        const ret = std.posix.waitpid(-1, 0);
        const status = WaitStatus.parse(ret.status);

        switch (status) {
            .Exited => break,
            .Stopped => |sig| switch (sig) {
                // First trap is due to execve
                linux.SIG.TRAP =>
                    syscall_state = if (syscall_state == .entry) .exit else .entry,
                linux.SIG.SEGV => break,
                linux.SIG.CHLD => break,
                // linux.SIG.ABRT => break,
                else => std.debug.print("Unhandled SIG: {}\n", .{sig}),
            },
            else => std.debug.print("{?}\n", .{status}),
        }
        //std.debug.print("Waitpid returned, pid: {}, status: {}\n", .{ret.pid, ret.status});

        try std.posix.ptrace(linux.PTRACE.GETREGS, ret.pid, 0, @intFromPtr(&regs));
        const count = map.get(regs.rip) orelse 0;
        try map.put(regs.rip, count + 1);

        if (syscall_state == .entry) {
            try syscalls.put(regs.rip, regs.orig_rax);
        }

        // std.debug.print("Getregs done? {}", .{regs});

        //try std.posix.ptrace(linux.PTRACE.SINGLESTEP, ret.pid, 0, 0);
        try std.posix.ptrace(linux.PTRACE.SYSCALL, ret.pid, 0, 0);
        //try std.posix.ptrace(linux.PTRACE.CONT, ret.pid, 0, 0);
        t0 = timer.read();
    }
    const elapsed = timer.read();
    std.debug.print("Took {} ns\n", .{elapsed});

    {
        var it = map.iterator();
        while (it.next()) |kv| {
            std.debug.print("0x{x}\t{}\n", .{kv.key_ptr.*, kv.value_ptr.*});
        }
    }

    {
        std.debug.print("Syscalls:\n", .{});
        var it = syscalls.iterator();
        while (it.next()) |kv| {
            const syscall: linux.syscalls.X64 = @enumFromInt(kv.value_ptr.*);
            std.debug.print("0x{x}\t{}\n", .{kv.key_ptr.*, syscall});
        }
    }
}

