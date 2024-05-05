const std = @import("std");
const linux = std.os.linux;

const rng = std.Random.DefaultPrng.init(std.time.timestamp());

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

const TraceeState = enum {
    // Initally the tracee has to trap once after execve.
    waiting_for_execve,

    // Main running state. When in this state, the rax is stored on every trap.
    // TODO: This should only happen for syscall related reasons, for
    // code-coverage it is not really needed.
    running,

    // Used in syscall mode, so we can know whether the syscall has been called
    // or returned.
    running_alt,

    // Various reasons the program halted.
    segfaulted,
    exited,

    unknown,
};

fn spawn(args: []const []const u8) std.posix.pid_t {
    const pid = std.posix.fork() catch @panic("Fork failed!\n");

    if (pid == 0) {
        // Child
        std.posix.ptrace(linux.PTRACE.TRACEME, pid, 0, 0)
            catch @panic("TRACEME failed?\n");

        // Pipe stdout and stderr to /dev/null
        const fd = std.posix.open(
            "/dev/null", .{}, @intFromEnum(std.posix.ACCMODE.WRONLY))
            catch @panic("Could not open /dev/null\n");
        std.posix.dup2(fd, 1) catch unreachable;
        std.posix.dup2(fd, 2) catch unreachable;
        std.posix.close(fd);


        const file: [*:0]const u8 = @ptrCast(args[0]);
        //const argv: [*:null]const ?[*:0]const u8 = @ptrCast(args.ptr);

        // Taken from https://github.com/ratfactor/zigish/blob/main/src/main.zig
        // Should be able to do this much simpler. Then underlying data is not
        // changing at all, except for the added null sentinal. Could also just
        // call `libc.execve`.
        const max_args = 10;
        if (args.len > max_args)
            @panic("More arguments given than can be handled.");

        var args_ptr: [max_args:null] ?[*:0]const u8 = undefined;
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            args_ptr[i] = @ptrCast(args[i].ptr);
        }
        args_ptr[i] = null;

        // This format works
        // const tmp: [*:null]const ?[*:0]const u8 = &.{ @ptrCast(args[0]), @ptrCast(args[1]), null};

        const e = std.posix.execvpeZ(file, &args_ptr, &.{null});
        std.debug.panic("Execve err: {s}\n", .{ @errorName(e) });
    }

    return pid;
}

pub fn main() !void {
    //var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    //defer arena.deinit();
    //const allocator = arena.allocator();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();


    // Get program arguments, which should hold the to-be-fuzzed binary
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    std.debug.print("{s}\n", .{args});
    if (args.len < 3) {
        std.debug.print("Usage: {s} <input_file> <binary_to_fuzz> [<args>]\n", .{args[0]});
        std.process.exit(1);
    }

    var visited = std.AutoHashMap(u64, u32).init(allocator);
    defer visited.deinit();

    var syscalls = std.AutoHashMap(u64, u64).init(allocator);
    defer syscalls.deinit();

    var tracees = std.AutoHashMap(std.posix.pid_t, TraceeState).init(allocator);
    defer tracees.deinit();

    var start_addresses = std.AutoHashMap(std.posix.pid_t, u64).init(allocator);
    defer start_addresses.deinit();

    var regs: UserRegs = undefined;


    var tracee_count: usize = 0;
    // Spawn tracee
    for (0..1) |_| {
        const pid = spawn(args[2..]);
        try tracees.put(pid, .waiting_for_execve);
        tracee_count += 1;
    }


    const WaitStatus = union(enum) {
        const Self = @This();

        exited: u8,
        signaled: u32,
        stopped: u32,

        fn parse(status: u32) Self {
            return if (linux.W.IFEXITED(status))
                Self{ .exited = linux.W.EXITSTATUS(status) }
            else if (linux.W.IFSIGNALED(status))
                Self{ .signaled = linux.W.TERMSIG(status) }
            else if (linux.W.IFSTOPPED(status))
                Self{ .stopped = linux.W.STOPSIG(status) }
            else unreachable;
        }
    };

    var timer = try std.time.Timer.start();
    var t0: u64 = 0;

    while (true) {
        const ret = std.posix.waitpid(-1, 0);
        const status = WaitStatus.parse(ret.status);

        const state = tracees.getPtr(ret.pid).?;

        switch (status) {
            .exited => {
                state.* = .exited;
                tracee_count -= 1;

                if (tracee_count == 0)
                    break;
                continue;
            },
            .stopped => |sig| switch (sig) {
                // First trap is due to execve
                linux.SIG.TRAP => switch (state.*) {
                    .waiting_for_execve => {
                        state.* = .running;

                        // TODO: Fix this. This does not get proper field from
                        // the user struct yet.
                        //const start_addr = linux.ptrace(linux.PTRACE.PEEKUSER, ret.pid, 37*4, 0, 0);
                        const start_addr = linux.ptrace(linux.PTRACE.PEEKUSER, ret.pid, 0, 0, 0);
                        std.debug.print("0x{x}\n", .{start_addr});
                        try start_addresses.put(ret.pid, start_addr);
                    },
                    .running =>
                        state.* = .running_alt,
                    .running_alt => state.* = .running,
                    else => unreachable,
                },
                linux.SIG.SEGV => {
                    state.* = .segfaulted;
                    break;
                },
                linux.SIG.CHLD => {
                    state.* = .unknown;
                    break;
                },
                // linux.SIG.ABRT => break,
                else => std.debug.print("Unhandled SIG: {}\n", .{sig}),
            },
            else => std.debug.print("{?}\n", .{status}),
        }

        //const start_code = start_addresses.getPtr(ret.pid).?;

        try std.posix.ptrace(linux.PTRACE.GETREGS, ret.pid, 0, @intFromPtr(&regs));
        const count = visited.get(regs.rip) orelse 0;
        try visited.put(regs.rip, count + 1);

        if (state.* == .running) {
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
    //std.debug.print("State: {}\n", .{state});

    {
        std.debug.print("Tracees statuses:\n", .{});
        var it = tracees.valueIterator();
        while (it.next()) |value| {
            std.debug.print("\t{?}\n", .{value});
        }
    }

    {
        var it = visited.iterator();
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

