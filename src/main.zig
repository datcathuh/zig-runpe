const std = @import("std");
const builtin = @import("builtin");
const string = @import("strings.zig");
const stub = @import("stub.zig");

pub fn main() !void {
    stub.init() catch |err| {
        std.debug.print("Error: {}\n", .{err});
    };
}
