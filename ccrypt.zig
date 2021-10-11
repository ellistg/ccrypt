const std = @import("std");

pub const cipher = @import("cipher.zig");
pub const analysis = @import("analysis.zig");

// Use 512-bit vectors in order to make best use of modern CPUs (eg. AVX-512)
const U8V = std.meta.Vector(512 / 8, u8);
pub const textAlign = @alignOf(U8V);

test {
    std.testing.refAllDecls(@This());
}
