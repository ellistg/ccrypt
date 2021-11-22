const std = @import("std");
const ccrypt = @import("ccrypt.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = &arena.allocator;

    const p = "Hello, World! I'm going to encrypt this. :)";

    const _timer = try std.time.Timer.start();
    var _ciphertext = try ccrypt.cipher.caesar.crypt(allocator, .Encrypt, p, 3);
    const _ns = _timer.read();
    allocator.free(_ciphertext);

    var max: usize = _ns;
    var min: usize = _ns;
    var total: usize = 0;

    var i: usize = 0;
    while (i < 1_000_000) : (i += 1) {
        const timer = try std.time.Timer.start();

        var ciphertext = try ccrypt.cipher.caesar.crypt(allocator, .Encrypt, p, 3);

        const ns = timer.read();

        max = if (ns > max) ns else max;
        min = if (ns < max) ns else min;

        allocator.free(ciphertext);

        total += ns;
    }

    std.debug.print("mean : {d}\n", .{total / 1000000});
    std.debug.print("max: {d}\n", .{max});
    std.debug.print("min: {d}\n", .{min});
}
