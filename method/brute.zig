const std = @import("std");

const cipher = @import("../cipher.zig");
const analysis = @import("../analysis.zig");

pub fn brute(
    comptime Cipher: type,
) fn (
    *std.mem.Allocator,
    *analysis.Fitness,
    cipher.Crypt,
    []align(cipher.textAlign) const u8,
    Cipher.Key.Type,
    usize,
) anyerror!Cipher.Key.Basic {
    return struct {
        pub fn brute(
            allocator: *std.mem.Allocator,
            fit: *analysis.Fitness,
            crypt: cipher.Crypt,
            text: []align(cipher.textAlign) const u8,
            start_key: Cipher.Key.Type,
            num_iter: usize,
        ) !Cipher.Key.Basic {
            var key = try Cipher.Key.Full.init(allocator, fit, crypt, start_key, text);
            defer key.deinit();

            var best = try Cipher.Key.Basic.init(allocator, start_key, text);
            errdefer best.deinit();

            var best_fit: f32 = key.fit.calc(text);

            var count: usize = 0;
            while (count < num_iter) {
                try key.next();

                key.crypt();
                const test_fit: f32 = key.fit.calc(key.buf);

                if (key.fit.cmp(test_fit, best_fit)) {
                    best_fit = test_fit;
                    try Cipher.Key.copy(&best.v, &key.v);
                }

                count += 1;
            }

            return best;
        }
    }.brute;
}
