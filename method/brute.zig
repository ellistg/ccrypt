const std = @import("std");
const ccrypt = @import("../ccrypt.zig");

pub fn brute(
    comptime Cipher: type,
) fn (
    *std.mem.Allocator,
    *ccrypt.analysis.Fitness,
    ccrypt.cipher.Crypt,
    []align(ccrypt.textAlign) const u8,
    Cipher.Key.Type,
    usize,
) anyerror!Cipher.Key.Basic {
    return struct {
        pub fn brute(
            allocator: *std.mem.Allocator,
            fitness: *ccrypt.analysis.Fitness,
            crypt: ccrypt.cipher.Crypt,
            text: []align(ccrypt.textAlign) const u8,
            start_key: Cipher.Key.Type,
            num_iter: usize,
        ) !Cipher.Key.Basic {
            var key = try Cipher.Key.Full.init(allocator, fitness, crypt, start_key, text);
            defer key.deinit();

            var best = try Cipher.Key.Basic.init(allocator, start_key, text);
            errdefer best.deinit();

            var best_fit: f32 = key.fitness.calc(text);

            var count: usize = 0;
            while (count <= num_iter) {
                try key.next();

                key.crypt();
                const test_fit: f32 = key.bufFit();

                if (key.fitness.cmp(test_fit, best_fit)) {
                    best_fit = test_fit;
                    best.log(&key.v);
                }

                count += 1;
            }

            return best;
        }
    }.brute;
}
