const std = @import("std");
const ccrypt = @import("../ccrypt.zig");

pub fn brute(
    comptime Cipher: type,
) fn (
    ccrypt.analysis.FitFn,
    ccrypt.cipher.Crypt,
    *Cipher.Key,
    usize,
    []align(ccrypt.textAlign) const u8,
    []align(ccrypt.textAlign) u8,
) anyerror!void {
    return struct {
        pub fn brute(
            fitness: ccrypt.analysis.FitFn,
            crypt: ccrypt.cipher.Crypt,
            key: *Cipher.Key,
            num_iter: usize,
            input: []align(ccrypt.textAlign) const u8,
            text_buf: []align(ccrypt.textAlign) u8,
        ) !void {
            const cryptFn = crypt.CryptFn(Cipher);

            cryptFn(input, key.v, text_buf);
            var best_fit: f32 = fitness.fit(text_buf);

            var count: usize = 0;
            while (count <= num_iter) {
                try key.next();
                cryptFn(input, key.v, text_buf);
                const test_fit: f32 = fitness.fit(text_buf);

                if (fitness.cmp(test_fit, best_fit)) {
                    best_fit = test_fit;
                    key.logBest();
                }

                count += 1;
            }
        }
    }.brute;
}
