const std = @import("std");

const bigrams = @import("analysis/bigrams.zig").bigram_log_freq;
const quadgrams = @import("analysis/quadgrams.zig").quadgram_log_freq;

pub const FitFn = struct {
    step: usize = 1,
    fitFn: fn ([]const u8, usize) f32,
    cmpFn: fn (f32, f32) bool,

    const Self = @This();
    pub fn fit(self: *const Self, text: []const u8) f32 {
        return self.fitFn(text, self.step);
    }

    pub fn cmp(self: *const Self, a: f32, b: f32) bool {
        return self.cmpFn(a, b);
    }
};

pub fn greaterThan(a: f32, b: f32) bool {
    return if (a > b) true else false;
}

pub fn lessThan(a: f32, b: f32) bool {
    return if (a < b) true else false;
}

pub fn CloserTo(comptime x: f32) fn (f32, f32) bool {
    return struct {
        fn ct(a: f32, b: f32) bool {
            const da = @fabs(x - a);
            const db = @fabs(x - b);
            return if (da < db) true else false;
        }
    }.ct;
}

/// English letter frequencies - data supplied by practical cryptography
/// http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/
const mono_freq = std.meta.Vector(26, f32){
    0.0855, 0.0160, 0.0316, 0.0387, 0.1210, 0.0218, 0.0209, 0.0496, 0.0733, 0.0022, 0.0081, 0.0421,
    0.0253, 0.0717, 0.0747, 0.0207, 0.0010, 0.0633, 0.0673, 0.0894, 0.0268, 0.0106, 0.0183, 0.0019,
    0.0172, 0.0011,
};

/// Generates count of each lowercase alphabetic character in a string
/// Input must consist of only lowercase alphabetic characters or the function will crash
/// The items in the returned array are alphabetically ordered; 0 -> a, 1 -> b, ...
fn getAlphCounts(text: []const u8, step: usize) [26]f32 {
    var alph_counts = std.mem.zeroes([26]f32);
    var i: usize = 0;
    while (i < text.len) : (i += step) {
        const alpha = text[i] - 'a';
        alph_counts[alpha] += 1;
    }

    return alph_counts;
}

test "alph counts" {
    const s = try std.testing.allocator.dupe(u8, "abbcyyzaa");
    defer std.testing.allocator.free(s);

    const alph_counts = getAlphCounts(s, 1);

    // Check all values known to be non-zero
    try std.testing.expect(alph_counts[0] == 3);
    try std.testing.expect(alph_counts[1] == 2);
    try std.testing.expect(alph_counts[2] == 1);
    try std.testing.expect(alph_counts[24] == 2);
    try std.testing.expect(alph_counts[25] == 1);

    // Check all other values are 0
    for (alph_counts[4..24]) |count| {
        try std.testing.expect(count == 0);
    }
}

/// Generates count of any characters that could be in a text.
/// uppercase and lowercase of the same character will be counted seperately
fn getCharCounts(text: []const u8, step: usize) [255]f32 {
    var char_counts = std.mem.zeroes([255]f32);
    var i: usize = 0;
    while (i < text.len) : (i += step) {
        char_counts[text[i]] += 1;
    }

    return char_counts;
}

test "char chounts" {
    const s = try std.testing.allocator.dupe(u8, "AAbyz>>*yy");
    defer std.testing.allocator.free(s);

    var counts = getCharCounts(s, 1);

    // Check all values known to be non-zero
    try std.testing.expect(counts['A'] == 2);
    try std.testing.expect(counts['b'] == 1);
    try std.testing.expect(counts['y'] == 3);
    try std.testing.expect(counts['z'] == 1);
    try std.testing.expect(counts['>'] == 2);
    try std.testing.expect(counts['*'] == 1);

    const non_zero_chars = [6]u8{ 'A', 'b', 'y', 'z', '>', '*' };

    // Check all other u8 values are zero
    var char: u8 = 0;
    while (char < 255) : (char += 1) {
        const is_non_zero: bool = for (non_zero_chars) |check_char| {
            if (check_char == char) break true;
        } else false;
        if (!is_non_zero) try std.testing.expect(counts[char] == 0);
    }
}

/// Calculates the Chi-Squared statistic against the English Distribution
/// Requires that input is sanitised meaning it only contains lowercase alphabetic characters
fn chiSquaredFn(text: []const u8, step: usize) f32 {
    const count: std.meta.Vector(26, f32) = getAlphCounts(text, step);
    const expected = mono_freq * @splat(26, @intToFloat(f32, text.len));
    const delta = count - expected;
    const fitness = @reduce(.Add, delta * delta / expected);
    return fitness;
}

pub fn chiSquared(step: usize) FitFn {
    return FitFn{
        .step = step,
        .fitFn = chiSquaredFn,
        .cmpFn = lessThan,
    };
}

test "chi-squared" {
    const s_eng = try std.testing.allocator.dupe(u8, "defendtheeastwallofthecastle");
    defer std.testing.allocator.free(s_eng);

    const s_not = try std.testing.allocator.dupe(u8, "kaldfjalksdfjasldkfasdfasdfb");
    defer std.testing.allocator.free(s_not);

    const fit_eng = chiSquared(1).fit(s_eng);
    const fit_not = chiSquared(1).fit(s_not);

    // Check s_eng is within 2 of expected fitness
    try std.testing.expect(@fabs(fit_eng - 18.5) < 2);

    // Check random text (s_not) will have a worse fitness
    try std.testing.expect(fit_eng < fit_not);
}

/// Calculates Index of Coincidence
/// If text contains upper and lowercase letters may give unexpected 
/// result as will take them to be different characters
fn iocFn(text: []const u8, step: usize) f32 {
    const count: std.meta.Vector(255, f32) = getCharCounts(text, step);
    const count_dec = count - @splat(255, @as(f32, 1));
    const fitness = @reduce(.Add, count * count_dec) / @intToFloat(f32, text.len * (text.len - 1));
    return fitness;
}

pub fn ioc(step: usize) FitFn {
    return FitFn{
        .step = step,
        .fitFn = iocFn,
        .cmpFn = CloserTo(0.066),
    };
}

test "index of coincidence" {
    const allocator = std.testing.allocator;
    const s = try allocator.dupe(u8, "defendtheeastwallofthecastle");
    defer allocator.free(s);

    const fit = ioc(1).fit(s);

    // The tolerance for ioc is usually 0.01 but as the text is very short had to increase
    // This gives a less accurate test but should be fine
    try std.testing.expect(@fabs(fit - 0.066) < 0.05);
}

// NGram Fitness Algorithms
// Instead of using a HashMap the ideal HashFunction is used with base26 numbers and an arry
// By this, what is meant is for bigram fitness is as follows:
//      aa -> 0
//      ab -> 1
//      ba -> 26
//      zz -> 675
// The same will apply for trigram and quadgram fitness
// All three require for the text to be entirely lowercase alphabetic

pub fn biFitFn(text: []const u8, step: usize) f32 {
    var fitness: f32 = 0.0;
    var i: usize = 0;

    const coef = std.meta.Vector(2, u32){ 26, 1 };
    while (i < text.len - 1) : (i += step) {
        const bg8: std.meta.Vector(2, u8) = text[i..][0..2].*;
        const bg: std.meta.Vector(2, u32) = bg8 - @splat(2, @as(u8, 'a'));
        const pos = @reduce(.Add, bg * coef);
        fitness += bigrams[pos];
    }
    return fitness;
}

pub fn biFit(step: usize) FitFn {
    return FitFn{
        .step = step,
        .fitFn = biFitFn,
        .cmpFn = greaterThan,
    };
}

test "bigram fitness" {
    const allocator = std.testing.allocator;

    const s_eng = try allocator.dupe(u8, "defendtheeastwallofthecastle");
    defer allocator.free(s_eng);

    const s_not = try allocator.dupe(u8, "fkasjlfdkjfaksfheoifsfnvakfe");
    defer allocator.free(s_not);

    const fit_eng = biFit(1).fit(s_eng);
    const fit_not = biFit(1).fit(s_not);

    // Check better than random text
    try std.testing.expect(fit_eng > fit_not);

    // Check against arbitrary value close to what it should be
    try std.testing.expect(fit_eng > -75.0);
}

pub fn quadFitFn(text: []const u8, step: usize) f32 {
    var fitness: f32 = 0.0;
    var i: usize = 0;

    const coef = std.meta.Vector(4, u32){ 17576, 676, 26, 1 };
    while (i < text.len - 3) : (i += step) {
        const qg8: std.meta.Vector(4, u8) = text[i..][0..4].*;
        const qg: std.meta.Vector(4, u32) = qg8 - @splat(4, @as(u8, 'a'));
        const pos = @reduce(.Add, qg * coef);
        fitness += quadgrams[pos];
    }
    return fitness;
}

pub fn quadFit(step: usize) FitFn {
    return FitFn{
        .step = step,
        .fitFn = quadFitFn,
        .cmpFn = greaterThan,
    };
}

test "quadgram fitness" {
    const allocator = std.testing.allocator;

    const s_eng = try allocator.dupe(u8, "defendtheeastwallofthecastle");
    defer allocator.free(s_eng);

    const s_not = try allocator.dupe(u8, "fkasjlfdkjfaksfheoifsfnvakfe");
    defer allocator.free(s_not);

    const fit_eng = quadFit(1).fit(s_eng);
    const fit_not = quadFit(1).fit(s_not);

    // Check better than random text
    try std.testing.expect(fit_eng > fit_not);

    // Check against arbitrary value close to what it should be
    try std.testing.expect(fit_eng > -125.0);
}
