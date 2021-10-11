const std = @import("std");

fn nextFn(_: *std.mem.Allocator, key: *u5) !void {
    if (key.* >= 25) {
        return error.InvalidKey;
    } else {
        key.* += 1;
    }
}

fn dupeFn(_: *std.mem.Allocator, key: u5) !u5 {
    return key;
}

fn copyFn(a: *u5, b: *u5) void {
    a.* = b.*;
}

fn freeFn(_: *std.mem.Allocator, _: *u5) void {}

fn encryptFn(text: []const u8, key: u5, output: []u8) void {
    for (text) |char, idx| {
        output[idx] = (char - 'a' + key) % 26 + 'a';
    }
}

fn decryptFn(text: []const u8, key: u5, output: []u8) void {
    encryptFn(text, 26 - key, output);
}

pub usingnamespace @import("../../cipher.zig").Cipher(
    u5,
    .Mono,
    dupeFn,
    copyFn,
    freeFn,
    nextFn,
    decryptFn,
    encryptFn,
);
