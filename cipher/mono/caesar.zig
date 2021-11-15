const std = @import("std");
const cipher = @import("../../cipher.zig");

// TODO implement safe varients

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

fn detectSafetyFn(_: []const u8) cipher.Safety {
    // TODO actually implement this
    return .UnsafeAfterStrip;
}

fn encryptFn(text: []const u8, key: u5, _: void, output: []u8) void {
    for (text) |char, idx| {
        output[idx] = (char - 'a' + key) % 26 + 'a';
    }
}

fn decryptFn(text: []const u8, key: u5, _: void, output: []u8) void {
    encryptFn(text, 26 - key, {}, output);
}

pub usingnamespace cipher.Cipher(
    u5,
    dupeFn,
    copyFn,
    freeFn,
    nextFn,
    //
    cipher.VoidContext,
    //
    detectSafetyFn,
    //
    decryptFn,
    encryptFn,
    decryptFn,
    encryptFn,

    .Mono,
);
