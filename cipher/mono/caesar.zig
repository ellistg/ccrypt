const std = @import("std");
const cipher = @import("../../cipher.zig");

const Context = cipher.VoidContext;

fn dupeFn(_: *std.mem.Allocator, key: u5) !u5 {
    return key;
}

fn copyFn(a: *u5, b: *u5) !void {
    a.* = b.*;
}

fn idxFn(_: *std.mem.Allocator, key: u5) !usize {
    return key;
}

fn freeFn(_: *std.mem.Allocator, _: *u5) void {}

fn nextFn(_: *std.mem.Allocator, key: *u5, _: *Context) !void {
    if (key.* >= 25) {
        return error.InvalidKey;
    } else {
        key.* += 1;
    }
}

// always strips text, will check if this causes significant performance impact.
fn detectSafetyFn(_: []const u8) cipher.Safety {
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

fn encryptSFn(text: []const u8, key: u5, _: void, output: []u8) void {
    for (text) |char, idx| {
        if (std.ascii.isAlpha(char)) {
            if (std.ascii.isLower(char)) {
                output[idx] = (char - 'a' + key) % 26 + 'a';
            } else {
                output[idx] = (char - 'A' + key) % 26 + 'A';
            }
        } else {
            output[idx] = char;
        }
    }
}

fn decryptSFn(text: []const u8, key: u5, _: void, output: []u8) void {
    encryptSFn(text, 26 - key, {}, output);
}

pub usingnamespace cipher.Cipher(
    Context,
    //
    u5,
    dupeFn,
    copyFn,
    idxFn,
    freeFn,
    nextFn,
    //
    detectSafetyFn,
    //
    decryptFn,
    encryptFn,
    decryptSFn,
    encryptSFn,
    //
    .Mono,
);
