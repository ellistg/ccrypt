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
    // TODO is it worth checking if it needs stripping or just doing it regardless?
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
    decryptSFn,
    encryptSFn,

    .Mono,
);
