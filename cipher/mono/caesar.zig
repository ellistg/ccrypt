const std = @import("std");
const cipher = @import("../../cipher.zig");

pub const Context = cipher.VoidContext;
pub const KeyType = u5;

pub const Kind = cipher.Kind{.Mono};

pub fn dupe(_: *std.mem.Allocator, key: KeyType) !KeyType {
    return key;
}

pub fn copy(a: *KeyType, b: *KeyType) !void {
    a.* = b.*;
}

pub fn index(_: *std.mem.Allocator, key: KeyType) !usize {
    return key;
}

pub fn free(_: *std.mem.Allocator, _: *KeyType) void {}

pub fn next(_: *std.mem.Allocator, key: *KeyType, _: *Context) !void {
    if (key.* >= 25) {
        return error.InvalidKey;
    } else {
        key.* += 1;
    }
}

pub fn detectSafety(_: []const u8) cipher.Safety {
    // TODO Implement This
    return .UnsafeAfterStrip;
}

pub fn encrypt(text: []const u8, key: KeyType, _: void, output: []u8) void {
    for (text) |char, idx| {
        output[idx] = ((char & 31) - 1 + key) % 26 + 'a';
    }
}

pub fn decrypt(text: []const u8, key: KeyType, _: void, output: []u8) void {
    encrypt(text, 26 - key, {}, output);
}

pub fn encryptS(text: []const u8, key: KeyType, _: void, output: []u8) void {
    for (text) |char, idx| {
        if (std.ascii.isAlpha(char)) {
            output[idx] = ((char & 31) - 1 + key) % 26 + 'a';
        } else {
            output[idx] = char;
        }
    }
}

pub fn decryptS(text: []const u8, key: KeyType, _: void, output: []u8) void {
    encryptS(text, 26 - key, {}, output);
}
