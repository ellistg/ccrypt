const std = @import("std");
const method = struct {
    pub const brute = @import("method/brute.zig").brute;
};

pub fn Cipher(
    comptime KeyType: type,
    comptime kind_val: Kind,
    comptime dupeFn: fn (*std.mem.Allocator, KeyType) std.mem.Allocator.Error!KeyType,
    comptime copyFn: fn (*KeyType, *KeyType) void,
    comptime freeFn: fn (*std.mem.Allocator, *KeyType) void,
    comptime nextFn_opt: ?fn (*std.mem.Allocator, *KeyType) anyerror!void,
    comptime decryptFn: fn ([]const u8, KeyType, []u8) void,
    comptime encryptFn: fn ([]const u8, KeyType, []u8) void,
) type {
    return struct {
        pub const Key = struct {
            v: KeyType,
            best: KeyType,

            // Not used by every cipher but always stored for simplicity of lib
            allocator: *std.mem.Allocator,

            const KeySelf = @This();

            // Type of key value `v`
            pub const Type = KeyType;

            pub fn init(allocator: *std.mem.Allocator, key: KeyType) std.mem.Allocator.Error!KeySelf {
                return KeySelf{
                    .v = try dupeFn(allocator, key),
                    .best = try dupeFn(allocator, key),
                    .allocator = allocator,
                };
            }

            pub fn deinit(self: *KeySelf) void {
                freeFn(self.allocator, self.v);
                freeFn(self.allocator, self.best);
            }

            pub fn logBest(self: *KeySelf) void {
                copyFn(&self.best, &self.v);
            }

            // If no pointer is provided for nextFn there will be no next function
            // in the key, resulting compile error rather than unresolved bug if
            // a cipher is used in an attack method that requires it.
            pub usingnamespace if (nextFn_opt) |nextFn| struct {
                pub fn next(self: *KeySelf) !void {
                    try nextFn(self.allocator, &self.v);
                }
            } else struct {};
        };

        pub const kind = kind_val;

        pub fn decrypt(text: []const u8, key: KeyType, output: []u8) void {
            return decryptFn(text, key, output);
        }

        pub fn encrypt(text: []const u8, key: KeyType, output: []u8) void {
            return encryptFn(text, key, output);
        }

        const Self = @This();

        pub usingnamespace if (@hasDecl(Key, "next")) struct {
            pub const brute = method.brute(Self);
        } else struct {};
    };
}

pub const Kind = enum { Mono, Trans, Poly, Homo };
pub const Crypt = enum {
    decrypt,
    encrypt,

    pub fn CryptFn(self: Crypt, comptime T: type) fn ([]const u8, T.Key.Type, []u8) void {
        return switch (self) {
            .decrypt => T.decrypt,
            .encrypt => T.encrypt,
        };
    }
};

// Namespace containing all purely monoalphabetic ciphers.
usingnamespace @import("cipher/mono.zig");

test {
    std.testing.refAllDecls(@This());
}
