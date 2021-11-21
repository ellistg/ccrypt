const std = @import("std");
const analysis = @import("analysis.zig");

const method = struct {
    pub const brute = @import("method/brute.zig").brute;
};

/// Comptime interface to generate the type for each cipher.
pub fn Cipher(
    comptime Context: type,
    //
    comptime KeyType: type,
    comptime dupeFn: fn (*std.mem.Allocator, KeyType) anyerror!KeyType,
    comptime copyFn: fn (*KeyType, *KeyType) anyerror!void,
    comptime idxFn: fn (*std.mem.Allocator, KeyType) anyerror!usize,
    comptime freeFn: fn (*std.mem.Allocator, *KeyType) void,
    comptime nextFn_opt: ?fn (*std.mem.Allocator, *KeyType, *Context) anyerror!void,
    //
    comptime detectSafetyFn: fn ([]const u8) Safety,
    //
    comptime decrypt: fn ([]const u8, KeyType, Context.Type, []u8) void,
    comptime encrypt: fn ([]const u8, KeyType, Context.Type, []u8) void,
    comptime decryptS: fn ([]const u8, KeyType, Context.Type, []u8) void,
    comptime encryptS: fn ([]const u8, KeyType, Context.Type, []u8) void,
    //
    comptime kind_val: Kind,
) type {
    return struct {
        pub const Key = struct {
            pub const Type = KeyType;

            pub fn idx(allocator: *std.mem.Allocator, key: KeyType) !usize {
                return idxFn(allocator, key);
            }

            /// Copy passed value to `v` - may cause allocations.
            pub fn copy(a: *KeyType, b: *KeyType) !void {
                try copyFn(a, b);
            }

            /// All data and functions needed to decode/encode a 
            /// ciphertext/plaintext. This type should be used as the test key
            /// for any method.
            pub const Full = struct {
                v: KeyType,
                context: Context,

                text: []align(textAlign) const u8,
                buf: []align(textAlign) u8,
                freeText: bool, // If true `text` must be freed on `deinit`

                cryptFn: fn ([]const u8, KeyType, Context.Type, []u8) void,
                fit: analysis.Fitness,

                // Not used by every cipher but always stored for simplicity of lib
                allocator: *std.mem.Allocator,

                const Self = @This();

                /// Initialize a Full Key, providing all data it could need.
                /// This is stored so that in code optimisatoins may be applied.
                pub fn init(
                    allocator: *std.mem.Allocator,
                    fit: *analysis.Fitness,
                    cryptE: Crypt,
                    key: KeyType,
                    text: []align(textAlign) const u8,
                ) std.mem.Allocator.Error!Self {
                    const safety = detectSafetyFn(text);

                    if (safety != .Safe) {
                        fit.*.safe(false);
                    }

                    var textF = text;
                    var free = false;

                    if (safety == .UnsafeAfterStrip) {
                        var t = std.ArrayListAligned(u8, textAlign).init(allocator);
                        errdefer t.deinit();

                        for (text) |c| {
                            if (std.ascii.isAlpha(c)) {
                                try t.append((c & 31) - 1 + 'a');
                            }
                        }
                        textF = t.items;
                        free = true;
                    }

                    var buf = try allocator.alignedAlloc(u8, textAlign, textF.len);
                    errdefer allocator.free(buf);

                    const cryptFn = switch (safety) {
                        .Safe => switch (cryptE) {
                            .Encrypt => encryptS,
                            .Decrypt => decryptS,
                        },
                        .Unsafe, .UnsafeAfterStrip => switch (cryptE) {
                            .Encrypt => encrypt,
                            .Decrypt => decrypt,
                        },
                    };

                    return Self{
                        .v = try dupeFn(allocator, key),
                        .context = Context.init(key, text),
                        .text = textF,
                        .buf = buf,
                        .freeText = free,
                        .fit = fit.*,
                        .cryptFn = cryptFn,
                        .allocator = allocator,
                    };
                }

                /// Release all data stored by the Full Key.
                pub fn deinit(self: *Self) void {
                    freeFn(self.allocator, &self.v);
                    self.allocator.free(self.buf);
                    if (self.freeText) self.allocator.free(self.text);
                }

                /// [En|De]crypt the text using the current key value.
                pub fn crypt(self: *Self) void {
                    self.cryptFn(self.text, self.v, self.context.v, self.buf);
                }

                // If no pointer is provided for nextFn there will be no next function
                // in the key, resulting compile error rather than unresolved bug if
                // a cipher is used in an attack method that requires it.
                pub usingnamespace if (nextFn_opt) |nextFn| struct {
                    /// Transform `v` to be the next key in the sequence.
                    /// For integer keys this will go 1,2,3,... 
                    /// However, some will have more complex patterns.
                    pub fn next(self: *Self) !void {
                        try nextFn(self.allocator, &self.v, &self.context);
                    }
                } else struct {};
            };

            /// Key data needed to describe the final result of an attack, used 
            /// as return type by all methods.
            pub const Basic = struct {
                v: KeyType,
                context: Context,

                // Not used by every cipher but always stored for simplicity of lib
                allocator: *std.mem.Allocator,

                const Self = @This();

                /// [En|De]crypt the text using the current key value.
                pub fn init(
                    allocator: *std.mem.Allocator,
                    key: KeyType,
                    text: []const u8,
                ) std.mem.Allocator.Error!Self {
                    return Self{
                        .v = try dupeFn(allocator, key),
                        .context = Context.init(key, text),
                        .allocator = allocator,
                    };
                }

                /// Release all data stored by the Full Key.
                pub fn deinit(self: *Self) void {
                    freeFn(self.allocator, &self.v);
                }
            };
        };

        // Would be self however that would create shadow of `Self` in
        // `Key.Full` and `Key.Basic`.
        const CipherImpl = @This();

        pub const kind = kind_val;

        /// Easily [en|de]crypts data passed in, does not generate key and 
        /// always runs methods in safe mode.
        pub fn crypt(
            allocator: *std.mem.Allocator,
            cryptE: Crypt,
            text: []const u8,
            key: KeyType,
        ) ![]u8 {
            const cryptFn = switch (cryptE) {
                .Encrypt => encryptS,
                .Decrypt => decryptS,
            };

            const buf = try allocator.alloc(u8, text.len);
            var context = Context.init(key, text);
            cryptFn(text, key, context.v, buf);

            return buf;
        }

        // Determines if `Key.Full` has the methods needed to run a brute force.
        pub usingnamespace if (@hasDecl(Key.Full, "next")) struct {
            /// Brute forces every key within range specified when calling.
            pub const brute = method.brute(CipherImpl);
        } else struct {};
    };
}

/// Alignment to use 512-bit vectors in order to make best use of modern CPUs (eg. AVX-512)
pub const textAlign = @alignOf(std.meta.Vector(512 / 8, u8));

/// Context to use in `Cipher` if one isn't needed.
pub const VoidContext = struct {
    v: void = {},

    const Type = void;
    const Self = @This();

    pub fn init(_: anytype, _: []const u8) Self {
        return VoidContext{};
    }
};

/// Describes the category of cipher that is generated by `Cipher`.
pub const Kind = enum { Mono, Trans, Poly, Homo };

/// Used as input for functions to determine whether text is meant to be
/// encrypted or decrypted. 
/// Used instead of bool to improve readability when using this library.
pub const Crypt = enum { Decrypt, Encrypt };

/// Determines how an decrypt methods and fitness functions should be 
/// used.
pub const Safety = enum {
    Safe, // crypt and fitness functions should work on any input
    Unsafe, // crypt and fitness functions work on lowercase alphabetic input
    // crypt and fitness functions work on lowercase alphabetic input after sanitisation
    UnsafeAfterStrip,
};

// Namespace containing all purely monoalphabetic ciphers.
usingnamespace @import("cipher/mono.zig");
usingnamespace @import("cipher/trans.zig");

test {
    std.testing.refAllDecls(@This());
}
