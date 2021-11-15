const std = @import("std");
const ccrypt = @import("ccrypt.zig");

const method = struct {
    pub const brute = @import("method/brute.zig").brute;
};

pub fn Cipher(
    comptime KeyType: type,
    comptime dupeFn: fn (*std.mem.Allocator, KeyType) std.mem.Allocator.Error!KeyType,
    comptime copyFn: fn (*KeyType, *KeyType) void,
    comptime freeFn: fn (*std.mem.Allocator, *KeyType) void,
    comptime nextFn_opt: ?fn (*std.mem.Allocator, *KeyType) anyerror!void,
    //
    comptime Context: type,
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

            pub const Full = struct {
                v: KeyType,
                context: Context,

                text: []align(ccrypt.textAlign) const u8,
                buf: []align(ccrypt.textAlign) u8,
                freeText: bool,

                cryptFn: fn ([]const u8, KeyType, Context.Type, []u8) void,
                fitness: ccrypt.analysis.Fitness,

                // Not used by every cipher but always stored for simplicity of lib
                allocator: *std.mem.Allocator,

                const Self = @This();

                pub fn init(
                    allocator: *std.mem.Allocator,
                    fitness: *ccrypt.analysis.Fitness,
                    cryptE: Crypt,
                    key: KeyType,
                    text: []align(ccrypt.textAlign) const u8,
                ) std.mem.Allocator.Error!Self {
                    const safety = detectSafetyFn(text);

                    if (safety != .Safe) {
                        fitness.*.safe(false);
                    }

                    var textF = text;
                    var free = false;

                    if (safety == .UnsafeAfterStrip) {
                        var t = std.ArrayListAligned(u8, ccrypt.textAlign).init(allocator);
                        errdefer t.deinit();

                        for (text) |c| {
                            if (std.ascii.isAlpha(c)) {
                                try t.append((c & 31) - 1 + 'a');
                            }
                        }
                        textF = t.items;
                        free = true;
                    }

                    var buf = try allocator.alignedAlloc(u8, ccrypt.textAlign, textF.len);

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
                        .context = Context.init(allocator, key, text),
                        .text = textF,
                        .buf = buf,
                        .freeText = free,
                        .fitness = fitness.*,
                        .cryptFn = cryptFn,
                        .allocator = allocator,
                    };
                }

                pub fn deinit(self: *Self) void {
                    freeFn(self.allocator, &self.v);
                    self.context.deinit();
                    if (self.freeText) self.allocator.free(self.text);
                }

                pub fn crypt(self: *Self) void {
                    self.cryptFn(self.text, self.v, self.context.v, self.buf);
                }

                pub fn bufFit(self: *const Self) f32 {
                    return self.fitness.calc(self.buf);
                }

                // If no pointer is provided for nextFn there will be no next function
                // in the key, resulting compile error rather than unresolved bug if
                // a cipher is used in an attack method that requires it.
                pub usingnamespace if (nextFn_opt) |nextFn| struct {
                    pub fn next(self: *Self) !void {
                        try nextFn(self.allocator, &self.v);
                    }
                } else struct {};
            };

            pub const Basic = struct {
                v: KeyType,
                context: Context,

                // Not used by every cipher but always stored for simplicity of lib
                allocator: *std.mem.Allocator,

                const Self = @This();

                pub fn init(
                    allocator: *std.mem.Allocator,
                    key: KeyType,
                    text: []const u8,
                ) std.mem.Allocator.Error!Self {
                    return Self{
                        .v = try dupeFn(allocator, key),
                        .context = Context.init(allocator, key, text),
                        .allocator = allocator,
                    };
                }

                pub fn deinit(self: *Self) void {
                    freeFn(self.allocator, &self.v);
                    self.context.deinit();
                }

                pub fn log(self: *Self, key: *KeyType) void {
                    copyFn(&self.v, key);
                }
            };
        };

        pub const kind = kind_val;
        pub const CipherImpl = @This();

        pub usingnamespace if (@hasDecl(Key.Full, "next")) struct {
            pub const brute = method.brute(CipherImpl);
        } else struct {};
    };
}

pub const VoidContext = struct {
    v: void = {},

    const Type = void;
    const Self = @This();

    pub fn init(_: *std.mem.Allocator, _: anytype, _: []const u8) Self {
        return VoidContext{};
    }

    pub fn deinit(_: *Self) void {}
};

pub const Kind = enum { Mono, Trans, Poly, Homo };
pub const Crypt = enum { Decrypt, Encrypt };
pub const Safety = enum { Safe, Unsafe, UnsafeAfterStrip };

// Namespace containing all purely monoalphabetic ciphers.
usingnamespace @import("cipher/mono.zig");

test {
    std.testing.refAllDecls(@This());
}
