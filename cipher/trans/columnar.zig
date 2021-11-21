const std = @import("std");
const cipher = @import("../../cipher.zig");

const KeyType = std.ArrayList(u8);

const Context = struct {
    v: Type,

    pub const Type = struct {
        chunk: usize, // minimum size of a column for a given key length.
        over: usize, // number of clomns with a column length 1 more than chunk.

        text_len: usize,
        key_len: usize,
    };

    pub fn next(self: *Context) void {
        self.v.key_len += 1;

        self.v.chunk = self.v.text_len / self.v.key_len;
        self.v.over = self.v.text_len % self.v.key_len;
    }

    pub fn init(key: KeyType, text: []const u8) Context {
        const key_slice = key.items;
        return Context{ .v = .{ .chunk = text.len / key_slice.len, .over = text.len % key_slice.len, .text_len = text.len, .key_len = key_slice.len } };
    }
};

/// Finds the next lexicographical permutation of the key.
/// If the last permutation for a given length is found the first for the next 
/// length will be returned.
fn nextFn(allocator: *std.mem.Allocator, key: *KeyType, context: *Context) !void {
    var i = key.items.len - 2;

    while (i >= 0) : (i -= 1) {
        if (key.items[i] < key.items[i + 1]) {
            break;
        } else if (i == 0) {
            //  this is executed if the key was the last of that length
            const len = key.items.len + 1;

            var slice = try allocator.alloc(u8, len);
            defer allocator.free(slice);

            var ii: u8 = 0;
            while (ii < len) : (ii += 1) {
                slice[ii] = ii;
            }

            try key.ensureUnusedCapacity(1);
            key.items.len += 1;
            std.mem.copy(u8, key.items, slice);
            context.next();

            return;
        }
    }

    i += 1;

    var j = key.items.len - 1;
    while (key.items[j] <= key.items[i - 1]) : (j -= 1) {}

    std.mem.swap(u8, &key.items[i - 1], &key.items[j]);
    std.mem.reverse(u8, key.items[i..]);
}

fn dupeFn(allocator: *std.mem.Allocator, key: KeyType) !KeyType {
    var new = try KeyType.initCapacity(allocator, key.items.len);
    new.appendSliceAssumeCapacity(key.items);

    return new;
}

fn copyFn(a: *KeyType, b: *KeyType) !void {
    try a.ensureTotalCapacity(b.items.len);
    a.items.len = b.items.len;
    std.mem.copy(u8, a.items, b.items);
}

fn freeFn(_: *std.mem.Allocator, key: *KeyType) void {
    key.deinit();
}

// TODO implement this
fn detectSafetyFn(_: []const u8) cipher.Safety {
    return .Safe;
}

fn encryptFn(text: []const u8, key: KeyType, _: void, output: []u8) void {
    for (text) |char, idx| {
        output[idx] = (char - 'a' + key) % 26 + 'a';
    }
}

fn decrypt(
    text: []const u8,
    key: KeyType,
    context: Context.Type,
    output: []u8,
) void {
    var offset: usize = 0;
    for (key.items) |idx| {
        const this_chunk = context.chunk + @boolToInt(idx < context.over);
        var j: usize = 0;
        while (j < this_chunk) : (j += 1) {
            output[idx + j * key.items.len] = text[offset + j];
        }
        offset += this_chunk;
    }
}

pub usingnamespace cipher.Cipher(
    Context,
    //
    KeyType,
    dupeFn,
    copyFn,
    freeFn,
    nextFn,
    //
    detectSafetyFn,
    //
    decrypt,
    decrypt,
    decrypt,
    decrypt,
    //
    .Trans,
);
