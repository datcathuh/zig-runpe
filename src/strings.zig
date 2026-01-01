const std = @import("std");
const crypto = std.crypto;
const mem = std.mem;

pub fn xorEncrypt(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    const key_length = text.len;
    const key = try allocator.alloc(u8, key_length);
    crypto.random.bytes(key);

    const encrypted = try allocator.alloc(u8, key_length);
    for (text, 0..) |byte, i| {
        encrypted[i] = byte ^ key[i];
    }

    const result = try allocator.alloc(u8, 2 + key_length + key_length);
    result[0] = @truncate(key_length >> 8);
    result[1] = @truncate(key_length & 0xFF);
    @memcpy(result[2 .. 2 + key_length], key);
    @memcpy(result[2 + key_length ..], encrypted);

    allocator.free(key);
    allocator.free(encrypted);

    return result;
}

pub fn xorDecrypt(allocator: std.mem.Allocator, encrypted_data: []const u8) ![]const u8 {
    if (encrypted_data.len < 2) return error.InvalidData;

    const key_length = (@as(usize, encrypted_data[0]) << 8) | encrypted_data[1];

    if (encrypted_data.len != 2 + key_length + key_length) {
        return error.InvalidDataLength;
    }

    const key_start: usize = 2;
    const data_start: usize = 2 + key_length;

    const key = encrypted_data[key_start..data_start];
    const encrypted = encrypted_data[data_start..];

    var decrypted = try allocator.alloc(u8, key_length);
    for (encrypted, 0..) |byte, i| {
        decrypted[i] = byte ^ key[i];
    }

    return decrypted;
}

fn comptimeEncrypt(comptime text: []const u8) [text.len * 2 + 2]u8 {
    @setEvalBranchQuota(100000);

    var result: [text.len * 2 + 2]u8 = undefined;

    result[0] = @truncate(text.len >> 8);
    result[1] = @truncate(text.len & 0xFF);

    for (text, 0..) |byte, i| {
        const key_byte = @as(u8, @truncate(i *% 0x37 + 0xAB));
        result[2 + i] = key_byte;
        result[2 + text.len + i] = byte ^ key_byte;
    }

    return result;
}

pub fn EncryptedString(comptime str: []const u8) type {
    const encrypted_data = comptimeEncrypt(str);

    return struct {
        const data = encrypted_data;

        pub fn get(allocator: std.mem.Allocator) ![]const u8 {
            if (data.len < 2) return error.InvalidData;

            const key_length = (@as(usize, data[0]) << 8) | data[1];

            if (data.len != 2 + key_length + key_length) {
                return error.InvalidDataLength;
            }

            const key_start: usize = 2;
            const data_start: usize = 2 + key_length;

            const key = data[key_start..data_start];
            const encrypted = data[data_start..];

            var decrypted = try allocator.alloc(u8, key_length);
            for (encrypted, 0..) |byte, i| {
                decrypted[i] = byte ^ key[i];
            }

            return decrypted;
        }
    };
}
