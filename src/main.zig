const r4os = @import("r4os");

const MAGIC: [4]u8 = .{ 'R', '4', 'S', 'L' };
const VERSION: u8 = 1;
const TYPE_DIAG: u8 = 1;
const HEADER_SIZE: usize = 10;
const MAX_PAYLOAD: usize = 256;
const MAX_FRAME: usize = HEADER_SIZE + MAX_PAYLOAD;

const RuntimeState = struct {
    summary: r4os.abi.R4slSummary = .{},
    rx_buf: [MAX_FRAME]u8 = .{0} ** MAX_FRAME,
    rx_len: usize = 0,
    rx_expected: usize = 0,
};

var api_addr: usize = 1;
var state_addr: usize = 1;

comptime {
    asm (r4os.r4dev.protocolEntriesAsm("netr4sl_init", "netr4sl_shutdown", "netr4sl_query", "netr4sl_dispatch"));
}

export fn netr4sl_init(api: *const r4os.r4dev.ProtocolApi) callconv(.c) i32 {
    var ctx = r4os.r4dev.ProtocolContext.init(api);
    api_addr = @intFromPtr(api);
    const memory = ctx.alloc(@sizeOf(RuntimeState), @alignOf(RuntimeState)) orelse {
        ctx.logError("NETR4SL.R4P state allocation failed");
        return -1;
    };
    state_addr = @intFromPtr(memory);
    reset();
    ctx.logInfo("NETR4SL.R4P init");
    _ = ctx.registerRole("net.serial_link", .net, 0);
    _ = ctx.setStatus(.active, "R4SL R4P active");
    return 0;
}

export fn netr4sl_shutdown() callconv(.c) i32 {
    if (context()) |ctx| {
        if (state_addr > 1) ctx.free(@ptrFromInt(state_addr), @sizeOf(RuntimeState));
    }
    state_addr = 1;
    api_addr = 1;
    return 0;
}

export fn netr4sl_query(out: *r4os.abi.ProtocolStatus) callconv(.c) i32 {
    out.* = .{
        .state = @intFromEnum(r4os.abi.ProtocolState.active),
        .flags = 0,
        .last_error = 0,
        .reserved = 0,
        .note = note("R4SL R4P ready"),
    };
    return 0;
}

export fn netr4sl_dispatch(op: u32, in_buffer: *const r4os.abi.ProtocolBuffer, out_buffer: *r4os.abi.ProtocolBuffer) callconv(.c) i32 {
    _ = out_buffer;
    const request = requestFromBuffer(in_buffer) orelse return -2;
    switch (op) {
        r4os.abi.r4sl_op_build_frame => buildFrameOp(request),
        r4os.abi.r4sl_op_parse_bytes => parseBytesOp(request),
        r4os.abi.r4sl_op_reset_parser => resetParserOp(request),
        r4os.abi.r4sl_op_summary => summary(request),
        else => return -4,
    }
    return request.result;
}

fn reset() void {
    const s = state() orelse return;
    s.* = .{};
}

fn context() ?r4os.r4dev.ProtocolContext {
    if (api_addr <= 1) return null;
    return r4os.r4dev.ProtocolContext.init(@ptrFromInt(api_addr));
}

fn state() ?*RuntimeState {
    if (state_addr <= 1) return null;
    return @ptrFromInt(state_addr);
}

fn buildFrameOp(op: *r4os.abi.R4slOp) void {
    const s = state() orelse {
        op.result = r4os.abi.r4sl_result_bad_state;
        return;
    };
    const payload_len: usize = @intCast(op.payload_len);
    const len = buildFrame(op.frame_type, op.payload[0..payload_len], op.frame[0..]) orelse {
        s.summary.bad_length += 1;
        op.result = r4os.abi.r4sl_result_buffer_small;
        return;
    };
    op.frame_len = @intCast(len);
    s.summary.built_frames += 1;
    op.result = r4os.abi.r4sl_result_ok;
}

fn parseBytesOp(op: *r4os.abi.R4slOp) void {
    const input_len: usize = @intCast(op.input_len);
    if (input_len > op.input.len) {
        op.result = r4os.abi.r4sl_result_bad_length;
        return;
    }
    op.completed = 0;
    op.payload_len = 0;
    op.result = r4os.abi.r4sl_result_need_more;
    var i: usize = 0;
    while (i < input_len) : (i += 1) {
        parseByte(op, op.input[i]);
        if (op.result != r4os.abi.r4sl_result_need_more) return;
    }
}

fn resetParserOp(op: *r4os.abi.R4slOp) void {
    resetParser();
    op.result = r4os.abi.r4sl_result_ok;
}

fn summary(op: *r4os.abi.R4slOp) void {
    const s = state() orelse {
        op.result = r4os.abi.r4sl_result_bad_state;
        return;
    };
    op.summary = s.summary;
    op.result = r4os.abi.r4sl_result_ok;
}

fn parseByte(op: *r4os.abi.R4slOp, byte: u8) void {
    const s = state() orelse {
        op.result = r4os.abi.r4sl_result_bad_state;
        return;
    };
    if (s.rx_len >= s.rx_buf.len) {
        s.summary.overflows += 1;
        resetParser();
        op.result = r4os.abi.r4sl_result_overflow;
        return;
    }
    if (s.rx_len == 0 and byte != MAGIC[0]) {
        s.summary.bad_magic += 1;
        op.result = r4os.abi.r4sl_result_bad_magic;
        return;
    }

    s.rx_buf[s.rx_len] = byte;
    s.rx_len += 1;

    if (s.rx_len == MAGIC.len and !magicOk(s.rx_buf[0..MAGIC.len])) {
        s.summary.bad_magic += 1;
        resetParser();
        op.result = r4os.abi.r4sl_result_bad_magic;
        return;
    }

    if (s.rx_len == HEADER_SIZE) {
        if (s.rx_buf[4] != VERSION) {
            s.summary.bad_version += 1;
            resetParser();
            op.result = r4os.abi.r4sl_result_bad_version;
            return;
        }
        const payload_len = readLe16(s.rx_buf[6..8]);
        if (payload_len > MAX_PAYLOAD) {
            s.summary.bad_length += 1;
            resetParser();
            op.result = r4os.abi.r4sl_result_bad_length;
            return;
        }
        s.rx_expected = HEADER_SIZE + payload_len;
    }

    if (s.rx_expected != 0 and s.rx_len == s.rx_expected) {
        finishFrame(op);
    } else {
        op.result = r4os.abi.r4sl_result_need_more;
    }
}

fn finishFrame(op: *r4os.abi.R4slOp) void {
    const s = state() orelse {
        op.result = r4os.abi.r4sl_result_bad_state;
        return;
    };
    const expected_sum = readLe16(s.rx_buf[8..10]);
    const actual_sum = checksum(s.rx_buf[0..s.rx_expected]);
    if (expected_sum != actual_sum) {
        s.summary.checksum_errors += 1;
        resetParser();
        op.result = r4os.abi.r4sl_result_checksum;
        return;
    }
    const payload_len = readLe16(s.rx_buf[6..8]);
    const payload = s.rx_buf[HEADER_SIZE .. HEADER_SIZE + payload_len];
    op.frame_type = s.rx_buf[5];
    op.payload_len = payload_len;
    op.completed = 1;
    if (payload_len != 0) @memcpy(op.payload[0..payload_len], payload);
    s.summary.parsed_frames += 1;
    resetParser();
    op.result = r4os.abi.r4sl_result_ok;
}

fn resetParser() void {
    const s = state() orelse return;
    s.rx_len = 0;
    s.rx_expected = 0;
}

fn buildFrame(frame_type: u8, payload: []const u8, out: []u8) ?usize {
    if (payload.len > MAX_PAYLOAD or out.len < HEADER_SIZE + payload.len) return null;
    out[0] = MAGIC[0];
    out[1] = MAGIC[1];
    out[2] = MAGIC[2];
    out[3] = MAGIC[3];
    out[4] = VERSION;
    out[5] = frame_type;
    writeLe16(out[6..8], @intCast(payload.len));
    out[8] = 0;
    out[9] = 0;
    if (payload.len != 0) @memcpy(out[HEADER_SIZE .. HEADER_SIZE + payload.len], payload);
    writeLe16(out[8..10], checksum(out[0 .. HEADER_SIZE + payload.len]));
    return HEADER_SIZE + payload.len;
}

fn checksum(frame: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i < frame.len) : (i += 1) {
        if (i == 8 or i == 9) continue;
        sum += frame[i];
    }
    return @truncate(sum & 0xFFFF);
}

fn requestFromBuffer(buffer: *const r4os.abi.ProtocolBuffer) ?*r4os.abi.R4slOp {
    if (buffer.data == null) return null;
    if (buffer.len < @sizeOf(r4os.abi.R4slOp)) return null;
    return @ptrCast(@alignCast(buffer.data.?));
}

fn magicOk(data: []const u8) bool {
    if (data.len != MAGIC.len) return false;
    var i: usize = 0;
    while (i < MAGIC.len) : (i += 1) {
        if (data[i] != MAGIC[i]) return false;
    }
    return true;
}

fn readLe16(data: []const u8) u16 {
    return @as(u16, data[0]) | (@as(u16, data[1]) << 8);
}

fn writeLe16(out: []u8, value: u16) void {
    out[0] = @truncate(value & 0x00FF);
    out[1] = @truncate(value >> 8);
}

fn note(comptime text: []const u8) [64]u8 {
    var out: [64]u8 = .{0} ** 64;
    @memcpy(out[0..text.len], text);
    return out;
}
