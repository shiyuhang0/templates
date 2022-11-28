// deno-fmt-ignore-file
// deno-lint-ignore-file
// This code was bundled using `deno bundle` and it's not recommended to edit it manually

class ConnnectionError extends Error {
    constructor(msg){
        super(msg);
    }
}
class WriteError extends ConnnectionError {
    constructor(msg){
        super(msg);
    }
}
class ReadError extends ConnnectionError {
    constructor(msg){
        super(msg);
    }
}
class ResponseTimeoutError extends ConnnectionError {
    constructor(msg){
        super(msg);
    }
}
class ProtocolError extends ConnnectionError {
    constructor(msg){
        super(msg);
    }
}
function deferred() {
    let methods;
    let state = "pending";
    const promise = new Promise((resolve, reject)=>{
        methods = {
            async resolve (value) {
                await value;
                state = "fulfilled";
                resolve(value);
            },
            reject (reason) {
                state = "rejected";
                reject(reason);
            }
        };
    });
    Object.defineProperty(promise, "state", {
        get: ()=>state
    });
    return Object.assign(promise, methods);
}
const noColor = globalThis.Deno?.noColor ?? true;
let enabled = !noColor;
function code(open, close) {
    return {
        open: `\x1b[${open.join(";")}m`,
        close: `\x1b[${close}m`,
        regexp: new RegExp(`\\x1b\\[${close}m`, "g")
    };
}
function run(str, code) {
    return enabled ? `${code.open}${str.replace(code.regexp, code.open)}${code.close}` : str;
}
function green(str) {
    return run(str, code([
        32
    ], 39));
}
new RegExp([
    "[\\u001B\\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?\\u0007)",
    "(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~]))",
].join("|"), "g");
function format(data) {
    const bytes = new Uint8Array(data.buffer);
    let out = "         +-------------------------------------------------+\n";
    out += `         |${green("  0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f ")}|\n`;
    out += "+--------+-------------------------------------------------+----------------+\n";
    const lineCount = Math.ceil(bytes.length / 16);
    for(let line = 0; line < lineCount; line++){
        const start = line * 16;
        const addr = start.toString(16).padStart(8, "0");
        const lineBytes = bytes.slice(start, start + 16);
        out += `|${green(addr)}| `;
        lineBytes.forEach((__byte)=>out += __byte.toString(16).padStart(2, "0") + " ");
        if (lineBytes.length < 16) {
            out += "   ".repeat(16 - lineBytes.length);
        }
        out += "|";
        lineBytes.forEach(function(__byte) {
            return out += __byte > 31 && __byte < 127 ? green(String.fromCharCode(__byte)) : ".";
        });
        if (lineBytes.length < 16) {
            out += " ".repeat(16 - lineBytes.length);
        }
        out += "|\n";
    }
    out += "+--------+-------------------------------------------------+----------------+";
    return out;
}
const base64abc = [
    "A",
    "B",
    "C",
    "D",
    "E",
    "F",
    "G",
    "H",
    "I",
    "J",
    "K",
    "L",
    "M",
    "N",
    "O",
    "P",
    "Q",
    "R",
    "S",
    "T",
    "U",
    "V",
    "W",
    "X",
    "Y",
    "Z",
    "a",
    "b",
    "c",
    "d",
    "e",
    "f",
    "g",
    "h",
    "i",
    "j",
    "k",
    "l",
    "m",
    "n",
    "o",
    "p",
    "q",
    "r",
    "s",
    "t",
    "u",
    "v",
    "w",
    "x",
    "y",
    "z",
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "+",
    "/"
];
function encode(data) {
    const uint8 = typeof data === "string" ? new TextEncoder().encode(data) : data instanceof Uint8Array ? data : new Uint8Array(data);
    let result = "", i;
    const l = uint8.length;
    for(i = 2; i < l; i += 3){
        result += base64abc[uint8[i - 2] >> 2];
        result += base64abc[(uint8[i - 2] & 0x03) << 4 | uint8[i - 1] >> 4];
        result += base64abc[(uint8[i - 1] & 0x0f) << 2 | uint8[i] >> 6];
        result += base64abc[uint8[i] & 0x3f];
    }
    if (i === l + 1) {
        result += base64abc[uint8[i - 2] >> 2];
        result += base64abc[(uint8[i - 2] & 0x03) << 4];
        result += "==";
    }
    if (i === l) {
        result += base64abc[uint8[i - 2] >> 2];
        result += base64abc[(uint8[i - 2] & 0x03) << 4 | uint8[i - 1] >> 4];
        result += base64abc[(uint8[i - 1] & 0x0f) << 2];
        result += "=";
    }
    return result;
}
function decode(b64) {
    const binString = atob(b64);
    const size = binString.length;
    const bytes = new Uint8Array(size);
    for(let i = 0; i < size; i++){
        bytes[i] = binString.charCodeAt(i);
    }
    return bytes;
}
let cachedTextDecoder = new TextDecoder("utf-8", {
    ignoreBOM: true,
    fatal: true
});
cachedTextDecoder.decode();
let cachegetUint8Memory0 = null;
function getUint8Memory0() {
    if (cachegetUint8Memory0 === null || cachegetUint8Memory0.buffer !== wasm.memory.buffer) {
        cachegetUint8Memory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachegetUint8Memory0;
}
function getStringFromWasm0(ptr, len) {
    return cachedTextDecoder.decode(getUint8Memory0().subarray(ptr, ptr + len));
}
const heap = new Array(32).fill(undefined);
heap.push(undefined, null, true, false);
let heap_next = heap.length;
function addHeapObject(obj) {
    if (heap_next === heap.length) heap.push(heap.length + 1);
    const idx = heap_next;
    heap_next = heap[idx];
    heap[idx] = obj;
    return idx;
}
function getObject(idx) {
    return heap[idx];
}
function dropObject(idx) {
    if (idx < 36) return;
    heap[idx] = heap_next;
    heap_next = idx;
}
function takeObject(idx) {
    const ret = getObject(idx);
    dropObject(idx);
    return ret;
}
let WASM_VECTOR_LEN = 0;
let cachedTextEncoder = new TextEncoder("utf-8");
const encodeString = function(arg, view) {
    return cachedTextEncoder.encodeInto(arg, view);
};
function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length);
        getUint8Memory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }
    let len = arg.length;
    let ptr1 = malloc(len);
    const mem = getUint8Memory0();
    let offset = 0;
    for(; offset < len; offset++){
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr1 + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr1 = realloc(ptr1, len, len = offset + arg.length * 3);
        const view = getUint8Memory0().subarray(ptr1 + offset, ptr1 + len);
        const ret = encodeString(arg, view);
        offset += ret.written;
    }
    WASM_VECTOR_LEN = offset;
    return ptr1;
}
function create_hash(algorithm) {
    var ptr0 = passStringToWasm0(algorithm, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    var len0 = WASM_VECTOR_LEN;
    var ret = wasm.create_hash(ptr0, len0);
    return DenoHash.__wrap(ret);
}
function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
    return instance.ptr;
}
function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1);
    getUint8Memory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}
function update_hash(hash, data) {
    _assertClass(hash, DenoHash);
    var ptr0 = passArray8ToWasm0(data, wasm.__wbindgen_malloc);
    var len0 = WASM_VECTOR_LEN;
    wasm.update_hash(hash.ptr, ptr0, len0);
}
let cachegetInt32Memory0 = null;
function getInt32Memory0() {
    if (cachegetInt32Memory0 === null || cachegetInt32Memory0.buffer !== wasm.memory.buffer) {
        cachegetInt32Memory0 = new Int32Array(wasm.memory.buffer);
    }
    return cachegetInt32Memory0;
}
function getArrayU8FromWasm0(ptr, len) {
    return getUint8Memory0().subarray(ptr / 1, ptr / 1 + len);
}
function digest_hash(hash) {
    try {
        const retptr = wasm.__wbindgen_add_to_stack_pointer(-16);
        _assertClass(hash, DenoHash);
        wasm.digest_hash(retptr, hash.ptr);
        var r0 = getInt32Memory0()[retptr / 4 + 0];
        var r1 = getInt32Memory0()[retptr / 4 + 1];
        var v0 = getArrayU8FromWasm0(r0, r1).slice();
        wasm.__wbindgen_free(r0, r1 * 1);
        return v0;
    } finally{
        wasm.__wbindgen_add_to_stack_pointer(16);
    }
}
const DenoHashFinalization = new FinalizationRegistry((ptr)=>wasm.__wbg_denohash_free(ptr));
class DenoHash {
    static __wrap(ptr) {
        const obj = Object.create(DenoHash.prototype);
        obj.ptr = ptr;
        DenoHashFinalization.register(obj, obj.ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.ptr;
        this.ptr = 0;
        DenoHashFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_denohash_free(ptr);
    }
}
const imports = {
    __wbindgen_placeholder__: {
        __wbindgen_string_new: function(arg0, arg1) {
            var ret = getStringFromWasm0(arg0, arg1);
            return addHeapObject(ret);
        },
        __wbindgen_throw: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbindgen_rethrow: function(arg0) {
            throw takeObject(arg0);
        }
    }
};
const wasmModule = new WebAssembly.Module(decode("AGFzbQEAAAAB64CAgAAQYAAAYAF/AGABfwF/YAF/AX5gAn9/AGACf38Bf2ADf39/AGADf39/AX9gBH\
9/f38Bf2AFf39/f38AYAV/f39/fwF/YAZ/f39/f38Bf2AFf39/fn8AYAd/f39+f39/AX9gAn9+AGAC\
fn8BfwKMgYCAAAMYX193YmluZGdlbl9wbGFjZWhvbGRlcl9fFV9fd2JpbmRnZW5fc3RyaW5nX25ldw\
AFGF9fd2JpbmRnZW5fcGxhY2Vob2xkZXJfXxBfX3diaW5kZ2VuX3Rocm93AAQYX193YmluZGdlbl9w\
bGFjZWhvbGRlcl9fEl9fd2JpbmRnZW5fcmV0aHJvdwABA8aBgIAAxAEGBgQEBQYCDAYEBA0BBAQEAQ\
cFBA4EBAQHCgQEBAQLBAQEBAQEBAQEBAQEBAQEAQQEBAQEBAQHBQQEBAYGBgYEBAQEBA8BBAQEBAEE\
BgYGBgYEBAQEBAQEBgQEBgQEBAYEBAQEBAQEBAQGBAQEBAQEBAQEBgQEBAQEBAQECQUFAQEGBgYGBg\
QBAAUEBwcBBggBBgEBBwEBAQQBBwIBAQcBBQUCBQUGBAAFAQEBAQIAAAUEAQMCAgICAgICAgICAgIC\
AAQBBIWAgIAAAXABcXEFg4CAgAABABEGiYCAgAABfwFBgIDAAAsHroGAgAAJBm1lbW9yeQIAE19fd2\
JnX2Rlbm9oYXNoX2ZyZWUAkAELY3JlYXRlX2hhc2gABwt1cGRhdGVfaGFzaACRAQtkaWdlc3RfaGFz\
aACNARFfX3diaW5kZ2VuX21hbGxvYwCeARJfX3diaW5kZ2VuX3JlYWxsb2MAoQEfX193YmluZGdlbl\
9hZGRfdG9fc3RhY2tfcG9pbnRlcgCwAQ9fX3diaW5kZ2VuX2ZyZWUAqQEJnoGAgAABAEEBC3CnAcUB\
qwGmAbMBxgFbGGFNwQE4UVVpnwG9AXVQVGh0UjxXmgG/AWtTHzCTAcABTmI7VpkBal4vRJYBvAFzLT\
KVAbsBck8ZJYMBwgFdGiqCAcMBXD9GQqwBuAF6QTc0rgG3AX0+JyOtAbkBd0ArKa8BugF5RUN8NjN4\
JiR7LCh+ogELIjWKAb4BHo4BOowBpAGAAYEBtgGjAQrs84aAAMQBkVoCAX8ifiMAQYABayIDJAAgA0\
EAQYABEJ0BIQMgACkDOCEEIAApAzAhBSAAKQMoIQYgACkDICEHIAApAxghCCAAKQMQIQkgACkDCCEK\
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\
CnZzaiAeaiAiICVqIhsgAiAhc3EgIXNqIBtBGncgG0EVd3MgG0EHd3NqQfLxxbN8aiIeaiELIBwgCm\
ohCiAjIAlqIQkgICAIaiEIIB0gB2ogHmohByAbIAZqIQYgAiAFaiEFICEgBGohBCABQcAAaiIBIAxH\
DQALCyAAIAQ2AhwgACAFNgIYIAAgBjYCFCAAIAc2AhAgACAINgIMIAAgCTYCCCAAIAo2AgQgACALNg\
IAC4ouASJ/IwBBwABrIgJBGGoiA0IANwMAIAJBIGoiBEIANwMAIAJBOGoiBUIANwMAIAJBMGoiBkIA\
NwMAIAJBKGoiB0IANwMAIAJBCGoiCCABKQAINwMAIAJBEGoiCSABKQAQNwMAIAMgASgAGCIKNgIAIA\
QgASgAICIDNgIAIAIgASkAADcDACACIAEoABwiBDYCHCACIAEoACQiCzYCJCAHIAEoACgiDDYCACAC\
IAEoACwiBzYCLCAGIAEoADAiDTYCACACIAEoADQiBjYCNCAFIAEoADgiDjYCACACIAEoADwiATYCPC\
AAIA4gAyABIAsgAigCACIFIAkoAgAiCSAFIAcgAigCDCIPIAIoAgQiECABIAUgASAMIAIoAhQiAiAF\
IAAoAggiESAAKAIEIhJzIAAoAgwiE3MgACgCACIUampBC3cgACgCECIVaiIWQQp3IhdqIA8gEUEKdy\
IRaiAQIBVqIBEgEnMgFnNqQQ53IBNqIhUgF3MgCCgCACIIIBNqIBYgEkEKdyIScyAVc2pBD3cgEWoi\
E3NqQQx3IBJqIhYgE0EKdyIRcyAJIBJqIBMgFUEKdyIScyAWc2pBBXcgF2oiE3NqQQh3IBJqIhdBCn\
ciFWogAyAWQQp3IhZqIAogEmogEyAWcyAXc2pBB3cgEWoiEiAVcyAEIBFqIBcgE0EKdyITcyASc2pB\
CXcgFmoiFnNqQQt3IBNqIhcgFkEKdyIRcyALIBNqIBYgEkEKdyIScyAXc2pBDXcgFWoiE3NqQQ53IB\
JqIhZBCnciFWogBiAXQQp3IhdqIBIgB2ogEyAXcyAWc2pBD3cgEWoiEiAVcyARIA1qIBYgE0EKdyIT\
cyASc2pBBncgF2oiFnNqQQd3IBNqIhEgFkEKdyIYcyATIA5qIBYgEkEKdyIZcyARc2pBCXcgFWoiFX\
NqQQh3IBlqIhdBCnciEmogDyAMIAYgBSAAKAIcIhpBCnciE2ogBCAAKAIgIhZqIA4gACgCJCIbaiAC\
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\
akHEABCXARogAkHYAGoiAyACQcgCakE8aikCADcDACACQdAAaiIEIAJByAJqQTRqKQIANwMAIAJByA\
BqIgUgAkHIAmpBLGopAgA3AwAgAkHAAGoiBiACQcgCakEkaikCADcDACACQThqIgcgAkHIAmpBHGop\
AgA3AwAgAkEwaiIIIAJByAJqQRRqKQIANwMAIAJBIGpBCGoiCSACQcgCakEMaikCADcDACACIAIpAs\
wCNwMgQeAAEAkiAUUNDCABQQA2AgggAUIANwMAIAEgAikDIDcCDCABQRRqIAkpAwA3AgAgAUEcaiAI\
KQMANwIAIAFBJGogBykDADcCACABQSxqIAYpAwA3AgAgAUE0aiAFKQMANwIAIAFBPGogBCkDADcCAC\
ABQcQAaiADKQMANwIAIAFB1ABqQQApAoibQDcCACABQQApAoCbQDcCTEHUgMAAIQMMHwsgAkGwAWpB\
DGoiAUIANwIAIAJCADcCtAEgAkEQNgKwASACQcgCakEQaiIEIAJBsAFqQRBqIgUoAgA2AgAgAkHIAm\
pBCGoiAyACQbABakEIaiIGKQMANwMAIAJBIGpBCGoiByACQcgCakEMaiIIKQIANwMAIAIgAikDsAE3\
A8gCIAIgAikCzAI3AyAgAUIANwIAIAJCADcCtAEgAkEQNgKwASAEIAUoAgA2AgAgAyAGKQMANwMAIA\
IgAikDsAE3A8gCIAJBEGpBCGoiBCAIKQIANwMAIAIgAikCzAI3AxAgAyAHKQMANwMAIAIgAikDIDcD\
yAJB1AAQCSIBRQ0JIAFBADYCACABIAIpA8gCNwIEIAFCADcCFCABIAIpAxA3AkQgAUEcakIANwIAIA\
FBJGpCADcCACABQSxqQgA3AgAgAUE0akIANwIAIAFBPGpCADcCACABQQxqIAMpAwA3AgAgAUHMAGog\
BCkDADcCAEGEgMAAIQMMHgsgAkGwAWpBDGpCADcCACACQbABakEUakIANwIAIAJBsAFqQRxqQgA3Ag\
AgAkGwAWpBJGpCADcCACACQbABakEsakIANwIAIAJBsAFqQTRqQgA3AgAgAkGwAWpBPGpCADcCACAC\
QgA3ArQBIAJBwAA2ArABIAJByAJqIAJBsAFqQcQAEJcBGiACQdgAaiIDIAJByAJqQTxqKQIANwMAIA\
JB0ABqIgQgAkHIAmpBNGopAgA3AwAgAkHIAGoiBSACQcgCakEsaikCADcDACACQcAAaiIGIAJByAJq\
QSRqKQIANwMAIAJBOGoiByACQcgCakEcaikCADcDACACQTBqIgggAkHIAmpBFGopAgA3AwAgAkEgak\
EIaiIJIAJByAJqQQxqKQIANwMAIAIgAikCzAI3AyBB4AAQCSIBRQ0JIAFBADYCCCABQgA3AwAgASAC\
KQMgNwIMIAFBFGogCSkDADcCACABQRxqIAgpAwA3AgAgAUEkaiAHKQMANwIAIAFBLGogBikDADcCAC\
ABQTRqIAUpAwA3AgAgAUE8aiAEKQMANwIAIAFBxABqIAMpAwA3AgAgAUHUAGpBACkCiJtANwIAIAFB\
ACkCgJtANwJMQayAwAAhAwwdCwJAAkAgAEH4gMAAQQkQjwFFDQAgAEGogcAAQQkQjwFFDQEgAEG8hM\
AAIAEQjwFFDQQgAEHshMAAIAEQjwFFDQUgAEGchcAAIAEQjwFFDQYgAEHMhcAAIAEQjwENCCACQQA2\
ArABIAJBsAFqQQRyQQBByAAQnQEaIAJByAA2ArABIAJByAJqIAJBsAFqQcwAEJcBGiACQSBqIAJByA\
JqQQRyQcgAEJcBGkGYAhAJIgFFDRkgAUEAQcwBEJ0BQcwBaiACQSBqQcgAEJcBGkHYhcAAIQMMHgsg\
AkGwAWpBDGpCADcCACACQbABakEUakIANwIAIAJBsAFqQRxqQgA3AgAgAkGwAWpBJGpCADcCACACQb\
ABakEsakIANwIAIAJBsAFqQTRqQgA3AgAgAkGwAWpBPGpCADcCACACQgA3ArQBIAJBwAA2ArABIAJB\
yAJqIAJBsAFqQcQAEJcBGiACQSBqQThqIgMgAkHIAmpBPGopAgA3AwAgAkEgakEwaiIEIAJByAJqQT\
RqKQIANwMAIAJBIGpBKGoiBSACQcgCakEsaikCADcDACACQcAAaiIGIAJByAJqQSRqKQIANwMAIAJB\
IGpBGGoiByACQcgCakEcaikCADcDACACQSBqQRBqIgggAkHIAmpBFGopAgA3AwAgAkEgakEIaiIJIA\
JByAJqQQxqKQIANwMAIAIgAikCzAI3AyBB4AAQCSIBRQ0LIAFCADcDACABQQA2AhwgASACKQMgNwIg\
IAFBACkDuJtANwMIIAFBEGpBACkDwJtANwMAIAFBGGpBACgCyJtANgIAIAFBKGogCSkDADcCACABQT\
BqIAgpAwA3AgAgAUE4aiAHKQMANwIAIAFBwABqIAYpAwA3AgAgAUHIAGogBSkDADcCACABQdAAaiAE\
KQMANwIAIAFB2ABqIAMpAwA3AgBBhIHAACEDDB0LIAJBsAFqQQxqQgA3AgAgAkGwAWpBFGpCADcCAC\
ACQbABakEcakIANwIAIAJBsAFqQSRqQgA3AgAgAkGwAWpBLGpCADcCACACQbABakE0akIANwIAIAJB\
sAFqQTxqQgA3AgAgAkIANwK0ASACQcAANgKwASACQcgCaiACQbABakHEABCXARogAkHYAGoiAyACQc\
gCakE8aikCADcDACACQdAAaiIEIAJByAJqQTRqKQIANwMAIAJBIGpBKGoiBSACQcgCakEsaikCADcD\
ACACQSBqQSBqIgYgAkHIAmpBJGopAgA3AwAgAkEgakEYaiIHIAJByAJqQRxqKQIANwMAIAJBIGpBEG\
oiCCACQcgCakEUaikCADcDACACQSBqQQhqIgkgAkHIAmpBDGopAgA3AwAgAiACKQLMAjcDIEH4ABAJ\
IgFFDQsgAUIANwMAIAFBADYCMCABIAIpAyA3AjQgAUEAKQOQm0A3AwggAUEQakEAKQOYm0A3AwAgAU\
EYakEAKQOgm0A3AwAgAUEgakEAKQOom0A3AwAgAUEoakEAKQOwm0A3AwAgAUE8aiAJKQMANwIAIAFB\
xABqIAgpAwA3AgAgAUHMAGogBykDADcCACABQdQAaiAGKQMANwIAIAFB3ABqIAUpAwA3AgAgAUHkAG\
ogBCkDADcCACABQewAaiADKQMANwIAQbSBwAAhAwwcCwJAAkACQAJAIABB/IHAAEEGEI8BRQ0AIABB\
qILAAEEGEI8BRQ0BIABB1ILAAEEGEI8BRQ0CIABBgIPAAEEGEI8BRQ0DIABB/IXAAEEGEI8BDQkgAk\
HlAmoiA0EAKQOInEAiCjcAACACQd0CakEAKQOAnEAiCzcAACACQdUCakEAKQP4m0AiDDcAACACQQAp\
A/CbQCINNwDNAkH4DhAJIgFFDRsgAUIANwMAIAEgDTcDCCABQRBqIAw3AwAgAUEYaiALNwMAIAFBIG\
ogCjcDACABQShqQQBBwwAQnQEaIAFBADoA8A4gAUGIAWogAykAADcAACABQYMBaiACQcgCakEYaikA\
ADcAACABQfsAaiACQcgCakEQaikAADcAACABQfMAaiACQdACaikAADcAACABIAIpAMgCNwBrQYSGwA\
AhAwwfCyACQbABakEMakIANwIAIAJBsAFqQRRqQgA3AgAgAkGwAWpBHGpCADcCACACQbABakEkakIA\
NwIAIAJBsAFqQSxqQgA3AgAgAkGwAWpBNGpCADcCACACQbABakE8akIANwIAIAJCADcCtAEgAkHAAD\
YCsAEgAkHIAmogAkGwAWpBxAAQlwEaIAJB2ABqIgMgAkHIAmpBPGopAgA3AwAgAkHQAGoiBCACQcgC\
akE0aikCADcDACACQcgAaiIFIAJByAJqQSxqKQIANwMAIAJBwABqIgYgAkHIAmpBJGopAgA3AwAgAk\
E4aiIHIAJByAJqQRxqKQIANwMAIAJBMGoiCCACQcgCakEUaikCADcDACACQSBqQQhqIgkgAkHIAmpB\
DGopAgA3AwAgAiACKQLMAjcDIEHwABAJIgFFDQ4gASACKQMgNwIMIAFBADYCCCABQgA3AwAgAUEcai\
AIKQMANwIAIAFBFGogCSkDADcCACABQSRqIAcpAwA3AgAgAUEsaiAGKQMANwIAIAFBNGogBSkDADcC\
ACABQTxqIAQpAwA3AgAgAUHEAGogAykDADcCACABQdQAakEAKQLUm0A3AgAgAUEAKQLMm0A3AkwgAU\
HkAGpBACkC5JtANwIAIAFB3ABqQQApAtybQDcCAEGEgsAAIQMMHgsgAkGwAWpBDGpCADcCACACQbAB\
akEUakIANwIAIAJBsAFqQRxqQgA3AgAgAkGwAWpBJGpCADcCACACQbABakEsakIANwIAIAJBsAFqQT\
RqQgA3AgAgAkGwAWpBPGpCADcCACACQgA3ArQBIAJBwAA2ArABIAJByAJqIAJBsAFqQcQAEJcBGiAC\
QdgAaiIDIAJByAJqQTxqKQIANwMAIAJB0ABqIgQgAkHIAmpBNGopAgA3AwAgAkHIAGoiBSACQcgCak\
EsaikCADcDACACQcAAaiIGIAJByAJqQSRqKQIANwMAIAJBOGoiByACQcgCakEcaikCADcDACACQTBq\
IgggAkHIAmpBFGopAgA3AwAgAkEgakEIaiIJIAJByAJqQQxqKQIANwMAIAIgAikCzAI3AyBB8AAQCS\
IBRQ0OIAEgAikDIDcCDCABQQA2AgggAUIANwMAIAFBHGogCCkDADcCACABQRRqIAkpAwA3AgAgAUEk\
aiAHKQMANwIAIAFBLGogBikDADcCACABQTRqIAUpAwA3AgAgAUE8aiAEKQMANwIAIAFBxABqIAMpAw\
A3AgAgAUHUAGpBACkD+JtANwIAIAFBACkD8JtANwJMIAFB5ABqQQApA4icQDcCACABQdwAakEAKQOA\
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\
AkEIQQAoArynQCICQQIgAhsRBAAAC0G4AkEIQQAoArynQCICQQIgAhsRBAAAC0GYAkEIQQAoArynQC\
ICQQIgAhsRBAAAC0HgAkEIQQAoArynQCICQQIgAhsRBAAAC0HYAkEIQQAoArynQCICQQIgAhsRBAAA\
C0G4AkEIQQAoArynQCICQQIgAhsRBAAAC0GYAkEIQQAoArynQCICQQIgAhsRBAAAC0H4DkEIQQAoAr\
ynQCICQQIgAhsRBAAAC0E4QQFBACgCvKdAIgJBAiACGxEEAAALQaSHwABBMyACQcgCakHYh8AAQeiH\
wAAQfwALIAJBsAFqQQxqQgA3AgAgAkGwAWpBFGpCADcCACACQbABakEcakIANwIAIAJBsAFqQSRqQg\
A3AgAgAkGwAWpBLGpCADcCACACQbABakE0akIANwIAIAJBsAFqQTxqQgA3AgAgAkIANwK0ASACQcAA\
NgKwASACQcgCaiACQbABakHEABCXARogAkEgakE4aiIDIAJByAJqQTxqKQIANwMAIAJBIGpBMGoiBC\
ACQcgCakE0aikCADcDACACQSBqQShqIgUgAkHIAmpBLGopAgA3AwAgAkHAAGoiBiACQcgCakEkaikC\
ADcDACACQSBqQRhqIgcgAkHIAmpBHGopAgA3AwAgAkEgakEQaiIIIAJByAJqQRRqKQIANwMAIAJBIG\
pBCGoiCSACQcgCakEMaikCADcDACACIAIpAswCNwMgQeAAEAkiAUUNASABQgA3AwAgAUEANgIcIAEg\
AikDIDcCICABQQApA7ibQDcDCCABQRBqQQApA8CbQDcDACABQRhqQQAoAsibQDYCACABQShqIAkpAw\
A3AgAgAUEwaiAIKQMANwIAIAFBOGogBykDADcCACABQcAAaiAGKQMANwIAIAFByABqIAUpAwA3AgAg\
AUHQAGogBCkDADcCACABQdgAaiADKQMANwIAQdiBwAAhAwsgABAPAkBBDBAJIgANAEEMQQRBACgCvK\
dAIgJBAiACGxEEAAALIAAgAzYCCCAAIAE2AgQgAEEANgIAIAJB4ANqJAAgAA8LQeAAQQhBACgCvKdA\
IgJBAiACGxEEAAALuSQBU38jAEHAAGsiA0E4akIANwMAIANBMGpCADcDACADQShqQgA3AwAgA0Egak\
IANwMAIANBGGpCADcDACADQRBqQgA3AwAgA0EIakIANwMAIANCADcDACAAKAIQIQQgACgCDCEFIAAo\
AgghBiAAKAIEIQcgACgCACEIAkAgAkEGdCICRQ0AIAEgAmohCQNAIAMgASgAACICQRh0IAJBCHRBgI\
D8B3FyIAJBCHZBgP4DcSACQRh2cnI2AgAgAyABQQRqKAAAIgJBGHQgAkEIdEGAgPwHcXIgAkEIdkGA\
/gNxIAJBGHZycjYCBCADIAFBCGooAAAiAkEYdCACQQh0QYCA/AdxciACQQh2QYD+A3EgAkEYdnJyNg\
IIIAMgAUEMaigAACICQRh0IAJBCHRBgID8B3FyIAJBCHZBgP4DcSACQRh2cnI2AgwgAyABQRBqKAAA\
IgJBGHQgAkEIdEGAgPwHcXIgAkEIdkGA/gNxIAJBGHZycjYCECADIAFBFGooAAAiAkEYdCACQQh0QY\
CA/AdxciACQQh2QYD+A3EgAkEYdnJyNgIUIAMgAUEcaigAACICQRh0IAJBCHRBgID8B3FyIAJBCHZB\
gP4DcSACQRh2cnIiCjYCHCADIAFBIGooAAAiAkEYdCACQQh0QYCA/AdxciACQQh2QYD+A3EgAkEYdn\
JyIgs2AiAgAyABQRhqKAAAIgJBGHQgAkEIdEGAgPwHcXIgAkEIdkGA/gNxIAJBGHZyciIMNgIYIAMo\
AgAhDSADKAIEIQ4gAygCCCEPIAMoAhAhECADKAIMIREgAygCFCESIAMgAUEkaigAACICQRh0IAJBCH\
RBgID8B3FyIAJBCHZBgP4DcSACQRh2cnIiEzYCJCADIAFBKGooAAAiAkEYdCACQQh0QYCA/AdxciAC\
QQh2QYD+A3EgAkEYdnJyIhQ2AiggAyABQTBqKAAAIgJBGHQgAkEIdEGAgPwHcXIgAkEIdkGA/gNxIA\
JBGHZyciIVNgIwIAMgAUEsaigAACICQRh0IAJBCHRBgID8B3FyIAJBCHZBgP4DcSACQRh2cnIiFjYC\
LCADIAFBNGooAAAiAkEYdCACQQh0QYCA/AdxciACQQh2QYD+A3EgAkEYdnJyIgI2AjQgAyABQThqKA\
AAIhdBGHQgF0EIdEGAgPwHcXIgF0EIdkGA/gNxIBdBGHZyciIXNgI4IAMgAUE8aigAACIYQRh0IBhB\
CHRBgID8B3FyIBhBCHZBgP4DcSAYQRh2cnIiGDYCPCAIIBMgCnMgGHMgDCAQcyAVcyARIA5zIBNzIB\
dzQQF3IhlzQQF3IhpzQQF3IhsgCiAScyACcyAQIA9zIBRzIBhzQQF3IhxzQQF3Ih1zIBggAnMgHXMg\
FSAUcyAccyAbc0EBdyIec0EBdyIfcyAaIBxzIB5zIBkgGHMgG3MgFyAVcyAacyAWIBNzIBlzIAsgDH\
MgF3MgEiARcyAWcyAPIA1zIAtzIAJzQQF3IiBzQQF3IiFzQQF3IiJzQQF3IiNzQQF3IiRzQQF3IiVz\
QQF3IiZzQQF3IicgHSAhcyACIBZzICFzIBQgC3MgIHMgHXNBAXciKHNBAXciKXMgHCAgcyAocyAfc0\
EBdyIqc0EBdyIrcyAfIClzICtzIB4gKHMgKnMgJ3NBAXciLHNBAXciLXMgJiAqcyAscyAlIB9zICdz\
ICQgHnMgJnMgIyAbcyAlcyAiIBpzICRzICEgGXMgI3MgICAXcyAicyApc0EBdyIuc0EBdyIvc0EBdy\
Iwc0EBdyIxc0EBdyIyc0EBdyIzc0EBdyI0c0EBdyI1ICsgL3MgKSAjcyAvcyAoICJzIC5zICtzQQF3\
IjZzQQF3IjdzICogLnMgNnMgLXNBAXciOHNBAXciOXMgLSA3cyA5cyAsIDZzIDhzIDVzQQF3IjpzQQ\
F3IjtzIDQgOHMgOnMgMyAtcyA1cyAyICxzIDRzIDEgJ3MgM3MgMCAmcyAycyAvICVzIDFzIC4gJHMg\
MHMgN3NBAXciPHNBAXciPXNBAXciPnNBAXciP3NBAXciQHNBAXciQXNBAXciQnNBAXciQyA5ID1zID\
cgMXMgPXMgNiAwcyA8cyA5c0EBdyJEc0EBdyJFcyA4IDxzIERzIDtzQQF3IkZzQQF3IkdzIDsgRXMg\
R3MgOiBEcyBGcyBDc0EBdyJIc0EBdyJJcyBCIEZzIEhzIEEgO3MgQ3MgQCA6cyBCcyA/IDVzIEFzID\
4gNHMgQHMgPSAzcyA/cyA8IDJzID5zIEVzQQF3IkpzQQF3IktzQQF3IkxzQQF3Ik1zQQF3Ik5zQQF3\
Ik9zQQF3IlBzQQF3aiBGIEpzIEQgPnMgSnMgR3NBAXciUXMgSXNBAXciUiBFID9zIEtzIFFzQQF3Il\
MgTCBBIDogOSA8IDEgJiAfICggISAXIBMgECAIQR53IlRqIA4gBSAHQR53IhAgBnMgCHEgBnNqaiAN\
IAQgCEEFd2ogBiAFcyAHcSAFc2pqQZnzidQFaiIOQQV3akGZ84nUBWoiVUEedyIIIA5BHnciDXMgBi\
APaiAOIFQgEHNxIBBzaiBVQQV3akGZ84nUBWoiDnEgDXNqIBAgEWogVSANIFRzcSBUc2ogDkEFd2pB\
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\
IAcoAggiACABNgIMIAEgADYCCAwDCyABIAdBEGogBhshBgNAIAYhCAJAIAAiAUEUaiIGKAIAIgANAC\
ABQRBqIQYgASgCECEACyAADQALIAhBADYCAAwCCwJAAkACQAJAAkACQAJAAkACQAJAAkACQAJAQQAo\
AvymQCIAIAJPDQBBACgCgKdAIgAgAksNBEEAIQEgAkGvgARqIgVBEHZAACIAQX9GIgcNDSAAQRB0Ig\
ZFDQ1BAEEAKAKMp0BBACAFQYCAfHEgBxsiCGoiADYCjKdAQQBBACgCkKdAIgEgACABIABLGzYCkKdA\
QQAoAoinQCIBRQ0BQZSnwAAhAANAIAAoAgAiBSAAKAIEIgdqIAZGDQMgACgCCCIADQAMBAsLQQAoAo\
SnQCEBAkACQCAAIAJrIgVBD0sNAEEAQQA2AoSnQEEAQQA2AvymQCABIABBA3I2AgQgASAAaiIAIAAo\
AgRBAXI2AgQMAQtBACAFNgL8pkBBACABIAJqIgY2AoSnQCAGIAVBAXI2AgQgASAAaiAFNgIAIAEgAk\
EDcjYCBAsgAUEIag8LAkACQEEAKAKop0AiAEUNACAAIAZNDQELQQAgBjYCqKdAC0EAQf8fNgKsp0BB\
ACAINgKYp0BBACAGNgKUp0BBAEH0o8AANgKApEBBAEH8o8AANgKIpEBBAEH0o8AANgL8o0BBAEGEpM\
AANgKQpEBBAEH8o8AANgKEpEBBAEGMpMAANgKYpEBBAEGEpMAANgKMpEBBAEGUpMAANgKgpEBBAEGM\
pMAANgKUpEBBAEGcpMAANgKopEBBAEGUpMAANgKcpEBBAEGkpMAANgKwpEBBAEGcpMAANgKkpEBBAE\
GspMAANgK4pEBBAEGkpMAANgKspEBBAEEANgKgp0BBAEG0pMAANgLApEBBAEGspMAANgK0pEBBAEG0\
pMAANgK8pEBBAEG8pMAANgLIpEBBAEG8pMAANgLEpEBBAEHEpMAANgLQpEBBAEHEpMAANgLMpEBBAE\
HMpMAANgLYpEBBAEHMpMAANgLUpEBBAEHUpMAANgLgpEBBAEHUpMAANgLcpEBBAEHcpMAANgLopEBB\
AEHcpMAANgLkpEBBAEHkpMAANgLwpEBBAEHkpMAANgLspEBBAEHspMAANgL4pEBBAEHspMAANgL0pE\
BBAEH0pMAANgKApUBBAEH8pMAANgKIpUBBAEH0pMAANgL8pEBBAEGEpcAANgKQpUBBAEH8pMAANgKE\
pUBBAEGMpcAANgKYpUBBAEGEpcAANgKMpUBBAEGUpcAANgKgpUBBAEGMpcAANgKUpUBBAEGcpcAANg\
KopUBBAEGUpcAANgKcpUBBAEGkpcAANgKwpUBBAEGcpcAANgKkpUBBAEGspcAANgK4pUBBAEGkpcAA\
NgKspUBBAEG0pcAANgLApUBBAEGspcAANgK0pUBBAEG8pcAANgLIpUBBAEG0pcAANgK8pUBBAEHEpc\
AANgLQpUBBAEG8pcAANgLEpUBBAEHMpcAANgLYpUBBAEHEpcAANgLMpUBBAEHUpcAANgLgpUBBAEHM\
pcAANgLUpUBBAEHcpcAANgLopUBBAEHUpcAANgLcpUBBAEHkpcAANgLwpUBBAEHcpcAANgLkpUBBAE\
HspcAANgL4pUBBAEHkpcAANgLspUBBACAGNgKIp0BBAEHspcAANgL0pUBBACAIQVhqIgA2AoCnQCAG\
IABBAXI2AgQgBiAAakEoNgIEQQBBgICAATYCpKdADAoLIAAoAgwNACAFIAFLDQAgBiABSw0CC0EAQQ\
AoAqinQCIAIAYgACAGSRs2AqinQCAGIAhqIQVBlKfAACEAAkACQAJAA0AgACgCACAFRg0BIAAoAggi\
AA0ADAILCyAAKAIMRQ0BC0GUp8AAIQACQANAAkAgACgCACIFIAFLDQAgBSAAKAIEaiIFIAFLDQILIA\
AoAggiAA0ACwALQQAgBjYCiKdAQQAgCEFYaiIANgKAp0AgBiAAQQFyNgIEIAYgAGpBKDYCBEEAQYCA\
gAE2AqSnQCABIAVBYGpBeHFBeGoiACAAIAFBEGpJGyIHQRs2AgRBACkClKdAIQogB0EQakEAKQKcp0\
A3AgAgByAKNwIIQQAgCDYCmKdAQQAgBjYClKdAQQAgB0EIajYCnKdAQQBBADYCoKdAIAdBHGohAANA\
IABBBzYCACAFIABBBGoiAEsNAAsgByABRg0JIAcgBygCBEF+cTYCBCABIAcgAWsiBkEBcjYCBCAHIA\
Y2AgACQCAGQYACSQ0AQR8hAAJAIAZB////B0sNACAGQQYgBkEIdmciAGtBH3F2QQFxIABBAXRrQT5q\
IQALIAFCADcCECABQRxqIAA2AgAgAEECdEH8pcAAaiEFAkACQAJAAkACQEEAKALwo0AiB0EBIABBH3\
F0IghxRQ0AIAUoAgAiBygCBEF4cSAGRw0BIAchAAwCC0EAIAcgCHI2AvCjQCAFIAE2AgAgAUEYaiAF\
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\
ACADQfgAakE4aiAAQThqKQMANwMAIANB+ABqQcAAaiAAQcAAaikDADcDACADQfgAakHIAGogAEHIAG\
opAwA3AwAgA0H4AGpB0ABqIABB0ABqKQMANwMAIANB+ABqQdgAaiAAQdgAaikDADcDACADQfgAakHg\
AGogAEHgAGopAwA3AwAgAyAAKQMINwOAASADIAApAyg3A6ABIABB6QBqLQAAIQggAC0AaiEJIAMgAC\
0AaCIKOgDgASADIAApAwAiHjcDeCADIAkgCEVyQQJyIgg6AOEBIANB6AFqQRhqIgkgBykCADcDACAD\
QegBakEQaiIHIAYpAgA3AwAgA0HoAWpBCGoiBiAEKQIANwMAIAMgACkCCDcD6AEgA0HoAWogA0H4AG\
pBKGogCiAeIAgQCiAJKAIAIQggBygCACEHIAYoAgAhCSADKAKEAiEKIAMoAvwBIQsgAygC9AEhDCAD\
KALsASENIAMoAugBIQ4gACAAKQMAEBcgAEHwDmoiDy0AACIGQTdPDQIgACAGQQV0aiIEQZABaiAONg\
IAIARBrAFqIAo2AgAgBEGoAWogCDYCACAEQaQBaiALNgIAIARBoAFqIAc2AgAgBEGcAWogDDYCACAE\
QZgBaiAJNgIAIARBlAFqIA02AgAgDyAGQQFqOgAAIABBKGoiBEIANwMAIARBCGpCADcDACAEQRBqQg\
A3AwAgBEEYakIANwMAIARBIGpCADcDACAEQShqQgA3AwAgBEEwakIANwMAIARBOGpCADcDACAAQQA7\
AWggAEEIaiIEIAApA3A3AwAgBEEIaiAAQfgAaikDADcDACAEQRBqIABBgAFqKQMANwMAIARBGGogAE\
GIAWopAwA3AwAgACAAKQMAQgF8NwMAIAEgBWohAQsCQCACQYEISQ0AIABBkAFqIQ4gAEHwAGohByAA\
KQMAIR8gA0EIakEoaiEKIANBCGpBCGohDSADQfgAakEoaiEJIANB+ABqQQhqIQsgAEHwDmohDANAIB\
9CCoYhHkF/IAJBAXZndkEBaiEFA0AgBSIEQQF2IQUgHiAEQX9qrYNCAFINAAsgBEEKdq0hHgJAAkAg\
BEGBCEkNACACIARJDQYgAC0AaiEIIANB+ABqQThqQgA3AwAgA0H4AGpBMGpCADcDACAJQgA3AwAgA0\
H4AGpBIGpCADcDACADQfgAakEYakIANwMAIANB+ABqQRBqQgA3AwAgC0IANwMAIANCADcDeCABIAQg\
ByAfIAggA0H4AGpBwAAQDiEFIANBkAJqQRhqQgA3AwAgA0GQAmpBEGpCADcDACADQZACakEIakIANw\
MAIANCADcDkAICQCAFQQNJDQADQCAFQQV0IgVBwQBPDQkgA0H4AGogBSAHIAggA0GQAmpBIBAhIgVB\
BXQiBkHBAE8NCiAGQSFPDQsgA0H4AGogA0GQAmogBhCXARogBUECSw0ACwsgAygCtAEhECADKAKwAS\
ERIAMoAqwBIRIgAygCqAEhEyADKAKkASEUIAMoAqABIRUgAygCnAEhFiADKAKYASEXIAMoApQBIQgg\
AygCkAEhDyADKAKMASEYIAMoAogBIRkgAygChAEhGiADKAKAASEbIAMoAnwhHCADKAJ4IR0gACAAKQ\
MAEBcgDC0AACIGQTdPDQogDiAGQQV0aiIFIB02AgAgBSAINgIcIAUgDzYCGCAFIBg2AhQgBSAZNgIQ\
IAUgGjYCDCAFIBs2AgggBSAcNgIEIAwgBkEBajoAACAAIAApAwAgHkIBiHwQFyAMLQAAIgZBN08NCy\
AOIAZBBXRqIgUgFzYCACAFIBA2AhwgBSARNgIYIAUgEjYCFCAFIBM2AhAgBSAUNgIMIAUgFTYCCCAF\
IBY2AgQgDCAGQQFqOgAADAELIAlCADcDACAJQQhqIg9CADcDACAJQRBqIhhCADcDACAJQRhqIhlCAD\
cDACAJQSBqIhpCADcDACAJQShqIhtCADcDACAJQTBqIhxCADcDACAJQThqIh1CADcDACALIAcpAwA3\
AwAgC0EIaiIFIAdBCGopAwA3AwAgC0EQaiIGIAdBEGopAwA3AwAgC0EYaiIIIAdBGGopAwA3AwAgA0\
EAOwHgASADIB83A3ggAyAALQBqOgDiASADQfgAaiABIAQQORogDSALKQMANwMAIA1BCGogBSkDADcD\
ACANQRBqIAYpAwA3AwAgDUEYaiAIKQMANwMAIAogCSkDADcDACAKQQhqIA8pAwA3AwAgCkEQaiAYKQ\
MANwMAIApBGGogGSkDADcDACAKQSBqIBopAwA3AwAgCkEoaiAbKQMANwMAIApBMGogHCkDADcDACAK\
QThqIB0pAwA3AwAgAy0A4gEhDyADLQDhASEYIAMgAy0A4AEiGToAcCADIAMpA3giHzcDCCADIA8gGE\
VyQQJyIg86AHEgA0HoAWpBGGoiGCAIKQIANwMAIANB6AFqQRBqIgggBikCADcDACADQegBakEIaiIG\
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\
IQQgACgCDCEFIAAoAgQhBiACQcAAayICQRhqIgdCADcDACACQSBqIghCADcDACACQThqIglCADcDAC\
ACQTBqIgpCADcDACACQShqIgtCADcDACACQQhqIgwgASkACDcDACACQRBqIg0gASkAEDcDACAHIAEo\
ABgiDjYCACAIIAEoACAiDzYCACACIAEpAAA3AwAgAiABKAAcIhA2AhwgAiABKAAkIhE2AiQgCyABKA\
AoIhI2AgAgAiABKAAsIgs2AiwgCiABKAAwIhM2AgAgAiABKAA0Igo2AjQgCSABKAA4IhQ2AgAgAiAB\
KAA8IhU2AjwgACADIBMgCyASIBEgDyAQIA4gBiAEIAUgBiADIAYgBHFqIAUgBkF/c3FqIAIoAgAiFm\
pBA3ciAXFqIAQgAUF/c3FqIAIoAgQiF2pBB3ciByABcWogBiAHQX9zcWogDCgCACIMakELdyIIIAdx\
aiABIAhBf3NxaiACKAIMIhhqQRN3IgkgCHEgAWogByAJQX9zcWogDSgCACINakEDdyIBIAlxIAdqIA\
ggAUF/c3FqIAIoAhQiGWpBB3ciAiABcSAIaiAJIAJBf3NxampBC3ciByACcSAJaiABIAdBf3NxampB\
E3ciCCAHcSABaiACIAhBf3NxampBA3ciASAIcSACaiAHIAFBf3NxampBB3ciAiABcSAHaiAIIAJBf3\
NxampBC3ciByACcSAIaiABIAdBf3NxampBE3ciCCAHcSABaiACIAhBf3NxampBA3ciASAUIAEgCiAB\
IAhxIAJqIAcgAUF/c3FqakEHdyIJcSAHaiAIIAlBf3NxampBC3ciAiAJciAVIAIgCXEiByAIaiABIA\
JBf3NxampBE3ciAXEgB3JqIBZqQZnzidQFakEDdyIHIA8gAiAJIAcgASACcnEgASACcXJqIA1qQZnz\
idQFakEFdyIIIAcgAXJxIAcgAXFyampBmfOJ1AVqQQl3IgIgCHIgEyABIAIgCCAHcnEgCCAHcXJqak\
GZ84nUBWpBDXciAXEgAiAIcXJqIBdqQZnzidQFakEDdyIHIBEgAiAIIAcgASACcnEgASACcXJqIBlq\
QZnzidQFakEFdyIIIAcgAXJxIAcgAXFyampBmfOJ1AVqQQl3IgIgCHIgCiABIAIgCCAHcnEgCCAHcX\
JqakGZ84nUBWpBDXciAXEgAiAIcXJqIAxqQZnzidQFakEDdyIHIBIgAiAOIAggByABIAJycSABIAJx\
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\
ACIFKAIEQXhxIAFHDQEgBSECDAILQQAgBSAGcjYC8KNAIAMgADYCACAAQRhqIAM2AgAMAwsgAUEAQR\
kgAkEBdmtBH3EgAkEfRht0IQMDQCAFIANBHXZBBHFqQRBqIgYoAgAiAkUNAiADQQF0IQMgAiEFIAIo\
AgRBeHEgAUcNAAsLIAIoAggiASAANgIMIAIgADYCCCAAQRhqQQA2AgAgACACNgIMIAAgATYCCA8LIA\
YgADYCACAAQRhqIAU2AgALIAAgADYCDCAAIAA2AggPCyABQQN2IgJBA3RB9KPAAGohAQJAAkBBACgC\
7KNAIgNBASACdCICcUUNACABKAIIIQIMAQtBACADIAJyNgLso0AgASECCyABIAA2AgggAiAANgIMIA\
AgATYCDCAAIAI2AggLzwsCEH8EfiMAQeABayICJAACQAJAAkAgAUHwDmotAAAiA0UNACABQZABaiEE\
AkACQAJAAkAgAUHpAGotAAAiBUEGdEEAIAEtAGgiBmtHDQAgA0F+aiEHIANBAU0NBiACQfAAakEQai\
ABQfgAaikDADcDACACQfAAakEYaiABQYABaikDADcDACACQZABaiABQYgBaikDADcDACACQaABaiAE\
IAdBBXRqIgVBCGopAwA3AwAgAkGoAWogBUEQaikDADcDAEHAACEGIAJB8ABqQcAAaiAFQRhqKQMANw\
MAIAIgASkDcDcDeCACIAUpAwA3A5gBIANBBXQgBGpBYGoiBSkDACESIAUpAwghEyAFKQMQIRQgAS0A\
aiEIIAJB0AFqIAUpAxg3AwAgAkHIAWogFDcDACACQcABaiATNwMAIAJBuAFqIBI3AwBCACESIAJCAD\
cDcCACIAhBBHIiCToA2QEgAkHAADoA2AEgB0UNAiACQfAAakEIaiEFIAkhCgwBCyACQfAAakEQaiAB\
QRBqKQMANwMAIAJB8ABqQRhqIAFBGGopAwA3AwAgAkHwAGpBIGogAUEgaikDADcDACACQfAAakEwai\
ABQTBqKQMANwMAIAJB8ABqQThqIAFBOGopAwA3AwAgAkHwAGpBwABqIAFBwABqKQMANwMAIAJB8ABq\
QcgAaiABQcgAaikDADcDACACQfAAakHQAGogAUHQAGopAwA3AwAgAkHwAGpB2ABqIAFB2ABqKQMANw\
MAIAJB8ABqQeAAaiABQeAAaikDADcDACACIAEpAwg3A3ggAiABKQMoNwOYASACIAEtAGoiByAFRXJB\
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\
IA4pAgA3AwAgAiAGKQIANwOQASACQZABaiAAQcAAQgAgCBAKIAQoAgAhCyAMKAIAIQwgDSgCACENIA\
IoAqwBIQ4gAigCpAEhECACKAKcASERIAIoApQBIRIgAigCkAEhEyAPQf8BcSIEQTdPDQMgByAEQQV0\
aiIEIBM2AgAgBCAONgIcIAQgCzYCGCAEIBA2AhQgBCAMNgIQIAQgETYCDCAEIA02AgggBCASNgIEIA\
MgD0EBaiIEOgAAIARB/wFxIAVLDQALCyACQdABaiQADwtBnKLAAEErQZCKwAAQlAEACyACIA42AqwB\
IAIgCzYCqAEgAiAQNgKkASACIAw2AqABIAIgETYCnAEgAiANNgKYASACIBI2ApQBIAIgEzYCkAFBkJ\
3AAEErIAJBkAFqQcyLwABB8IrAABB/AAunBgERfyMAQYABayICJAACQAJAIAEoAgAiA0EQTw0AIAFB\
BGoiBCADakEQIANrIgMgAxCdARogAUEANgIAIAFBFGoiAyAEEA0gAkEQakEIaiIEIAFBzABqIgUpAA\
A3AwAgAiABQcQAaiIGKQAANwMQIAMgAkEQahANIAJBCGoiByABQRxqIggpAgA3AwAgAiABKQIUNwMA\
IAJBEGpBKGoiCUIANwMAIAJBEGpBIGoiCkIANwMAIAJBEGpBGGoiC0IANwMAIAJBEGpBEGoiDEIANw\
MAIARCADcDACACQgA3AxAgAkHQAGpBDGoiDUIANwIAIAJCADcCVCACQRA2AlAgAkHoAGpBEGogAkHQ\
AGpBEGooAgA2AgAgAkHoAGpBCGoiDiACQdAAakEIaiIPKQMANwMAIAIgAikDUDcDaCACQRBqQThqIh\
AgAkHoAGpBDGoiESkCADcDACACQRBqQTBqIhIgAikCbDcDACAFIBApAwA3AAAgBiASKQMANwAAIAFB\
PGogCSkDADcAACABQTRqIAopAwA3AAAgAUEsaiALKQMANwAAIAFBJGogDCkDADcAACAIIAQpAwA3AA\
AgASACKQMQNwAUIAFBADYCAEEQEAkiBUUNASAFIAIpAwA3AAAgBUEIaiAHKQMANwAAIAlCADcDACAK\
QgA3AwAgC0IANwMAIAJBEGpBEGoiBkIANwMAIARCADcDACACQgA3AxAgDUIANwIAIAJCADcCVCACQR\
A2AlAgAkHoAGpBEGogAkHQAGpBEGooAgA2AgAgDiAPKQMANwMAIAIgAikDUDcDaCAQIBEpAgA3AwAg\
EiACKQJsNwMAIANBOGogECkDADcAACADQTBqIBIpAwA3AAAgA0EoaiAJKQMANwAAIANBIGogCikDAD\
cAACADQRhqIAspAwA3AAAgA0EQaiAGKQMANwAAIANBCGogBCkDADcAACADIAIpAxA3AAAgAUEANgIA\
IABBEDYCBCAAIAU2AgAgAkGAAWokAA8LQbqfwABBFyACQRBqQeCawABB8JrAABB/AAtBEEEBQQAoAr\
ynQCICQQIgAhsRBAAAC/YFAgd/CH4jAEGgAWsiAiQAIAJBMGpBLGpCADcCACACQTBqQSRqQgA3AgAg\
AkEwakEcakIANwIAIAJBMGpBFGpCADcCACACQTBqQQxqQgA3AgAgAkIANwI0IAJBMDYCMCACQegAak\
EwaiACQTBqQTBqKAIANgIAIAJB6ABqQShqIAJBMGpBKGopAwA3AwAgAkHoAGpBIGogAkEwakEgaikD\
ADcDACACQegAakEYaiACQTBqQRhqKQMANwMAIAJB6ABqQRBqIAJBMGpBEGopAwA3AwAgAkHoAGpBCG\
ogAkEwakEIaikDADcDACACIAIpAzA3A2ggAkEoaiIDIAJB6ABqQSxqKQIANwMAIAJBIGoiBCACQegA\
akEkaikCADcDACACQRhqIgUgAkHoAGpBHGopAgA3AwAgAkEQaiIGIAJB6ABqQRRqKQIANwMAIAJBCG\
oiByACQegAakEMaikCADcDACACIAIpAmw3AwAgASACEB0gAUIANwMIIAFCADcDACABQQA2AlAgAUEA\
KQOQnEAiCTcDECABQRhqQQApA5icQCIKNwMAIAFBIGpBACkDoJxAIgs3AwAgAUEoakEAKQOonEAiDD\
cDACABQTBqQQApA7CcQCINNwMAIAFBOGpBACkDuJxAIg43AwAgAUHAAGpBACkDwJxAIg83AwAgAUHI\
AGpBACkDyJxAIhA3AwACQEEwEAkiCA0AQTBBAUEAKAK8p0AiAkECIAIbEQQAAAsgCCACKQMANwAAIA\
hBKGogAykDADcAACAIQSBqIAQpAwA3AAAgCEEYaiAFKQMANwAAIAhBEGogBikDADcAACAIQQhqIAcp\
AwA3AAAgAUIANwMIIAFCADcDACABQQA2AlAgAUEQaiIBIAk3AwAgAUEIaiAKNwMAIAFBEGogCzcDAC\
ABQRhqIAw3AwAgAUEgaiANNwMAIAFBKGogDjcDACABQTBqIA83AwAgAUE4aiAQNwMAIABBMDYCBCAA\
IAg2AgAgAkGgAWokAAvhBQIJfwh+IwBB0AFrIgIkACACQcAAakEMakIANwIAIAJBwABqQRRqQgA3Ag\
AgAkHAAGpBHGpCADcCACACQcAAakEkakIANwIAIAJBwABqQSxqQgA3AgAgAkHAAGpBNGpCADcCACAC\
QcAAakE8akIANwIAIAJCADcCRCACQcAANgJAIAJBiAFqIAJBwABqQcQAEJcBGiACQThqIgMgAkGIAW\
pBPGopAgA3AwAgAkEwaiIEIAJBiAFqQTRqKQIANwMAIAJBKGoiBSACQYgBakEsaikCADcDACACQSBq\
IgYgAkGIAWpBJGopAgA3AwAgAkEYaiIHIAJBiAFqQRxqKQIANwMAIAJBEGoiCCACQYgBakEUaikCAD\
cDACACQQhqIgkgAkGIAWpBDGopAgA3AwAgAiACKQKMATcDACABIAIQFiABQgA3AwggAUIANwMAIAFB\
ADYCUCABQQApA9CcQCILNwMQIAFBGGpBACkD2JxAIgw3AwAgAUEgakEAKQPgnEAiDTcDACABQShqQQ\
ApA+icQCIONwMAIAFBMGpBACkD8JxAIg83AwAgAUE4akEAKQP4nEAiEDcDACABQcAAakEAKQOAnUAi\
ETcDACABQcgAakEAKQOInUAiEjcDAAJAQcAAEAkiCg0AQcAAQQFBACgCvKdAIgJBAiACGxEEAAALIA\
ogAikDADcAACAKQThqIAMpAwA3AAAgCkEwaiAEKQMANwAAIApBKGogBSkDADcAACAKQSBqIAYpAwA3\
AAAgCkEYaiAHKQMANwAAIApBEGogCCkDADcAACAKQQhqIAkpAwA3AAAgAUIANwMIIAFCADcDACABQQ\
A2AlAgAUEQaiIBIAs3AwAgAUEIaiAMNwMAIAFBEGogDTcDACABQRhqIA43AwAgAUEgaiAPNwMAIAFB\
KGogEDcDACABQTBqIBE3AwAgAUE4aiASNwMAIABBwAA2AgQgACAKNgIAIAJB0AFqJAALoAUBCn8jAE\
EwayIDJAAgA0EkaiABNgIAIANBAzoAKCADQoCAgICABDcDCCADIAA2AiBBACEAIANBADYCGCADQQA2\
AhACQAJAAkACQCACKAIIIgENACACKAIAIQQgAigCBCIFIAJBFGooAgAiASABIAVLGyIGRQ0BIAIoAh\
AhB0EAIQAgBiEBA0ACQCAEIABqIghBBGooAgAiCUUNACADKAIgIAgoAgAgCSADKAIkKAIMEQcADQQL\
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\
IAtBBXQhDkEAIQsgBiEKA0AgCigCACEHIAZBEGpBGGoiCSACQRhqKQIANwMAIAZBEGpBEGoiASACQR\
BqKQIANwMAIAZBEGpBCGoiAyACQQhqKQIANwMAIAYgAikCADcDECAGQRBqIAdBwABCACANEAogBCAL\
aiIHQRhqIAkpAwA3AAAgB0EQaiABKQMANwAAIAdBCGogAykDADcAACAHIAYpAxA3AAAgCkEEaiEKIA\
4gC0EgaiILRw0ACyAGLQAIIQcLAkAgDEUNACAHQQV0IgIgBUsNAiAFIAJrIgtBH00NAyAMQSBHDQQg\
BCACaiICIAAgCGoiCykAADcAACACQRhqIAtBGGopAAA3AAAgAkEQaiALQRBqKQAANwAAIAJBCGogC0\
EIaikAADcAACAHQQFqIQcLIAZBMGokACAHDwsgBiALNgIQQZCdwABBKyAGQRBqQeCKwABB8IrAABB/\
AAsgAiAFQfyIwAAQhAEAC0EgIAtB/IjAABCFAQALQSAgDEGMnsAAEIYBAAuoBAEEfyMAQfAAayICJA\
AgAkEgakEcakIANwIAIAJBIGpBFGpCADcCACACQSBqQQxqQgA3AgAgAkIANwIkIAJBIDYCICACQcgA\
akEYaiACQSBqQRhqKQMANwMAIAJByABqQRBqIAJBIGpBEGopAwA3AwAgAkHIAGpBCGogAkEgakEIai\
kDADcDACACQcgAakEgaiACQSBqQSBqKAIANgIAIAIgAikDIDcDSCACQRBqIAJByABqQRRqKQIANwMA\
IAJBCGogAkHIAGpBDGopAgA3AwAgAkEYaiACQcgAakEcaikCADcDACACIAIpAkw3AwAgAiABEBIgAU\
IANwMAIAFBIGogAUGIAWopAwA3AwAgAUEYaiABQYABaikDADcDACABQRBqIAFB+ABqKQMANwMAIAEg\
ASkDcDcDCCABQShqQQBBwgAQnQEhAwJAIAFB8A5qIgQtAABFDQAgBEEAOgAACwJAQSAQCSIEDQBBIE\
EBQQAoArynQCICQQIgAhsRBAAACyAEIAIpAwA3AAAgBEEYaiACQRhqKQMANwAAIARBEGogAkEQaikD\
ADcAACAEQQhqIAJBCGopAwA3AAAgAUIANwMAIAFBCGoiBUEYaiABQfAAaiIBQRhqKQMANwMAIAVBEG\
ogAUEQaikDADcDACAFQQhqIAFBCGopAwA3AwAgBSABKQMANwMAIANBAEHCABCdARogAEEgNgIEIAAg\
BDYCACACQfAAaiQAC4kEAQd/IwBBoANrIgIkACACQegCakEsakIANwIAIAJB6AJqQSRqQgA3AgAgAk\
HoAmpBHGpCADcCACACQegCakEUakIANwIAIAJB6AJqQQxqQgA3AgAgAkIANwLsAiACQTA2AugCIAJB\
MGpBMGogAkHoAmpBMGooAgA2AgAgAkEwakEoaiACQegCakEoaikDADcDACACQTBqQSBqIAJB6AJqQS\
BqKQMANwMAIAJBMGpBGGogAkHoAmpBGGopAwA3AwAgAkEwakEQaiACQegCakEQaikDADcDACACQTBq\
QQhqIAJB6AJqQQhqKQMANwMAIAIgAikD6AI3AzAgAkEoaiIDIAJBMGpBLGopAgA3AwAgAkEgaiIEIA\
JBMGpBJGopAgA3AwAgAkEYaiIFIAJBMGpBHGopAgA3AwAgAkEQaiIGIAJBMGpBFGopAgA3AwAgAkEI\
aiIHIAJBMGpBDGopAgA3AwAgAiACKQI0NwMAIAJBMGogAUG4AhCXARogAkEwaiACEFoCQEEwEAkiCA\
0AQTBBAUEAKAK8p0AiAkECIAIbEQQAAAsgCCACKQMANwAAIAhBKGogAykDADcAACAIQSBqIAQpAwA3\
AAAgCEEYaiAFKQMANwAAIAhBEGogBikDADcAACAIQQhqIAcpAwA3AAAgARAPIABBMDYCBCAAIAg2Ag\
AgAkGgA2okAAuJBAEHfyMAQaADayICJAAgAkHoAmpBLGpCADcCACACQegCakEkakIANwIAIAJB6AJq\
QRxqQgA3AgAgAkHoAmpBFGpCADcCACACQegCakEMakIANwIAIAJCADcC7AIgAkEwNgLoAiACQTBqQT\
BqIAJB6AJqQTBqKAIANgIAIAJBMGpBKGogAkHoAmpBKGopAwA3AwAgAkEwakEgaiACQegCakEgaikD\
ADcDACACQTBqQRhqIAJB6AJqQRhqKQMANwMAIAJBMGpBEGogAkHoAmpBEGopAwA3AwAgAkEwakEIai\
ACQegCakEIaikDADcDACACIAIpA+gCNwMwIAJBKGoiAyACQTBqQSxqKQIANwMAIAJBIGoiBCACQTBq\
QSRqKQIANwMAIAJBGGoiBSACQTBqQRxqKQIANwMAIAJBEGoiBiACQTBqQRRqKQIANwMAIAJBCGoiBy\
ACQTBqQQxqKQIANwMAIAIgAikCNDcDACACQTBqIAFBuAIQlwEaIAJBMGogAhBZAkBBMBAJIggNAEEw\
QQFBACgCvKdAIgJBAiACGxEEAAALIAggAikDADcAACAIQShqIAMpAwA3AAAgCEEgaiAEKQMANwAAIA\
hBGGogBSkDADcAACAIQRBqIAYpAwA3AAAgCEEIaiAHKQMANwAAIAEQDyAAQTA2AgQgACAINgIAIAJB\
oANqJAALiQQBB38jAEHAAmsiAiQAIAJBiAJqQSxqQgA3AgAgAkGIAmpBJGpCADcCACACQYgCakEcak\
IANwIAIAJBiAJqQRRqQgA3AgAgAkGIAmpBDGpCADcCACACQgA3AowCIAJBMDYCiAIgAkEwakEwaiAC\
QYgCakEwaigCADYCACACQTBqQShqIAJBiAJqQShqKQMANwMAIAJBMGpBIGogAkGIAmpBIGopAwA3Aw\
AgAkEwakEYaiACQYgCakEYaikDADcDACACQTBqQRBqIAJBiAJqQRBqKQMANwMAIAJBMGpBCGogAkGI\
AmpBCGopAwA3AwAgAiACKQOIAjcDMCACQShqIgMgAkEwakEsaikCADcDACACQSBqIgQgAkEwakEkai\
kCADcDACACQRhqIgUgAkEwakEcaikCADcDACACQRBqIgYgAkEwakEUaikCADcDACACQQhqIgcgAkEw\
akEMaikCADcDACACIAIpAjQ3AwAgAkEwaiABQdgBEJcBGiACQTBqIAIQHQJAQTAQCSIIDQBBMEEBQQ\
AoArynQCICQQIgAhsRBAAACyAIIAIpAwA3AAAgCEEoaiADKQMANwAAIAhBIGogBCkDADcAACAIQRhq\
IAUpAwA3AAAgCEEQaiAGKQMANwAAIAhBCGogBykDADcAACABEA8gAEEwNgIEIAAgCDYCACACQcACai\
QAC4gEAQd/IwBBoAFrIgIkACACQTBqQSxqQgA3AgAgAkEwakEkakIANwIAIAJBMGpBHGpCADcCACAC\
QTBqQRRqQgA3AgAgAkEwakEMakIANwIAIAJCADcCNCACQTA2AjAgAkHoAGpBMGogAkEwakEwaigCAD\
YCACACQegAakEoaiACQTBqQShqKQMANwMAIAJB6ABqQSBqIAJBMGpBIGopAwA3AwAgAkHoAGpBGGog\
AkEwakEYaikDADcDACACQegAakEQaiACQTBqQRBqKQMANwMAIAJB6ABqQQhqIAJBMGpBCGopAwA3Aw\
AgAiACKQMwNwNoIAJBKGoiAyACQegAakEsaikCADcDACACQSBqIgQgAkHoAGpBJGopAgA3AwAgAkEY\
aiIFIAJB6ABqQRxqKQIANwMAIAJBEGoiBiACQegAakEUaikCADcDACACQQhqIgcgAkHoAGpBDGopAg\
A3AwAgAiACKQJsNwMAIAEgAhBZIAFBAEHMARCdASEIAkBBMBAJIgENAEEwQQFBACgCvKdAIgJBAiAC\
GxEEAAALIAEgAikDADcAACABQShqIAMpAwA3AAAgAUEgaiAEKQMANwAAIAFBGGogBSkDADcAACABQR\
BqIAYpAwA3AAAgAUEIaiAHKQMANwAAIAhBAEHMARCdARogAEEwNgIEIAAgATYCACACQaABaiQAC4gE\
AQd/IwBBoAFrIgIkACACQTBqQSxqQgA3AgAgAkEwakEkakIANwIAIAJBMGpBHGpCADcCACACQTBqQR\
RqQgA3AgAgAkEwakEMakIANwIAIAJCADcCNCACQTA2AjAgAkHoAGpBMGogAkEwakEwaigCADYCACAC\
QegAakEoaiACQTBqQShqKQMANwMAIAJB6ABqQSBqIAJBMGpBIGopAwA3AwAgAkHoAGpBGGogAkEwak\
EYaikDADcDACACQegAakEQaiACQTBqQRBqKQMANwMAIAJB6ABqQQhqIAJBMGpBCGopAwA3AwAgAiAC\
KQMwNwNoIAJBKGoiAyACQegAakEsaikCADcDACACQSBqIgQgAkHoAGpBJGopAgA3AwAgAkEYaiIFIA\
JB6ABqQRxqKQIANwMAIAJBEGoiBiACQegAakEUaikCADcDACACQQhqIgcgAkHoAGpBDGopAgA3AwAg\
AiACKQJsNwMAIAEgAhBaIAFBAEHMARCdASEIAkBBMBAJIgENAEEwQQFBACgCvKdAIgJBAiACGxEEAA\
ALIAEgAikDADcAACABQShqIAMpAwA3AAAgAUEgaiAEKQMANwAAIAFBGGogBSkDADcAACABQRBqIAYp\
AwA3AAAgAUEIaiAHKQMANwAAIAhBAEHMARCdARogAEEwNgIEIAAgATYCACACQaABaiQAC/QDAQl/Iw\
BBoANrIgIkACACQdgCakEMakIANwIAIAJB2AJqQRRqQgA3AgAgAkHYAmpBHGpCADcCACACQdgCakEk\
akIANwIAIAJB2AJqQSxqQgA3AgAgAkHYAmpBNGpCADcCACACQdgCakE8akIANwIAIAJCADcC3AIgAk\
HAADYC2AIgAkHAAGogAkHYAmpBxAAQlwEaIAJBOGoiAyACQcAAakE8aikCADcDACACQTBqIgQgAkHA\
AGpBNGopAgA3AwAgAkEoaiIFIAJBwABqQSxqKQIANwMAIAJBIGoiBiACQcAAakEkaikCADcDACACQR\
hqIgcgAkHAAGpBHGopAgA3AwAgAkEQaiIIIAJBwABqQRRqKQIANwMAIAJBCGoiCSACQcAAakEMaikC\
ADcDACACIAIpAkQ3AwAgAkHAAGogAUGYAhCXARogAkHAAGogAhBLAkBBwAAQCSIKDQBBwABBAUEAKA\
K8p0AiAkECIAIbEQQAAAsgCiACKQMANwAAIApBOGogAykDADcAACAKQTBqIAQpAwA3AAAgCkEoaiAF\
KQMANwAAIApBIGogBikDADcAACAKQRhqIAcpAwA3AAAgCkEQaiAIKQMANwAAIApBCGogCSkDADcAAC\
ABEA8gAEHAADYCBCAAIAo2AgAgAkGgA2okAAv0AwEJfyMAQaADayICJAAgAkHYAmpBDGpCADcCACAC\
QdgCakEUakIANwIAIAJB2AJqQRxqQgA3AgAgAkHYAmpBJGpCADcCACACQdgCakEsakIANwIAIAJB2A\
JqQTRqQgA3AgAgAkHYAmpBPGpCADcCACACQgA3AtwCIAJBwAA2AtgCIAJBwABqIAJB2AJqQcQAEJcB\
GiACQThqIgMgAkHAAGpBPGopAgA3AwAgAkEwaiIEIAJBwABqQTRqKQIANwMAIAJBKGoiBSACQcAAak\
EsaikCADcDACACQSBqIgYgAkHAAGpBJGopAgA3AwAgAkEYaiIHIAJBwABqQRxqKQIANwMAIAJBEGoi\
CCACQcAAakEUaikCADcDACACQQhqIgkgAkHAAGpBDGopAgA3AwAgAiACKQJENwMAIAJBwABqIAFBmA\
IQlwEaIAJBwABqIAIQSgJAQcAAEAkiCg0AQcAAQQFBACgCvKdAIgJBAiACGxEEAAALIAogAikDADcA\
ACAKQThqIAMpAwA3AAAgCkEwaiAEKQMANwAAIApBKGogBSkDADcAACAKQSBqIAYpAwA3AAAgCkEYai\
AHKQMANwAAIApBEGogCCkDADcAACAKQQhqIAkpAwA3AAAgARAPIABBwAA2AgQgACAKNgIAIAJBoANq\
JAAL9AMBCX8jAEHgAmsiAiQAIAJBmAJqQQxqQgA3AgAgAkGYAmpBFGpCADcCACACQZgCakEcakIANw\
IAIAJBmAJqQSRqQgA3AgAgAkGYAmpBLGpCADcCACACQZgCakE0akIANwIAIAJBmAJqQTxqQgA3AgAg\
AkIANwKcAiACQcAANgKYAiACQcAAaiACQZgCakHEABCXARogAkE4aiIDIAJBwABqQTxqKQIANwMAIA\
JBMGoiBCACQcAAakE0aikCADcDACACQShqIgUgAkHAAGpBLGopAgA3AwAgAkEgaiIGIAJBwABqQSRq\
KQIANwMAIAJBGGoiByACQcAAakEcaikCADcDACACQRBqIgggAkHAAGpBFGopAgA3AwAgAkEIaiIJIA\
JBwABqQQxqKQIANwMAIAIgAikCRDcDACACQcAAaiABQdgBEJcBGiACQcAAaiACEBYCQEHAABAJIgoN\
AEHAAEEBQQAoArynQCICQQIgAhsRBAAACyAKIAIpAwA3AAAgCkE4aiADKQMANwAAIApBMGogBCkDAD\
cAACAKQShqIAUpAwA3AAAgCkEgaiAGKQMANwAAIApBGGogBykDADcAACAKQRBqIAgpAwA3AAAgCkEI\
aiAJKQMANwAAIAEQDyAAQcAANgIEIAAgCjYCACACQeACaiQAC/MDAQl/IwBB0AFrIgIkACACQcAAak\
EMakIANwIAIAJBwABqQRRqQgA3AgAgAkHAAGpBHGpCADcCACACQcAAakEkakIANwIAIAJBwABqQSxq\
QgA3AgAgAkHAAGpBNGpCADcCACACQcAAakE8akIANwIAIAJCADcCRCACQcAANgJAIAJBiAFqIAJBwA\
BqQcQAEJcBGiACQThqIgMgAkGIAWpBPGopAgA3AwAgAkEwaiIEIAJBiAFqQTRqKQIANwMAIAJBKGoi\
BSACQYgBakEsaikCADcDACACQSBqIgYgAkGIAWpBJGopAgA3AwAgAkEYaiIHIAJBiAFqQRxqKQIANw\
MAIAJBEGoiCCACQYgBakEUaikCADcDACACQQhqIgkgAkGIAWpBDGopAgA3AwAgAiACKQKMATcDACAB\
IAIQSiABQQBBzAEQnQEhCgJAQcAAEAkiAQ0AQcAAQQFBACgCvKdAIgJBAiACGxEEAAALIAEgAikDAD\
cAACABQThqIAMpAwA3AAAgAUEwaiAEKQMANwAAIAFBKGogBSkDADcAACABQSBqIAYpAwA3AAAgAUEY\
aiAHKQMANwAAIAFBEGogCCkDADcAACABQQhqIAkpAwA3AAAgCkEAQcwBEJ0BGiAAQcAANgIEIAAgAT\
YCACACQdABaiQAC/MDAQl/IwBB0AFrIgIkACACQcAAakEMakIANwIAIAJBwABqQRRqQgA3AgAgAkHA\
AGpBHGpCADcCACACQcAAakEkakIANwIAIAJBwABqQSxqQgA3AgAgAkHAAGpBNGpCADcCACACQcAAak\
E8akIANwIAIAJCADcCRCACQcAANgJAIAJBiAFqIAJBwABqQcQAEJcBGiACQThqIgMgAkGIAWpBPGop\
AgA3AwAgAkEwaiIEIAJBiAFqQTRqKQIANwMAIAJBKGoiBSACQYgBakEsaikCADcDACACQSBqIgYgAk\
GIAWpBJGopAgA3AwAgAkEYaiIHIAJBiAFqQRxqKQIANwMAIAJBEGoiCCACQYgBakEUaikCADcDACAC\
QQhqIgkgAkGIAWpBDGopAgA3AwAgAiACKQKMATcDACABIAIQSyABQQBBzAEQnQEhCgJAQcAAEAkiAQ\
0AQcAAQQFBACgCvKdAIgJBAiACGxEEAAALIAEgAikDADcAACABQThqIAMpAwA3AAAgAUEwaiAEKQMA\
NwAAIAFBKGogBSkDADcAACABQSBqIAYpAwA3AAAgAUEYaiAHKQMANwAAIAFBEGogCCkDADcAACABQQ\
hqIAkpAwA3AAAgCkEAQcwBEJ0BGiAAQcAANgIEIAAgATYCACACQdABaiQAC/ADAgV/BH4jAEHwAGsi\
AiQAIAJBIGpBHGpCADcCACACQSBqQRRqQgA3AgAgAkEgakEMakIANwIAIAJCADcCJCACQSA2AiAgAk\
HIAGpBIGogAkEgakEgaigCADYCACACQcgAakEYaiACQSBqQRhqKQMANwMAIAJByABqQRBqIAJBIGpB\
EGopAwA3AwAgAkHIAGpBCGogAkEgakEIaikDADcDACACIAIpAyA3A0ggAkEYaiIDIAJByABqQRxqKQ\
IANwMAIAJBEGoiBCACQcgAakEUaikCADcDACACQQhqIgUgAkHIAGpBDGopAgA3AwAgAiACKQJMNwMA\
IAEgAhAuIAFBADYCCCABQgA3AwAgAUEAKQPwm0AiBzcCTCABQdQAakEAKQP4m0AiCDcCACABQdwAak\
EAKQOAnEAiCTcCACABQeQAakEAKQOInEAiCjcCAAJAQSAQCSIGDQBBIEEBQQAoArynQCICQQIgAhsR\
BAAACyAGIAIpAwA3AAAgBkEYaiADKQMANwAAIAZBEGogBCkDADcAACAGQQhqIAUpAwA3AAAgAUEANg\
IIIAFCADcDACABQcwAaiIBIAc3AgAgAUEIaiAINwIAIAFBEGogCTcCACABQRhqIAo3AgAgAEEgNgIE\
IAAgBjYCACACQfAAaiQAC7cDAgF/BH4jAEEgayICJAAgABBIIAJBCGogAEHUAGopAgAiAzcDACACQR\
BqIABB3ABqKQIAIgQ3AwAgAkEYaiAAQeQAaikCACIFNwMAIAEgACkCTCIGpyIAQRh0IABBCHRBgID8\
B3FyIABBCHZBgP4DcSAAQRh2cnI2AAAgASADpyIAQRh0IABBCHRBgID8B3FyIABBCHZBgP4DcSAAQR\
h2cnI2AAggASAEpyIAQRh0IABBCHRBgID8B3FyIABBCHZBgP4DcSAAQRh2cnI2ABAgASAFpyIAQRh0\
IABBCHRBgID8B3FyIABBCHZBgP4DcSAAQRh2cnI2ABggAiAGNwMAIAEgAigCBCIAQRh0IABBCHRBgI\
D8B3FyIABBCHZBgP4DcSAAQRh2cnI2AAQgASACKAIMIgBBGHQgAEEIdEGAgPwHcXIgAEEIdkGA/gNx\
IABBGHZycjYADCABIAIoAhQiAEEYdCAAQQh0QYCA/AdxciAAQQh2QYD+A3EgAEEYdnJyNgAUIAEgAi\
gCHCIAQRh0IABBCHRBgID8B3FyIABBCHZBgP4DcSAAQRh2cnI2ABwgAkEgaiQAC9kDAgV/BH4jAEHg\
AGsiAiQAIAJBIGpBHGpBADYCACACQSBqQRRqQgA3AgAgAkEgakEMakIANwIAIAJCADcCJCACQRw2Ai\
AgAkHAAGpBEGogAkEgakEQaikDADcDACACQcAAakEIaiACQSBqQQhqKQMANwMAIAJBwABqQRhqIAJB\
IGpBGGopAwA3AwAgAkEIaiIDIAJBwABqQQxqKQIANwMAIAJBEGoiBCACQcAAakEUaikCADcDACACQR\
hqIgUgAkHAAGpBHGooAgA2AgAgAiACKQMgNwNAIAIgAikCRDcDACABIAIQPSABQQA2AgggAUIANwMA\
IAFBACkCzJtAIgc3AkwgAUHUAGpBACkC1JtAIgg3AgAgAUHcAGpBACkC3JtAIgk3AgAgAUHkAGpBAC\
kC5JtAIgo3AgACQEEcEAkiBg0AQRxBAUEAKAK8p0AiAkECIAIbEQQAAAsgBiACKQMANwAAIAZBGGog\
BSgCADYAACAGQRBqIAQpAwA3AAAgBkEIaiADKQMANwAAIAFBADYCCCABQgA3AwAgAUHMAGoiASAHNw\
IAIAFBCGogCDcCACABQRBqIAk3AgAgAUEYaiAKNwIAIABBHDYCBCAAIAY2AgAgAkHgAGokAAvCAwEG\
fyMAQdABayICJAAgAkGgAWpBJGpCADcCACACQaABakEcakIANwIAIAJBoAFqQRRqQgA3AgAgAkGgAW\
pBDGpCADcCACACQgA3AqQBIAJBKDYCoAEgAkEoakEoaiACQaABakEoaigCADYCACACQShqQSBqIAJB\
oAFqQSBqKQMANwMAIAJBKGpBGGogAkGgAWpBGGopAwA3AwAgAkEoakEQaiACQaABakEQaikDADcDAC\
ACQShqQQhqIAJBoAFqQQhqKQMANwMAIAIgAikDoAE3AyggAkEgaiIDIAJBKGpBJGopAgA3AwAgAkEY\
aiIEIAJBKGpBHGopAgA3AwAgAkEQaiIFIAJBKGpBFGopAgA3AwAgAkEIaiIGIAJBKGpBDGopAgA3Aw\
AgAiACKQIsNwMAIAJBKGogAUH4ABCXARogAkEoaiACEEkCQEEoEAkiBw0AQShBAUEAKAK8p0AiAkEC\
IAIbEQQAAAsgByACKQMANwAAIAdBIGogAykDADcAACAHQRhqIAQpAwA3AAAgB0EQaiAFKQMANwAAIA\
dBCGogBikDADcAACABEA8gAEEoNgIEIAAgBzYCACACQdABaiQAC9MDAgR/An4gAEEQaiEBIABBCGop\
AwAhBSAAKQMAIQYCQAJAAkACQCAAKAJQIgJBgAFHDQAgASAAQdQAakEBEANBACECIABBADYCUAwBCy\
ACQf8ASw0BCyAAQdQAaiIDIAJqQYABOgAAIAAgACgCUCIEQQFqIgI2AlACQCACQYEBTw0AIABB0ABq\
IAJqQQRqQQBB/wAgBGsQnQEaAkBBgAEgACgCUGtBEE8NACABIANBARADIAAoAlAiAkGBAU8NAyADQQ\
AgAhCdARoLIABBzAFqIAZCOIYgBkIohkKAgICAgIDA/wCDhCAGQhiGQoCAgICA4D+DIAZCCIZCgICA\
gPAfg4SEIAZCCIhCgICA+A+DIAZCGIhCgID8B4OEIAZCKIhCgP4DgyAGQjiIhISENwIAIABBxAFqIA\
VCOIYgBUIohkKAgICAgIDA/wCDhCAFQhiGQoCAgICA4D+DIAVCCIZCgICAgPAfg4SEIAVCCIhCgICA\
+A+DIAVCGIhCgID8B4OEIAVCKIhCgP4DgyAFQjiIhISENwIAIAEgA0EBEAMgAEEANgJQDwsgAkGAAU\
HcncAAEIQBAAsgAkGAAUHsncAAEIcBAAsgAkGAAUH8ncAAEIUBAAuHAwEFfyMAQcABayICJAAgAkGY\
AWpBHGpCADcCACACQZgBakEUakIANwIAIAJBmAFqQQxqQgA3AgAgAkIANwKcASACQSA2ApgBIAJBKG\
pBIGogAkGYAWpBIGooAgA2AgAgAkEoakEYaiACQZgBakEYaikDADcDACACQShqQRBqIAJBmAFqQRBq\
KQMANwMAIAJBKGpBCGogAkGYAWpBCGopAwA3AwAgAiACKQOYATcDKCACQQhqQRhqIgMgAkEoakEcai\
kCADcDACACQQhqQRBqIgQgAkEoakEUaikCADcDACACQQhqQQhqIgUgAkEoakEMaikCADcDACACIAIp\
Aiw3AwggAkEoaiABQfAAEJcBGiACQShqIAJBCGoQLgJAQSAQCSIGDQBBIEEBQQAoArynQCICQQIgAh\
sRBAAACyAGIAIpAwg3AAAgBkEYaiADKQMANwAAIAZBEGogBCkDADcAACAGQQhqIAUpAwA3AAAgARAP\
IABBIDYCBCAAIAY2AgAgAkHAAWokAAv7AgEFfyMAQaADayICJAAgAkH4AmpBHGpCADcCACACQfgCak\
EUakIANwIAIAJB+AJqQQxqQgA3AgAgAkIANwL8AiACQSA2AvgCIAJBIGpBIGogAkH4AmpBIGooAgA2\
AgAgAkEgakEYaiACQfgCakEYaikDADcDACACQSBqQRBqIAJB+AJqQRBqKQMANwMAIAJBIGpBCGogAk\
H4AmpBCGopAwA3AwAgAiACKQP4AjcDICACQRhqIgMgAkEgakEcaikCADcDACACQRBqIgQgAkEgakEU\
aikCADcDACACQQhqIgUgAkEgakEMaikCADcDACACIAIpAiQ3AwAgAkEgaiABQdgCEJcBGiACQSBqIA\
IQZQJAQSAQCSIGDQBBIEEBQQAoArynQCICQQIgAhsRBAAACyAGIAIpAwA3AAAgBkEYaiADKQMANwAA\
IAZBEGogBCkDADcAACAGQQhqIAUpAwA3AAAgARAPIABBIDYCBCAAIAY2AgAgAkGgA2okAAv7AgEFfy\
MAQaADayICJAAgAkH4AmpBHGpCADcCACACQfgCakEUakIANwIAIAJB+AJqQQxqQgA3AgAgAkIANwL8\
AiACQSA2AvgCIAJBIGpBIGogAkH4AmpBIGooAgA2AgAgAkEgakEYaiACQfgCakEYaikDADcDACACQS\
BqQRBqIAJB+AJqQRBqKQMANwMAIAJBIGpBCGogAkH4AmpBCGopAwA3AwAgAiACKQP4AjcDICACQRhq\
IgMgAkEgakEcaikCADcDACACQRBqIgQgAkEgakEUaikCADcDACACQQhqIgUgAkEgakEMaikCADcDAC\
ACIAIpAiQ3AwAgAkEgaiABQdgCEJcBGiACQSBqIAIQZgJAQSAQCSIGDQBBIEEBQQAoArynQCICQQIg\
AhsRBAAACyAGIAIpAwA3AAAgBkEYaiADKQMANwAAIAZBEGogBCkDADcAACAGQQhqIAUpAwA3AAAgAR\
APIABBIDYCBCAAIAY2AgAgAkGgA2okAAv7AgEFfyMAQcAPayICJAAgAkGYD2pBHGpCADcCACACQZgP\
akEUakIANwIAIAJBmA9qQQxqQgA3AgAgAkIANwKcDyACQSA2ApgPIAJBIGpBIGogAkGYD2pBIGooAg\
A2AgAgAkEgakEYaiACQZgPakEYaikDADcDACACQSBqQRBqIAJBmA9qQRBqKQMANwMAIAJBIGpBCGog\
AkGYD2pBCGopAwA3AwAgAiACKQOYDzcDICACQRhqIgMgAkEgakEcaikCADcDACACQRBqIgQgAkEgak\
EUaikCADcDACACQQhqIgUgAkEgakEMaikCADcDACACIAIpAiQ3AwAgAkEgaiABQfgOEJcBGiACIAJB\
IGoQEgJAQSAQCSIGDQBBIEEBQQAoArynQCICQQIgAhsRBAAACyAGIAIpAwA3AAAgBkEYaiADKQMANw\
AAIAZBEGogBCkDADcAACAGQQhqIAUpAwA3AAAgARAPIABBIDYCBCAAIAY2AgAgAkHAD2okAAv6AgEF\
fyMAQfAAayICJAAgAkEgakEcakIANwIAIAJBIGpBFGpCADcCACACQSBqQQxqQgA3AgAgAkIANwIkIA\
JBIDYCICACQcgAakEgaiACQSBqQSBqKAIANgIAIAJByABqQRhqIAJBIGpBGGopAwA3AwAgAkHIAGpB\
EGogAkEgakEQaikDADcDACACQcgAakEIaiACQSBqQQhqKQMANwMAIAIgAikDIDcDSCACQRhqIgMgAk\
HIAGpBHGopAgA3AwAgAkEQaiIEIAJByABqQRRqKQIANwMAIAJBCGoiBSACQcgAakEMaikCADcDACAC\
IAIpAkw3AwAgASACEGUgAUEAQcwBEJ0BIQYCQEEgEAkiAQ0AQSBBAUEAKAK8p0AiAkECIAIbEQQAAA\
sgASACKQMANwAAIAFBGGogAykDADcAACABQRBqIAQpAwA3AAAgAUEIaiAFKQMANwAAIAZBAEHMARCd\
ARogAEEgNgIEIAAgATYCACACQfAAaiQAC/oCAQV/IwBB8ABrIgIkACACQSBqQRxqQgA3AgAgAkEgak\
EUakIANwIAIAJBIGpBDGpCADcCACACQgA3AiQgAkEgNgIgIAJByABqQSBqIAJBIGpBIGooAgA2AgAg\
AkHIAGpBGGogAkEgakEYaikDADcDACACQcgAakEQaiACQSBqQRBqKQMANwMAIAJByABqQQhqIAJBIG\
pBCGopAwA3AwAgAiACKQMgNwNIIAJBGGoiAyACQcgAakEcaikCADcDACACQRBqIgQgAkHIAGpBFGop\
AgA3AwAgAkEIaiIFIAJByABqQQxqKQIANwMAIAIgAikCTDcDACABIAIQZiABQQBBzAEQnQEhBgJAQS\
AQCSIBDQBBIEEBQQAoArynQCICQQIgAhsRBAAACyABIAIpAwA3AAAgAUEYaiADKQMANwAAIAFBEGog\
BCkDADcAACABQQhqIAUpAwA3AAAgBkEAQcwBEJ0BGiAAQSA2AgQgACABNgIAIAJB8ABqJAALjAMBB3\
8jAEGwAWsiAiQAIAJB2ABqQQRyIAFBBGoQYyACIAEoAgA2AlggAkGYAWoiAyABQTxqKQAANwMAIAJB\
kAFqIgQgAUE0aikAADcDACACQYgBaiIFIAFBLGopAAA3AwAgAkHwAGpBEGoiBiABQSRqKQAANwMAIA\
JB8ABqQQhqIgcgAUEcaikAADcDACACIAEpABQ3A3AgAkGgAWoiCCABQcQAahBjIAJBEGogAkHYAGpB\
EGooAgA2AgAgAkEIaiACQdgAakEIaikDADcDACACQRxqIAcpAwA3AgAgAkEkaiAGKQMANwIAIAJBLG\
ogBSkDADcCACACQTRqIAQpAwA3AgAgAkE8aiADKQMANwIAIAJBxABqIAgpAwA3AgAgAkHMAGogAkGo\
AWopAwA3AgAgAiACKQNYNwMAIAIgAikDcDcCFAJAQdQAEAkiAQ0AQdQAQQRBACgCvKdAIgJBAiACGx\
EEAAALIAEgAkHUABCXASEBIABBlJXAADYCBCAAIAE2AgAgAkGwAWokAAvyAgEDfwJAAkACQAJAAkAg\
AC0AaCIDRQ0AIANBwQBPDQMgACADakEoaiABIAJBwAAgA2siAyADIAJLGyIDEJcBGiAAIAAtAGggA2\
oiBDoAaCABIANqIQECQCACIANrIgINAEEAIQIMAgsgAEEIaiAAQShqIgRBwAAgACkDACAALQBqIABB\
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\
AgEFfwJAAkACQAJAAkACQEGIASAAKALIASIDayIEIAJLDQAgAw0BIAEhBQwCCyADIAJqIgUgA0kNAi\
AFQYgBSw0DIABByAFqIANqQQRqIAEgAhCXARogACAAKALIASACajYCyAEPCyADQYkBTw0DIAIgBGsh\
AiABIARqIQUgACADakHMAWogASAEEJcBGkEAIQMDQCAAIANqIgEgAS0AACABQcwBai0AAHM6AAAgA0\
EBaiIDQYgBRw0ACyAAEBMLIAUgAiACQYgBcCIGayICaiEHAkAgAkGIAUkNAANAIAVBiAFqIQQgAkH4\
fmohAkEAIQMDQCAAIANqIgEgAS0AACAFIANqLQAAczoAACADQQFqIgNBiAFHDQALIAAQEyAEIQUgAk\
GIAU8NAAsLIABBzAFqIAcgBhCXARogACAGNgLIAQ8LIAMgBUG8oMAAEIgBAAsgBUGIAUG8oMAAEIUB\
AAsgA0GIAUHMoMAAEIQBAAvkAgEFfyMAQaADayICJAAgAkGAA2pBHGpBADYCACACQYADakEUakIANw\
IAIAJBgANqQQxqQgA3AgAgAkIANwKEAyACQRw2AoADIAJBIGpBEGogAkGAA2pBEGopAwA3AwAgAkEg\
akEIaiACQYADakEIaikDADcDACACQSBqQRhqIAJBgANqQRhqKQMANwMAIAJBCGoiAyACQSBqQQxqKQ\
IANwMAIAJBEGoiBCACQSBqQRRqKQIANwMAIAJBGGoiBSACQSBqQRxqKAIANgIAIAIgAikDgAM3AyAg\
AiACKQIkNwMAIAJBIGogAUHgAhCXARogAkEgaiACEGcCQEEcEAkiBg0AQRxBAUEAKAK8p0AiAkECIA\
IbEQQAAAsgBiACKQMANwAAIAZBGGogBSgCADYAACAGQRBqIAQpAwA3AAAgBkEIaiADKQMANwAAIAEQ\
DyAAQRw2AgQgACAGNgIAIAJBoANqJAAL5AIBBX8jAEGgA2siAiQAIAJBgANqQRxqQQA2AgAgAkGAA2\
pBFGpCADcCACACQYADakEMakIANwIAIAJCADcChAMgAkEcNgKAAyACQSBqQRBqIAJBgANqQRBqKQMA\
NwMAIAJBIGpBCGogAkGAA2pBCGopAwA3AwAgAkEgakEYaiACQYADakEYaikDADcDACACQQhqIgMgAk\
EgakEMaikCADcDACACQRBqIgQgAkEgakEUaikCADcDACACQRhqIgUgAkEgakEcaigCADYCACACIAIp\
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\
3J3AABCEAQALIAJBwABB7J3AABCHAQALIAJBwABB/J3AABCFAQALywICBH8BfiAAQQhqIQIgACkDAC\
EGAkACQAJAAkAgACgCMCIDQcAARw0AIAIgAEE0ahAFQQAhAyAAQQA2AjAMAQsgA0E/Sw0BCyAAQTRq\
IgQgA2pBgAE6AAAgACAAKAIwIgVBAWoiAzYCMAJAIANBwQBPDQAgAEEwaiADakEEakEAQT8gBWsQnQ\
EaAkBBwAAgACgCMGtBCE8NACACIAQQBSAAKAIwIgNBwQBPDQMgBEEAIAMQnQEaCyAAQewAaiAGQgOG\
NwIAIAIgBBAFIABBADYCMCABIAAoAgg2AAAgASAAQQxqKQIANwAEIAEgAEEUaikCADcADCABIABBHG\
opAgA3ABQgASAAQSRqKQIANwAcIAEgAEEsaigCADYAJA8LIANBwABB3J3AABCEAQALIANBwABB7J3A\
ABCHAQALIANBwABB/J3AABCFAQALuQIBA38jAEEQayICJAACQCAAKALIASIDQccASw0AIAAgA2pBzA\
FqQQY6AAACQCADQQFqIgRByABGDQAgACAEakHMAWpBAEHHACADaxCdARoLQQAhAyAAQQA2AsgBIABB\
kwJqIgQgBC0AAEGAAXI6AAADQCAAIANqIgQgBC0AACAEQcwBai0AAHM6AAAgA0EBaiIDQcgARw0ACy\
AAEBMgASAAKQAANwAAIAFBOGogAEE4aikAADcAACABQTBqIABBMGopAAA3AAAgAUEoaiAAQShqKQAA\
NwAAIAFBIGogAEEgaikAADcAACABQRhqIABBGGopAAA3AAAgAUEQaiAAQRBqKQAANwAAIAFBCGogAE\
EIaikAADcAACACQRBqJAAPC0G6n8AAQRcgAkEIakHUn8AAQYyiwAAQfwALuQIBA38jAEEQayICJAAC\
QCAAKALIASIDQccASw0AIAAgA2pBzAFqQQE6AAACQCADQQFqIgRByABGDQAgACAEakHMAWpBAEHHAC\
ADaxCdARoLQQAhAyAAQQA2AsgBIABBkwJqIgQgBC0AAEGAAXI6AAADQCAAIANqIgQgBC0AACAEQcwB\
ai0AAHM6AAAgA0EBaiIDQcgARw0ACyAAEBMgASAAKQAANwAAIAFBOGogAEE4aikAADcAACABQTBqIA\
BBMGopAAA3AAAgAUEoaiAAQShqKQAANwAAIAFBIGogAEEgaikAADcAACABQRhqIABBGGopAAA3AAAg\
AUEQaiAAQRBqKQAANwAAIAFBCGogAEEIaikAADcAACACQRBqJAAPC0G6n8AAQRcgAkEIakHUn8AAQc\
yhwAAQfwALtQIBBX8jAEGgAWsiAiQAIAJBADYCECACQQhqIAJBEGpBBHIgAkHUAGoQqAEgAigCECED\
AkAgAigCDCACKAIIIgRrIgVBwAAgBUHAAEkbIgZFDQAgBiEFA0AgBCABLQAAOgAAIARBAWohBCABQQ\
FqIQEgBUF/aiIFDQALIAIgAyAGaiIDNgIQCwJAIANBP0sNACADQcAAEIkBAAsgAkHYAGogAkEQakHE\
ABCXARogAEE4aiACQZQBaikCADcAACAAQTBqIAJBjAFqKQIANwAAIABBKGogAkGEAWopAgA3AAAgAE\
EgaiACQfwAaikCADcAACAAQRhqIAJB9ABqKQIANwAAIABBEGogAkHsAGopAgA3AAAgAEEIaiACQeQA\
aikCADcAACAAIAIpAlw3AAAgAkGgAWokAAu2AgEIfyMAQfAAayIBQShqIgJCADcDACABQSBqIgNCAD\
cDACABQRhqIgRCADcDACABQRBqIgVCADcDACABQQhqIgZCADcDACABQgA3AwAgAUHAAGpBDGpCADcC\
ACABQgA3AkQgAUEQNgJAIAFB2ABqQRBqIAFBwABqQRBqKAIANgIAIAFB2ABqQQhqIAFBwABqQQhqKQ\
MANwMAIAEgASkDQDcDWCABQThqIgcgAUHYAGpBDGopAgA3AwAgAUEwaiIIIAEpAlw3AwAgAEHMAGog\
BykDADcAACAAQcQAaiAIKQMANwAAIABBPGogAikDADcAACAAQTRqIAMpAwA3AAAgAEEsaiAEKQMANw\
AAIABBJGogBSkDADcAACAAQRxqIAYpAwA3AAAgACABKQMANwAUIABBADYCAAu3AgIFfwF+IwBBwAFr\
IgIkACACQdAAakEIaiIDIAFBEGopAwA3AwAgAkHQAGpBEGoiBCABQRhqKQMANwMAIAJB0ABqQRhqIg\
UgAUEgaikDADcDACACQdAAakEgaiIGIAFBKGopAwA3AwAgAiABKQMINwNQIAEpAwAhByACQfgAakEE\
ciABQTRqEEwgAiABKAIwNgJ4IAJBCGogAkH4AGpBxAAQlwEaAkBB+AAQCSIBDQBB+ABBCEEAKAK8p0\
AiAkECIAIbEQQAAAsgASAHNwMAIAEgAikDUDcDCCABQRBqIAMpAwA3AwAgAUEYaiAEKQMANwMAIAFB\
IGogBSkDADcDACABQShqIAYpAwA3AwAgAUEwaiACQQhqQcQAEJcBGiAAQfCUwAA2AgQgACABNgIAIA\
JBwAFqJAALowICBH8CfiAAIAApAwAiByACrUIDhnwiCDcDACAAQQhqIgMgAykDACAIIAdUrXw3AwAC\
QAJAQYABIAAoAlAiA2siBCACSw0AIABBEGohBQJAIANFDQAgA0GBAU8NAiAAQdQAaiIGIANqIAEgBB\
CXARogAEEANgJQIAUgBkEBEAMgAiAEayECIAEgBGohAQsgBSABIAJBB3YQAyAAQdQAaiABIAJBgH9x\
aiACQf8AcSICEJcBGiAAIAI2AlAPCwJAAkAgAyACaiIEIANJDQAgBEGAAUsNASAAQdAAaiADakEEai\
ABIAIQlwEaIAAgACgCUCACajYCUA8LIAMgBEG8ncAAEIgBAAsgBEGAAUG8ncAAEIUBAAsgA0GAAUHM\
ncAAEIQBAAueAgEEfyAAIAApAwAgAq18NwMAAkACQEHAACAAKAIIIgNrIgQgAksNACAAQcwAaiEFAk\
AgA0UNACADQcEATw0CIABBDGoiBiADaiABIAQQlwEaIAUgBhAMIAIgBGshAiABIARqIQELIAJBP3Eh\
AyABIAJBQHEiAmohBAJAIAJFDQBBACACayECA0AgBSABEAwgAUHAAGohASACQcAAaiICDQALCyAAQQ\
xqIAQgAxCXARogACADNgIIDwsCQAJAIAMgAmoiBSADSQ0AIAVBwABLDQEgAEEIaiADakEEaiABIAIQ\
lwEaIAAgACgCCCACajYCCA8LIAMgBUG8oMAAEIgBAAsgBUHAAEG8oMAAEIUBAAsgA0HAAEHMoMAAEI\
QBAAueAgEEfyAAIAApAwAgAq18NwMAAkACQEHAACAAKAIIIgNrIgQgAksNACAAQcwAaiEFAkAgA0UN\
ACADQcEATw0CIABBDGoiBiADaiABIAQQlwEaIAUgBhAQIAIgBGshAiABIARqIQELIAJBP3EhAyABIA\
JBQHEiAmohBAJAIAJFDQBBACACayECA0AgBSABEBAgAUHAAGohASACQcAAaiICDQALCyAAQQxqIAQg\
AxCXARogACADNgIIDwsCQAJAIAMgAmoiBSADSQ0AIAVBwABLDQEgAEEIaiADakEEaiABIAIQlwEaIA\
AgACgCCCACajYCCA8LIAMgBUG8oMAAEIgBAAsgBUHAAEG8oMAAEIUBAAsgA0HAAEHMoMAAEIQBAAud\
AgEEfyAAIAApAwAgAq18NwMAAkACQEHAACAAKAIcIgNrIgQgAksNACAAQQhqIQUCQCADRQ0AIANBwQ\
BPDQIgAEEgaiIGIANqIAEgBBCXARogBSAGEAYgAiAEayECIAEgBGohAQsgAkE/cSEDIAEgAkFAcSIC\
aiEEAkAgAkUNAEEAIAJrIQIDQCAFIAEQBiABQcAAaiEBIAJBwABqIgINAAsLIABBIGogBCADEJcBGi\
AAIAM2AhwPCwJAAkAgAyACaiIFIANJDQAgBUHAAEsNASAAQRxqIANqQQRqIAEgAhCXARogACAAKAIc\
IAJqNgIcDwsgAyAFQbygwAAQiAEACyAFQcAAQbygwAAQhQEACyADQcAAQcygwAAQhAEAC50CAQR/IA\
AgACkDACACrXw3AwACQAJAQcAAIAAoAjAiA2siBCACSw0AIABBCGohBQJAIANFDQAgA0HBAE8NAiAA\
QTRqIgYgA2ogASAEEJcBGiAFIAYQBSACIARrIQIgASAEaiEBCyACQT9xIQMgASACQUBxIgJqIQQCQC\
ACRQ0AQQAgAmshAgNAIAUgARAFIAFBwABqIQEgAkHAAGoiAg0ACwsgAEE0aiAEIAMQlwEaIAAgAzYC\
MA8LAkACQCADIAJqIgUgA0kNACAFQcAASw0BIABBMGogA2pBBGogASACEJcBGiAAIAAoAjAgAmo2Aj\
APCyADIAVBvKDAABCIAQALIAVBwABBvKDAABCFAQALIANBwABBzKDAABCEAQALpwICA38CfiMAQcAA\
ayICJAAgAkEQakEMakIANwIAIAJCADcCFCACQRA2AhAgAkEoakEQaiACQRBqQRBqKAIANgIAIAJBKG\
pBCGogAkEQakEIaikDADcDACACQQhqIgMgAkEoakEMaikCADcDACACIAIpAxA3AyggAiACKQIsNwMA\
IAEgAhBfIAFBADYCCCABQgA3AwAgAUHUAGpBACkCiJtAIgU3AgAgAUEAKQKAm0AiBjcCTAJAQRAQCS\
IEDQBBEEEBQQAoArynQCICQQIgAhsRBAAACyAEIAIpAwA3AAAgBEEIaiADKQMANwAAIAFBADYCCCAB\
QgA3AwAgAUHMAGoiAUEIaiAFNwIAIAEgBjcCACAAQRA2AgQgACAENgIAIAJBwABqJAALpwICA38Cfi\
MAQcAAayICJAAgAkEQakEMakIANwIAIAJCADcCFCACQRA2AhAgAkEoakEQaiACQRBqQRBqKAIANgIA\
IAJBKGpBCGogAkEQakEIaikDADcDACACQQhqIgMgAkEoakEMaikCADcDACACIAIpAxA3AyggAiACKQ\
IsNwMAIAEgAhBgIAFBADYCCCABQgA3AwAgAUHUAGpBACkCiJtAIgU3AgAgAUEAKQKAm0AiBjcCTAJA\
QRAQCSIEDQBBEEEBQQAoArynQCICQQIgAhsRBAAACyAEIAIpAwA3AAAgBEEIaiADKQMANwAAIAFBAD\
YCCCABQgA3AwAgAUHMAGoiAUEIaiAFNwIAIAEgBjcCACAAQRA2AgQgACAENgIAIAJBwABqJAALmgIB\
BH8jAEGQAWsiAiQAIAJB+ABqQRRqQQA2AgAgAkH4AGpBDGpCADcCACACQgA3AnwgAkEUNgJ4IAJBGG\
pBEGogAkH4AGpBEGopAwA3AwAgAkEYakEIaiACQfgAakEIaikDADcDACACQQhqIgMgAkEYakEMaikC\
ADcDACACQRBqIgQgAkEYakEUaigCADYCACACIAIpA3g3AxggAiACKQIcNwMAIAJBGGogAUHgABCXAR\
ogAkEYaiACECACQEEUEAkiBQ0AQRRBAUEAKAK8p0AiAkECIAIbEQQAAAsgBSACKQMANwAAIAVBEGog\
BCgCADYAACAFQQhqIAMpAwA3AAAgARAPIABBFDYCBCAAIAU2AgAgAkGQAWokAAuaAgEEfyMAQZABay\
ICJAAgAkH4AGpBFGpBADYCACACQfgAakEMakIANwIAIAJCADcCfCACQRQ2AnggAkEYakEQaiACQfgA\
akEQaikDADcDACACQRhqQQhqIAJB+ABqQQhqKQMANwMAIAJBCGoiAyACQRhqQQxqKQIANwMAIAJBEG\
oiBCACQRhqQRRqKAIANgIAIAIgAikDeDcDGCACIAIpAhw3AwAgAkEYaiABQeAAEJcBGiACQRhqIAIQ\
WAJAQRQQCSIFDQBBFEEBQQAoArynQCICQQIgAhsRBAAACyAFIAIpAwA3AAAgBUEQaiAEKAIANgAAIA\
VBCGogAykDADcAACABEA8gAEEUNgIEIAAgBTYCACACQZABaiQAC6QCAgR/AX4gAEEIaiECIAApAwAh\
BgJAAkACQAJAIAAoAhwiA0HAAEcNACACIABBIGoQBkEAIQMgAEEANgIcDAELIANBP0sNAQsgAEEgai\
IEIANqQYABOgAAIAAgACgCHCIFQQFqIgM2AhwCQCADQcEATw0AIABBHGogA2pBBGpBAEE/IAVrEJ0B\
GgJAQcAAIAAoAhxrQQhPDQAgAiAEEAYgACgCHCIDQcEATw0DIARBACADEJ0BGgsgAEHYAGogBkIDhj\
cDACACIAQQBiAAQQA2AhwgASAAKAIINgAAIAEgAEEMaikCADcABCABIABBFGopAgA3AAwPCyADQcAA\
QdydwAAQhAEACyADQcAAQeydwAAQhwEACyADQcAAQfydwAAQhQEAC5kCAQN/IwBBEGsiAiQAAkAgAC\
gCyAEiA0HnAEsNACAAIANqQcwBakEBOgAAAkAgA0EBaiIEQegARg0AIAAgBGpBzAFqQQBB5wAgA2sQ\
nQEaC0EAIQMgAEEANgLIASAAQbMCaiIEIAQtAABBgAFyOgAAA0AgACADaiIEIAQtAAAgBEHMAWotAA\
BzOgAAIANBAWoiA0HoAEcNAAsgABATIAEgACkAADcAACABQShqIABBKGopAAA3AAAgAUEgaiAAQSBq\
KQAANwAAIAFBGGogAEEYaikAADcAACABQRBqIABBEGopAAA3AAAgAUEIaiAAQQhqKQAANwAAIAJBEG\
okAA8LQbqfwABBFyACQQhqQdSfwABBvKHAABB/AAuZAgEDfyMAQRBrIgIkAAJAIAAoAsgBIgNB5wBL\
DQAgACADakHMAWpBBjoAAAJAIANBAWoiBEHoAEYNACAAIARqQcwBakEAQecAIANrEJ0BGgtBACEDIA\
BBADYCyAEgAEGzAmoiBCAELQAAQYABcjoAAANAIAAgA2oiBCAELQAAIARBzAFqLQAAczoAACADQQFq\
IgNB6ABHDQALIAAQEyABIAApAAA3AAAgAUEoaiAAQShqKQAANwAAIAFBIGogAEEgaikAADcAACABQR\
hqIABBGGopAAA3AAAgAUEQaiAAQRBqKQAANwAAIAFBCGogAEEIaikAADcAACACQRBqJAAPC0G6n8AA\
QRcgAkEIakHUn8AAQfyhwAAQfwALhQIBBH8CQAJAQRAgACgCACIDayIEIAJLDQAgAEEUaiEFAkAgA0\
UNACADQRFPDQIgAEEEaiIGIANqIAEgBBCXARogBSAGEA0gAiAEayECIAEgBGohAQsgAkEPcSEDIAEg\
AkFwcSICaiEEAkAgAkUNAEEAIAJrIQIDQCAFIAEQDSABQRBqIQEgAkEQaiICDQALCyAAQQRqIAQgAx\
CXARogACADNgIADwsCQAJAIAMgAmoiBSADSQ0AIAVBEEsNASAAIANqQQRqIAEgAhCXARogACAAKAIA\
IAJqNgIADwsgAyAFQbygwAAQiAEACyAFQRBBvKDAABCFAQALIANBEEHMoMAAEIQBAAukAgICfwJ+Iw\
BBkAJrIgIkACABQQhqKQMAIQQgASkDACEFIAJBiAFqQQRyIAFB1ABqEG0gAiABKAJQNgKIASACIAJB\
iAFqQYQBEJcBIQMCQEHYARAJIgINAEHYAUEIQQAoArynQCIBQQIgARsRBAAACyACIAU3AwAgAiAENw\
MIIAIgASkDEDcDECACQRhqIAFBGGopAwA3AwAgAkEgaiABQSBqKQMANwMAIAJBKGogAUEoaikDADcD\
ACACQTBqIAFBMGopAwA3AwAgAkE4aiABQThqKQMANwMAIAJBwABqIAFBwABqKQMANwMAIAJByABqIA\
FByABqKQMANwMAIAJB0ABqIANBhAEQlwEaIABBuJXAADYCBCAAIAI2AgAgA0GQAmokAAukAgICfwJ+\
IwBBkAJrIgIkACABQQhqKQMAIQQgASkDACEFIAJBiAFqQQRyIAFB1ABqEG0gAiABKAJQNgKIASACIA\
JBiAFqQYQBEJcBIQMCQEHYARAJIgINAEHYAUEIQQAoArynQCIBQQIgARsRBAAACyACIAU3AwAgAiAE\
NwMIIAIgASkDEDcDECACQRhqIAFBGGopAwA3AwAgAkEgaiABQSBqKQMANwMAIAJBKGogAUEoaikDAD\
cDACACQTBqIAFBMGopAwA3AwAgAkE4aiABQThqKQMANwMAIAJBwABqIAFBwABqKQMANwMAIAJByABq\
IAFByABqKQMANwMAIAJB0ABqIANBhAEQlwEaIABB3JXAADYCBCAAIAI2AgAgA0GQAmokAAuDAgEEfy\
AAIAApAwAgAq1CA4Z8NwMAAkACQEHAACAAKAIIIgNrIgQgAksNACAAQcwAaiEFAkAgA0UNACADQcEA\
Tw0CIABBDGoiBiADaiABIAQQlwEaIABBADYCCCAFIAZBARAEIAIgBGshAiABIARqIQELIAUgASACQQ\
Z2EAQgAEEMaiABIAJBQHFqIAJBP3EiAhCXARogACACNgIIDwsCQAJAIAMgAmoiBCADSQ0AIARBwABL\
DQEgAEEIaiADakEEaiABIAIQlwEaIAAgACgCCCACajYCCA8LIAMgBEG8ncAAEIgBAAsgBEHAAEG8nc\
AAEIUBAAsgA0HAAEHMncAAEIQBAAuZAgIEfwF+IABBzABqIQIgACkDACEGAkACQAJAAkAgACgCCCID\
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\
AgAgA0GQAWokAAvSAQICfwF+IwBBkAFrIgIkACABKQMAIQQgAkHIAGpBBHIgAUEMahBMIAIgASgCCD\
YCSCACIAJByABqQcQAEJcBIQMCQEHwABAJIgINAEHwAEEIQQAoArynQCIBQQIgARsRBAAACyACIAQ3\
AwAgAkEIaiADQcQAEJcBGiACQeQAaiABQeQAaikCADcCACACQdwAaiABQdwAaikCADcCACACQdQAai\
ABQdQAaikCADcCACACIAEpAkw3AkwgAEGYk8AANgIEIAAgAjYCACADQZABaiQAC64BAgJ/AX4jAEGQ\
AWsiAiQAIAEpAwAhBCACQcgAakEEciABQQxqEEwgAiABKAIINgJIIAIgAkHIAGpBxAAQlwEhAwJAQe\
AAEAkiAg0AQeAAQQhBACgCvKdAIgFBAiABGxEEAAALIAIgBDcDACACQQhqIANBxAAQlwEaIAJB1ABq\
IAFB1ABqKQIANwIAIAIgASkCTDcCTCAAQbyTwAA2AgQgACACNgIAIANBkAFqJAALrgECAn8BfiMAQZ\
ABayICJAAgASkDACEEIAJByABqQQRyIAFBDGoQTCACIAEoAgg2AkggAiACQcgAakHEABCXASEDAkBB\
4AAQCSICDQBB4ABBCEEAKAK8p0AiAUECIAEbEQQAAAsgAiAENwMAIAJBCGogA0HEABCXARogAkHUAG\
ogAUHUAGopAgA3AgAgAiABKQJMNwJMIABBhJTAADYCBCAAIAI2AgAgA0GQAWokAAuYAQEBf0EAIQMC\
QAJAIAFBAEgNAAJAAkACQAJAAkAgAigCACIDRQ0AAkAgAigCBA0AIAENAgwECyADIAEQFSECDAILIA\
FFDQILIAEQCSECCwJAIAJFDQAgASEDDAILIAAgATYCBEEBIQMMAgtBASECQQAhAwsgACACNgIEQQAh\
AQwBC0EBIQELIAAgATYCACAAQQhqIAM2AgALmgEBAX8jAEGwA2siAiQAIAJBCGogAUHIARCXARogAk\
HAAmpBBHIgAUHMAWoQcSACIAEoAsgBNgLAAiACQQhqQcgBaiACQcACakHsABCXARoCQEG4AhAJIgEN\
AEG4AkEIQQAoArynQCICQQIgAhsRBAAACyABIAJBCGpBuAIQlwEhASAAQdSQwAA2AgQgACABNgIAIA\
JBsANqJAALmgEBAX8jAEHwA2siAiQAIAJBCGogAUHIARCXARogAkHgAmpBBHIgAUHMAWoQbyACIAEo\
AsgBNgLgAiACQQhqQcgBaiACQeACakGMARCXARoCQEHYAhAJIgENAEHYAkEIQQAoArynQCICQQIgAh\
sRBAAACyABIAJBCGpB2AIQlwEhASAAQfiQwAA2AgQgACABNgIAIAJB8ANqJAALmgEBAX8jAEHwAmsi\
AiQAIAJBCGogAUHIARCXARogAkGgAmpBBHIgAUHMAWoQbiACIAEoAsgBNgKgAiACQQhqQcgBaiACQa\
ACakHMABCXARoCQEGYAhAJIgENAEGYAkEIQQAoArynQCICQQIgAhsRBAAACyABIAJBCGpBmAIQlwEh\
ASAAQZyRwAA2AgQgACABNgIAIAJB8AJqJAALmgEBAX8jAEGABGsiAiQAIAJBCGogAUHIARCXARogAk\
HoAmpBBHIgAUHMAWoQcCACIAEoAsgBNgLoAiACQQhqQcgBaiACQegCakGUARCXARoCQEHgAhAJIgEN\
AEHgAkEIQQAoArynQCICQQIgAhsRBAAACyABIAJBCGpB4AIQlwEhASAAQcCRwAA2AgQgACABNgIAIA\
JBgARqJAALmgEBAX8jAEGwA2siAiQAIAJBCGogAUHIARCXARogAkHAAmpBBHIgAUHMAWoQcSACIAEo\
AsgBNgLAAiACQQhqQcgBaiACQcACakHsABCXARoCQEG4AhAJIgENAEG4AkEIQQAoArynQCICQQIgAh\
sRBAAACyABIAJBCGpBuAIQlwEhASAAQeSRwAA2AgQgACABNgIAIAJBsANqJAALmgEBAX8jAEGABGsi\
AiQAIAJBCGogAUHIARCXARogAkHoAmpBBHIgAUHMAWoQcCACIAEoAsgBNgLoAiACQQhqQcgBaiACQe\
gCakGUARCXARoCQEHgAhAJIgENAEHgAkEIQQAoArynQCICQQIgAhsRBAAACyABIAJBCGpB4AIQlwEh\
ASAAQYiSwAA2AgQgACABNgIAIAJBgARqJAALmgEBAX8jAEHwA2siAiQAIAJBCGogAUHIARCXARogAk\
HgAmpBBHIgAUHMAWoQbyACIAEoAsgBNgLgAiACQQhqQcgBaiACQeACakGMARCXARoCQEHYAhAJIgEN\
AEHYAkEIQQAoArynQCICQQIgAhsRBAAACyABIAJBCGpB2AIQlwEhASAAQaySwAA2AgQgACABNgIAIA\
JB8ANqJAALmgEBAX8jAEHwAmsiAiQAIAJBCGogAUHIARCXARogAkGgAmpBBHIgAUHMAWoQbiACIAEo\
AsgBNgKgAiACQQhqQcgBaiACQaACakHMABCXARoCQEGYAhAJIgENAEGYAkEIQQAoArynQCICQQIgAh\
sRBAAACyABIAJBCGpBmAIQlwEhASAAQdCSwAA2AgQgACABNgIAIAJB8AJqJAALfwEBfyMAQcAAayIF\
JAAgBSABNgIMIAUgADYCCCAFIAM2AhQgBSACNgIQIAVBLGpBAjYCACAFQTxqQQQ2AgAgBUICNwIcIA\
VB4I/AADYCGCAFQQE2AjQgBSAFQTBqNgIoIAUgBUEQajYCOCAFIAVBCGo2AjAgBUEYaiAEEJsBAAt+\
AQJ/IwBBMGsiAiQAIAJBFGpBATYCACACQfSLwAA2AhAgAkEBNgIMIAJB7IvAADYCCCABQRxqKAIAIQ\
MgASgCGCEBIAJBLGpBAjYCACACQgI3AhwgAkHgj8AANgIYIAIgAkEIajYCKCABIAMgAkEYahAbIQEg\
AkEwaiQAIAELfgECfyMAQTBrIgIkACACQRRqQQE2AgAgAkH0i8AANgIQIAJBATYCDCACQeyLwAA2Ag\
ggAUEcaigCACEDIAEoAhghASACQSxqQQI2AgAgAkICNwIcIAJB4I/AADYCGCACIAJBCGo2AiggASAD\
IAJBGGoQGyEBIAJBMGokACABC44BACAAQgA3AwggAEIANwMAIABBADYCUCAAQQApA9CcQDcDECAAQR\
hqQQApA9icQDcDACAAQSBqQQApA+CcQDcDACAAQShqQQApA+icQDcDACAAQTBqQQApA/CcQDcDACAA\
QThqQQApA/icQDcDACAAQcAAakEAKQOAnUA3AwAgAEHIAGpBACkDiJ1ANwMAC44BACAAQgA3AwggAE\
IANwMAIABBADYCUCAAQQApA5CcQDcDECAAQRhqQQApA5icQDcDACAAQSBqQQApA6CcQDcDACAAQShq\
QQApA6icQDcDACAAQTBqQQApA7CcQDcDACAAQThqQQApA7icQDcDACAAQcAAakEAKQPAnEA3AwAgAE\
HIAGpBACkDyJxANwMAC20BAX8jAEEwayIDJAAgAyABNgIEIAMgADYCACADQRxqQQI2AgAgA0EsakEF\
NgIAIANCAjcCDCADQYiPwAA2AgggA0EFNgIkIAMgA0EgajYCGCADIANBBGo2AiggAyADNgIgIANBCG\
ogAhCbAQALbQEBfyMAQTBrIgMkACADIAE2AgQgAyAANgIAIANBHGpBAjYCACADQSxqQQU2AgAgA0IC\
NwIMIANBxI7AADYCCCADQQU2AiQgAyADQSBqNgIYIAMgA0EEajYCKCADIAM2AiAgA0EIaiACEJsBAA\
ttAQF/IwBBMGsiAyQAIAMgATYCBCADIAA2AgAgA0EcakECNgIAIANBLGpBBTYCACADQgM3AgwgA0H0\
j8AANgIIIANBBTYCJCADIANBIGo2AhggAyADNgIoIAMgA0EEajYCICADQQhqIAIQmwEAC20BAX8jAE\
EwayIDJAAgAyABNgIEIAMgADYCACADQRxqQQI2AgAgA0EsakEFNgIAIANCAjcCDCADQaiMwAA2Aggg\
A0EFNgIkIAMgA0EgajYCGCADIAM2AiggAyADQQRqNgIgIANBCGogAhCbAQALbQEBfyMAQTBrIgMkAC\
ADIAE2AgQgAyAANgIAIANBHGpBAjYCACADQSxqQQU2AgAgA0ICNwIMIANBrI/AADYCCCADQQU2AiQg\
AyADQSBqNgIYIAMgA0EEajYCKCADIAM2AiAgA0EIaiACEJsBAAtwAQF/IwBBMGsiAiQAIAIgATYCBC\
ACIAA2AgAgAkEcakECNgIAIAJBLGpBBTYCACACQgI3AgwgAkGAlsAANgIIIAJBBTYCJCACIAJBIGo2\
AhggAiACQQRqNgIoIAIgAjYCICACQQhqQZCWwAAQmwEAC2wAIABCADcDACAAIAApA3A3AwggAEEgai\
AAQYgBaikDADcDACAAQRhqIABBgAFqKQMANwMAIABBEGogAEH4AGopAwA3AwAgAEEoakEAQcIAEJ0B\
GgJAIABB8A5qIgAtAABFDQAgAEEAOgAACwt2AQJ/QQEhAEEAQQAoAuijQCIBQQFqNgLoo0ACQAJAQQ\
AoArCnQEEBRw0AQQAoArSnQEEBaiEADAELQQBBATYCsKdAC0EAIAA2ArSnQAJAIAFBAEgNACAAQQJL\
DQBBACgCuKdAQX9MDQAgAEEBSw0AEMQBAAsAC2MBAX8jAEEgayICJAAgAiAAKAIANgIEIAJBCGpBEG\
ogAUEQaikCADcDACACQQhqQQhqIAFBCGopAgA3AwAgAiABKQIANwMIIAJBBGpBjIfAACACQQhqEBsh\
ASACQSBqJAAgAQtlAgF/AX4jAEEQayICJAACQAJAIAFFDQAgASgCAA0BIAFBfzYCACACQQhqIAEoAg\
QgAUEIaigCACgCEBEEACACKQMIIQMgAUEANgIAIAAgAzcDACACQRBqJAAPCxCxAQALELIBAAtRAQJ/\
AkAgACgCACIDQQRqKAIAIANBCGoiBCgCACIAayACTw0AIAMgACACEGwgBCgCACEACyADKAIAIABqIA\
EgAhCXARogBCAAIAJqNgIAQQALSgEDf0EAIQMCQCACRQ0AAkADQCAALQAAIgQgAS0AACIFRw0BIABB\
AWohACABQQFqIQEgAkF/aiICRQ0CDAALCyAEIAVrIQMLIAMLUQECfwJAAkAgAEUNACAAKAIADQEgAE\
EANgIAIAAoAgQhASAAKAIIIQIgABAPIAEgAigCABEBAAJAIAIoAgRFDQAgARAPCw8LELEBAAsQsgEA\
C04AAkACQCAARQ0AIAAoAgANASAAQX82AgAgACgCBCABIAIgAEEIaigCACgCDBEGAAJAIAJFDQAgAR\
APCyAAQQA2AgAPCxCxAQALELIBAAtUAQF/AkACQAJAIAFBgIDEAEYNAEEBIQQgACgCGCABIABBHGoo\
AgAoAhARBQANAQsgAg0BQQAhBAsgBA8LIAAoAhggAiADIABBHGooAgAoAgwRBwALWAAgAEIANwMAIA\
BBADYCMCAAQQApA5CbQDcDCCAAQRBqQQApA5ibQDcDACAAQRhqQQApA6CbQDcDACAAQSBqQQApA6ib\
QDcDACAAQShqQQApA7CbQDcDAAtIAQF/IwBBIGsiAyQAIANBFGpBADYCACADQZyiwAA2AhAgA0IBNw\
IEIAMgATYCHCADIAA2AhggAyADQRhqNgIAIAMgAhCbAQALTAAgAEEANgIIIABCADcDACAAQQApA/Cb\
QDcCTCAAQdQAakEAKQP4m0A3AgAgAEHcAGpBACkDgJxANwIAIABB5ABqQQApA4icQDcCAAtMACAAQQ\
A2AgggAEIANwMAIABBACkCzJtANwJMIABB1ABqQQApAtSbQDcCACAAQdwAakEAKQLcm0A3AgAgAEHk\
AGpBACkC5JtANwIACzYBAX8CQCACRQ0AIAAhAwNAIAMgAS0AADoAACABQQFqIQEgA0EBaiEDIAJBf2\
oiAg0ACwsgAAs5AQN/IwBBEGsiASQAIAAoAgwhAiAAKAIIEKUBIQMgASACNgIIIAEgADYCBCABIAM2\
AgAgARCcAQALOgAgAEEANgIcIABCADcDACAAQRhqQQAoAsibQDYCACAAQRBqQQApA8CbQDcDACAAQQ\
ApA7ibQDcDCAs6ACAAQgA3AwAgAEEANgIcIABBACkDuJtANwMIIABBEGpBACkDwJtANwMAIABBGGpB\
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\
aWIucnMAAAAgBBAASQAAAAsCAAAKAAAAIAQQAEkAAAA5AgAACQAAACAEEABJAAAArgIAABkAAAAgBB\
AASQAAALACAAAJAAAAIAQQAEkAAACwAgAAOAAAAGFzc2VydGlvbiBmYWlsZWQ6IG1pZCA8PSBzZWxm\
LmxlbigpABwPEABNAAAA4wUAAAkAAAAgBBAASQAAAIMCAAAJAAAAIAQQAEkAAACKAgAACgAAACAEEA\
BJAAAAmgMAADIAAAAgBBAASQAAAFUEAAAWAAAAIAQQAEkAAABnBAAAFgAAACAEEABJAAAAmAQAABIA\
AAAgBBAASQAAAKIEAAASAAAABgAAAAQAAAAEAAAAbQAAAIAFEABLAAAAzQAAACAAAAB+Ly5jYXJnby\
9yZWdpc3RyeS9zcmMvZ2l0aHViLmNvbS0xZWNjNjI5OWRiOWVjODIzL2FycmF5dmVjLTAuNS4yL3Ny\
Yy9saWIucnMABgAAACAAAAABAAAAbgAAAAYAAAAEAAAABAAAAG0AAAARBhAADQAAAPwFEAAVAAAAaW\
5zdWZmaWNpZW50IGNhcGFjaXR5Q2FwYWNpdHlFcnJvclBhZEVycm9yAABIBhAAIAAAAGgGEAASAAAA\
BgAAAAAAAAABAAAAbwAAAGluZGV4IG91dCBvZiBib3VuZHM6IHRoZSBsZW4gaXMgIGJ1dCB0aGUgaW\
5kZXggaXMgMDAwMTAyMDMwNDA1MDYwNzA4MDkxMDExMTIxMzE0MTUxNjE3MTgxOTIwMjEyMjIzMjQy\
NTI2MjcyODI5MzAzMTMyMzMzNDM1MzYzNzM4Mzk0MDQxNDI0MzQ0NDU0NjQ3NDg0OTUwNTE1MjUzNT\
Q1NTU2NTc1ODU5NjA2MTYyNjM2NDY1NjY2NzY4Njk3MDcxNzI3Mzc0NzU3Njc3Nzg3OTgwODE4Mjgz\
ODQ4NTg2ODc4ODg5OTA5MTkyOTM5NDk1OTY5Nzk4OTkAAFQHEAAQAAAAZAcQACIAAAByYW5nZSBlbm\
QgaW5kZXggIG91dCBvZiByYW5nZSBmb3Igc2xpY2Ugb2YgbGVuZ3RoIAAAmAcQABIAAABkBxAAIgAA\
AHJhbmdlIHN0YXJ0IGluZGV4IAAAvAcQABYAAADSBxAADQAAAHNsaWNlIGluZGV4IHN0YXJ0cyBhdC\
AgYnV0IGVuZHMgYXQgABwREAAAAAAA8AcQAAIAAAA6ICkADAgQABUAAAAhCBAAKwAAAPIHEAABAAAA\
c291cmNlIHNsaWNlIGxlbmd0aCAoKSBkb2VzIG5vdCBtYXRjaCBkZXN0aW5hdGlvbiBzbGljZSBsZW\
5ndGggKEVycm9yAAAABgAAADgBAAAIAAAASgAAAEsAAABMAAAATQAAAE4AAABPAAAABgAAAFgBAAAI\
AAAARAAAAFkAAABaAAAARwAAAEgAAABbAAAABgAAABgBAAAIAAAAUAAAAFEAAABSAAAAUwAAAFQAAA\
BVAAAABgAAAGABAAAIAAAAPgAAAD8AAABAAAAAQQAAAEIAAABDAAAABgAAADgBAAAIAAAASgAAAFwA\
AABdAAAATQAAAE4AAABeAAAABgAAAGABAAAIAAAAPgAAAFYAAABXAAAAQQAAAEIAAABYAAAABgAAAF\
gBAAAIAAAARAAAAEUAAABGAAAARwAAAEgAAABJAAAABgAAABgBAAAIAAAAUAAAAF8AAABgAAAAUwAA\
AFQAAABhAAAABgAAAHAAAAAIAAAAKAAAAC4AAAAvAAAAMAAAADEAAAAyAAAABgAAAHAAAAAIAAAAKA\
AAACkAAAAqAAAAKwAAACwAAAAtAAAABgAAAGAAAAAIAAAAEwAAABQAAAAVAAAAEAAAABEAAAAWAAAA\
YgAAAHgHAAAIAAAAYwAAAGQAAABlAAAAZgAAAGcAAABoAAAABgAAAGAAAAAIAAAADQAAAA4AAAAPAA\
AAEAAAABEAAAASAAAABgAAAGAAAAAIAAAAIwAAACQAAAAlAAAAJgAAABsAAAAnAAAABgAAAGAAAAAI\
AAAAFwAAABgAAAAZAAAAGgAAABsAAAAcAAAABgAAAHgAAAAIAAAAHQAAAB4AAAAfAAAAIAAAACEAAA\
AiAAAABgAAAFQAAAAEAAAABwAAAAgAAAAJAAAACgAAAAsAAAAMAAAABgAAANgAAAAIAAAAMwAAADkA\
AAA6AAAAOwAAADwAAAA9AAAABgAAANgAAAAIAAAAMwAAADQAAAA1AAAANgAAADcAAAA4AAAAIAsQAC\
EAAABBCxAAFwAAAGkPEABRAAAAZwEAAAUAAABHZW5lcmljQXJyYXk6OmZyb21faXRlciByZWNlaXZl\
ZCAgZWxlbWVudHMgYnV0IGV4cGVjdGVkIAEAAAAAAAAAgoAAAAAAAACKgAAAAAAAgACAAIAAAACAi4\
AAAAAAAAABAACAAAAAAIGAAIAAAACACYAAAAAAAICKAAAAAAAAAIgAAAAAAAAACYAAgAAAAAAKAACA\
AAAAAIuAAIAAAAAAiwAAAAAAAICJgAAAAAAAgAOAAAAAAACAAoAAAAAAAICAAAAAAAAAgAqAAAAAAA\
AACgAAgAAAAICBgACAAAAAgICAAAAAAACAAQAAgAAAAAAIgACAAAAAgCkuQ8mi2HwBPTZUoezwBhNi\
pwXzwMdzjJiTK9m8TILKHptXPP3U4BZnQm8YihflEr5OxNbant5JoPv1jrsv7nqpaHmRFbIHP5TCEI\
kLIl8hgH9dmlqQMic1Psznv/eXA/8ZMLNIpbXR116SKqxWqsZPuDjSlqR9tnb8a+KcdATxRZ1wWWRx\
hyCGW89l5i2oAhtgJa2usLn2HEZhaTRAfg9VR6Mj3VGvOsNc+c66xeomLFMNboUohAnT3830QYFNUm\
rcN8hswav6JOF7CAy9sUp4iJWL42PobenL1f47AB058u+3DmZY0OSmd3L463VLCjFEULSP7R8a25mN\
M58RgxR+Ly5jYXJnby9yZWdpc3RyeS9zcmMvZ2l0aHViLmNvbS0xZWNjNjI5OWRiOWVjODIzL21kMi\
0wLjkuMC9zcmMvbGliLnJzAAAGAAAAAAAAAAEAAABwAAAAGA0QAEYAAABvAAAADgAAAAEjRWeJq83v\
/ty6mHZUMhABI0VniavN7/7cuph2VDIQ8OHSwxAyVHaYutz+782riWdFIwEPHi08ASNFZ4mrze/+3L\
qYdlQyEPDh0sPYngXBB9V8NhfdcDA5WQ73MQvA/xEVWGinj/lkpE/6vgAAAABn5glqha5nu3Lzbjw6\
9U+lf1IOUYxoBZur2YMfGc3gW9ieBcFdnbvLB9V8NiopmmIX3XAwWgFZkTlZDvfY7C8VMQvA/2cmM2\
cRFVhoh0q0jqeP+WQNLgzbpE/6vh1ItUcIybzzZ+YJajunyoSFrme7K/iU/nLzbjzxNh1fOvVPpdGC\
5q1/Ug5RH2w+K4xoBZtrvUH7q9mDH3khfhMZzeBbY2FsbGVkIGBSZXN1bHQ6OnVud3JhcCgpYCBvbi\
BhbiBgRXJyYCB2YWx1ZQBcEBAATwAAADoAAAANAAAAXBAQAE8AAABBAAAADQAAAFwQEABPAAAAhwAA\
ABcAAABcEBAATwAAAIQAAAAJAAAAXBAQAE8AAACLAAAAGwAAABwPEABNAAAA8gsAAA0AAAAvcnVzdG\
MvYTE3OGQwMzIyY2UyMGUzM2VhYzEyNDc1OGU4MzdjYmQ4MGE2ZjYzMy9saWJyYXJ5L2NvcmUvc3Jj\
L3NsaWNlL21vZC5yc34vLmNhcmdvL3JlZ2lzdHJ5L3NyYy9naXRodWIuY29tLTFlY2M2Mjk5ZGI5ZW\
M4MjMvZ2VuZXJpYy1hcnJheS0wLjE0LjQvc3JjL2xpYi5yc3dlIG5ldmVyIHVzZSBpbnB1dF9sYXp5\
AAAABgAAAAAAAAABAAAAcAAAAPQPEABHAAAAQQAAAAEAAAB+Ly5jYXJnby9yZWdpc3RyeS9zcmMvZ2\
l0aHViLmNvbS0xZWNjNjI5OWRiOWVjODIzL3NoYTMtMC45LjEvc3JjL2xpYi5ycwBcEBAATwAAABsA\
AAANAAAAXBAQAE8AAAAiAAAADQAAAH4vLmNhcmdvL3JlZ2lzdHJ5L3NyYy9naXRodWIuY29tLTFlY2\
M2Mjk5ZGI5ZWM4MjMvYmxvY2stYnVmZmVyLTAuOS4wL3NyYy9saWIucnMA9A8QAEcAAABIAAAAAQAA\
APQPEABHAAAATwAAAAEAAAD0DxAARwAAAFYAAAABAAAA9A8QAEcAAABmAAAAAQAAAPQPEABHAAAAbQ\
AAAAEAAAD0DxAARwAAAHQAAAABAAAA9A8QAEcAAAB7AAAAAQAAAGNhbGxlZCBgT3B0aW9uOjp1bndy\
YXAoKWAgb24gYSBgTm9uZWAgdmFsdWUAWBEQABwAAAACAgAAHgAAAGxpYnJhcnkvc3RkL3NyYy9wYW\
5pY2tpbmcucnMEAAAAAAAAAG51bGwgcG9pbnRlciBwYXNzZWQgdG8gcnVzdHJlY3Vyc2l2ZSB1c2Ug\
b2YgYW4gb2JqZWN0IGRldGVjdGVkIHdoaWNoIHdvdWxkIGxlYWQgdG8gdW5zYWZlIGFsaWFzaW5nIG\
luIHJ1c3QAp+WAgAAEbmFtZQGc5YCAAMcBADZ3YXNtX2JpbmRnZW46Ol9fd2JpbmRnZW5fc3RyaW5n\
X25ldzo6aDk1MTJkZTNiOWQ2NWIxNTgBMXdhc21fYmluZGdlbjo6X193YmluZGdlbl90aHJvdzo6aD\
FhNWVkZDZmZGYyMDYzNTkCM3dhc21fYmluZGdlbjo6X193YmluZGdlbl9yZXRocm93OjpoNTlmYWI0\
ZjY4MTEwNzZjMAMvc2hhMjo6c2hhNTEyOjpzb2Z0Ojpjb21wcmVzczo6aDUzOWRiOTRlNDcyMjc2NW\
MEL3NoYTI6OnNoYTI1Njo6c29mdDo6Y29tcHJlc3M6OmgwNWRhNDk4NTljYjY4Mzk4BTZyaXBlbWQz\
MjA6OmJsb2NrOjpwcm9jZXNzX21zZ19ibG9jazo6aGZmOWRjNjlmZmVmNzc0OGYGNnJpcGVtZDE2MD\
o6YmxvY2s6OnByb2Nlc3NfbXNnX2Jsb2NrOjpoZTc3ZDhjNTkzYWQ2YzBhNQcLY3JlYXRlX2hhc2gI\
K3NoYTE6OmNvbXByZXNzOjpjb21wcmVzczo6aGRhOWE5ZTQ5MzA4YzVhYzMJOmRsbWFsbG9jOjpkbG\
1hbGxvYzo6RGxtYWxsb2M8QT46Om1hbGxvYzo6aDQ3Nzk3YTUxNjJmOWYwNjcKNmJsYWtlMzo6cG9y\
dGFibGU6OmNvbXByZXNzX2luX3BsYWNlOjpoNjM1OTAzMGE5YjcxZGU0Ngs/PEQgYXMgZGlnZXN0Oj\
pkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Ojp1cGRhdGU6OmgyMGQ2ZGRkNjI1ZTU1OGM4DCdtZDU6OnV0\
aWxzOjpjb21wcmVzczo6aDhkMTI1ZDk1OWI3MTU5OTkNL21kMjo6TWQyU3RhdGU6OnByb2Nlc3NfYm\
xvY2s6OmhkODQxNTk3NWZjODg2MzNlDjBibGFrZTM6OmNvbXByZXNzX3N1YnRyZWVfd2lkZTo6aGJl\
MmRlNjg2ZmFhNWI2MDcPOGRsbWFsbG9jOjpkbG1hbGxvYzo6RGxtYWxsb2M8QT46OmZyZWU6OmhlMW\
IwZmJjYTNmZmQ0YjExEC9tZDQ6Ok1kNFN0YXRlOjpwcm9jZXNzX2Jsb2NrOjpoY2ViZGM4YjA0ODA0\
OGI3YhFBZGxtYWxsb2M6OmRsbWFsbG9jOjpEbG1hbGxvYzxBPjo6ZGlzcG9zZV9jaHVuazo6aGI0OD\
hiZGM5ZTE0MDNiNWQSK2JsYWtlMzo6SGFzaGVyOjpmaW5hbGl6ZTo6aDU2NGRjYTRkYmIzODkzNTET\
IGtlY2Nhazo6ZjE2MDA6Omg0NzcxYjVhZGMxODA0YmFkFCxjb3JlOjpmbXQ6OkZvcm1hdHRlcjo6cG\
FkOjpoOTdkZjJiY2Y2YzIzNDBiMBUOX19ydXN0X3JlYWxsb2MWYTxzaGEyOjpzaGE1MTI6OlNoYTUx\
MiBhcyBkaWdlc3Q6OmZpeGVkOjpGaXhlZE91dHB1dERpcnR5Pjo6ZmluYWxpemVfaW50b19kaXJ0eT\
o6aGYwOTMwYzY2MDQ0NjFlZGMXMWJsYWtlMzo6SGFzaGVyOjptZXJnZV9jdl9zdGFjazo6aDU0YjNm\
ZDJjNTcyZTdmN2MYRzxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxpem\
VfcmVzZXQ6OmgwMTA1YzMyNjNkMDkyYWY3GUc8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRp\
Z2VzdD46OmZpbmFsaXplX3Jlc2V0OjpoZWUxMDdiMDYwZmVmZGE3MhpHPEQgYXMgZGlnZXN0OjpkeW\
5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW5hbGl6ZV9yZXNldDo6aDdhNTBiZDZhMzEzZWJmNDkbI2Nv\
cmU6OmZtdDo6d3JpdGU6OmhlNGIyY2QxOWQxMjFhMzk5HDVjb3JlOjpmbXQ6OkZvcm1hdHRlcjo6cG\
FkX2ludGVncmFsOjpoOTNkNDQxMTdlMGQwMzU3Mh1hPHNoYTI6OnNoYTUxMjo6U2hhMzg0IGFzIGRp\
Z2VzdDo6Zml4ZWQ6OkZpeGVkT3V0cHV0RGlydHk+OjpmaW5hbGl6ZV9pbnRvX2RpcnR5OjpoMTU0Mj\
lmNDMwYzYwMmZlNx5CPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Ojpib3hfY2xv\
bmU6OmhhZjU4YTZlZDY5ZjA5MmUwH0c8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD\
46OmZpbmFsaXplX3Jlc2V0OjpoY2VjYjI0YWIzMjUwYzU5MCBXPHNoYTE6OlNoYTEgYXMgZGlnZXN0\
OjpmaXhlZDo6Rml4ZWRPdXRwdXREaXJ0eT46OmZpbmFsaXplX2ludG9fZGlydHk6OmhiOGU4NzczNj\
A0NjljMDQ3ITRibGFrZTM6OmNvbXByZXNzX3BhcmVudHNfcGFyYWxsZWw6Omg4NDQ3MzE4NWFkN2M4\
Zjk2Ikc8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmZpbmFsaXplX3Jlc2V0Oj\
poYzhiNjVhZmRjOTE3ZWE2MCNBPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Ojpm\
aW5hbGl6ZTo6aGFmZWZiYTJmMjQzOWY5YjQkQTxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRG\
lnZXN0Pjo6ZmluYWxpemU6OmhiOGI4ZDAwMjRiYzk1NzFmJUE8RCBhcyBkaWdlc3Q6OmR5bl9kaWdl\
c3Q6OkR5bkRpZ2VzdD46OmZpbmFsaXplOjpoMWU4YzgwNTI5ZmQ3YzM1MiZHPEQgYXMgZGlnZXN0Oj\
pkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW5hbGl6ZV9yZXNldDo6aDU3MzYyZWEwODNkYTlkNjIn\
RzxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxpemVfcmVzZXQ6OmhmY2\
FlMzNmNWU3MWJhNGI2KEE8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmZpbmFs\
aXplOjpoNjk0MDY5N2ViMWU4NWM0NSlBPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3\
Q+OjpmaW5hbGl6ZTo6aGZiMWY1ZjIwMGE3YmEwOGUqQTxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6\
RHluRGlnZXN0Pjo6ZmluYWxpemU6OmgyN2NhYWI3NGE2NzZlNzUzK0c8RCBhcyBkaWdlc3Q6OmR5bl\
9kaWdlc3Q6OkR5bkRpZ2VzdD46OmZpbmFsaXplX3Jlc2V0OjpoMjc3ZWVlYmQ3OWQwMjkzZSxHPEQg\
YXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW5hbGl6ZV9yZXNldDo6aGEwZmMwMW\
Q5Zjc0OTNkYjEtRzxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxpemVf\
cmVzZXQ6OmgzM2Y3ODMxYjgzOTc4MTdkLmE8c2hhMjo6c2hhMjU2OjpTaGEyNTYgYXMgZGlnZXN0Oj\
pmaXhlZDo6Rml4ZWRPdXRwdXREaXJ0eT46OmZpbmFsaXplX2ludG9fZGlydHk6OmhkZDIxZjc3MjM0\
ODk1NmI4L0c8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmZpbmFsaXplX3Jlc2\
V0OjpoMzhlM2Y5NzU3N2Q3NTQzZjBBPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+\
OjpmaW5hbGl6ZTo6aDc3MTE3ODRjNjNmODhlODUxMnNoYTI6OnNoYTUxMjo6RW5naW5lNTEyOjpmaW\
5pc2g6Omg3MWIwMTI3Y2NmYmJkMDY0MkE8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2Vz\
dD46OmZpbmFsaXplOjpoYjkwZDlmYTgwZjBmMTkxMzNBPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0Oj\
pEeW5EaWdlc3Q+OjpmaW5hbGl6ZTo6aGI0N2FjMDIyNjRjNGU5MTQ0QTxEIGFzIGRpZ2VzdDo6ZHlu\
X2RpZ2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxpemU6OmhmZDZiNDRhZGRiN2VmMGE1NUE8RCBhcyBkaW\
dlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmZpbmFsaXplOjpoNWFkOTUzYTFmOGFlMGNmNjZH\
PEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW5hbGl6ZV9yZXNldDo6aGI0MT\
g5NmY5NzA5YTVmNGY3RzxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxp\
emVfcmVzZXQ6OmhiNzgxOGI0NDM0OWJkNzRkOEI8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bk\
RpZ2VzdD46OmJveF9jbG9uZTo6aGU4OGZiY2Q3MmU2YjZiY2Q5LWJsYWtlMzo6Q2h1bmtTdGF0ZTo6\
dXBkYXRlOjpoZmE4NjhkYjJhNzg0YmE1ZDo7PCZtdXQgVyBhcyBjb3JlOjpmbXQ6OldyaXRlPjo6d3\
JpdGVfY2hhcjo6aDE2NjQzMWY5ZGM3OTAzNDY7RzxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHlu\
RGlnZXN0Pjo6ZmluYWxpemVfcmVzZXQ6OmhhM2M4MmVmMWRlNzlkOTIzPEc8RCBhcyBkaWdlc3Q6Om\
R5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmZpbmFsaXplX3Jlc2V0OjpoZGRjNjI1NzI2YzY0Nzg2OT1h\
PHNoYTI6OnNoYTI1Njo6U2hhMjI0IGFzIGRpZ2VzdDo6Zml4ZWQ6OkZpeGVkT3V0cHV0RGlydHk+Oj\
pmaW5hbGl6ZV9pbnRvX2RpcnR5OjpoNDljYmQ1ODA2NDhjMGRiMT4/PEQgYXMgZGlnZXN0OjpkeW5f\
ZGlnZXN0OjpEeW5EaWdlc3Q+Ojp1cGRhdGU6OmgwMDMxNWM4OTE4OThmZTRlPz88RCBhcyBkaWdlc3\
Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OnVwZGF0ZTo6aDA1ZmJkMzM0YTJlNzhmZTlAPzxEIGFz\
IGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6dXBkYXRlOjpoNTg0NDRkN2I5YzMzYjIzYk\
E/PEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Ojp1cGRhdGU6Omg3Yzg4MmU2MzM2\
ZDc2OWUyQkE8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmZpbmFsaXplOjpoYj\
VlN2MxODVhZTQ4NmM5MENBPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW5h\
bGl6ZTo6aGY2MTlhNzljODJkODAyMDREQTxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZX\
N0Pjo6ZmluYWxpemU6Omg0OGRhMzkwMjY5ZWRmYWU4RUc8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6\
OkR5bkRpZ2VzdD46OmZpbmFsaXplX3Jlc2V0OjpoNWFmZjIyMTc4MmU1NTY1NUZHPEQgYXMgZGlnZX\
N0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW5hbGl6ZV9yZXNldDo6aGM5ZDhkZTc1MjVmODMy\
YmVHL2NvcmU6OmZtdDo6bnVtOjppbXA6OmZtdF91NjQ6Omg3MWU2MjRjMmQzOWI3NzFlSDJzaGEyOj\
pzaGEyNTY6OkVuZ2luZTI1Njo6ZmluaXNoOjpoZGI4ZGU2N2Q2MmExZmQzN0lhPHJpcGVtZDMyMDo6\
UmlwZW1kMzIwIGFzIGRpZ2VzdDo6Zml4ZWQ6OkZpeGVkT3V0cHV0RGlydHk+OjpmaW5hbGl6ZV9pbn\
RvX2RpcnR5OjpoYWEzM2ZiNTE5NGIwNmJkNUpbPHNoYTM6OlNoYTNfNTEyIGFzIGRpZ2VzdDo6Zml4\
ZWQ6OkZpeGVkT3V0cHV0RGlydHk+OjpmaW5hbGl6ZV9pbnRvX2RpcnR5OjpoMjEzODY2NmM4Y2UzZD\
IyZktcPHNoYTM6OktlY2NhazUxMiBhcyBkaWdlc3Q6OmZpeGVkOjpGaXhlZE91dHB1dERpcnR5Pjo6\
ZmluYWxpemVfaW50b19kaXJ0eTo6aGZmNDc3MWJhY2I4ZWRhNTJMbmdlbmVyaWNfYXJyYXk6OmltcG\
xzOjo8aW1wbCBjb3JlOjpjbG9uZTo6Q2xvbmUgZm9yIGdlbmVyaWNfYXJyYXk6OkdlbmVyaWNBcnJh\
eTxULE4+Pjo6Y2xvbmU6OmhiY2MzNzAzOGUyMDU0ZTZjTT48RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3\
Q6OkR5bkRpZ2VzdD46OnJlc2V0OjpoZjlmNWVkZGIyOTQzOGRiOU5CPEQgYXMgZGlnZXN0OjpkeW5f\
ZGlnZXN0OjpEeW5EaWdlc3Q+Ojpib3hfY2xvbmU6Omg5ZDY5YzBkMTZhZjE2ODk0Tz88RCBhcyBkaW\
dlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OnVwZGF0ZTo6aDZjNzQ3MDQ3ZTBiOTlhZTRQPzxE\
IGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6dXBkYXRlOjpoYzc0NWM2OGZiMjUzZm\
M3NVE/PEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Ojp1cGRhdGU6OmgwYWVmYjE2\
NGE0OGFhYjkzUj88RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OnVwZGF0ZTo6aD\
hhNzU4MTA3YTE1YTY5ODhTPzxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6dXBk\
YXRlOjpoZTZjYTA1YjBlMDIzMmFmMVRHPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3\
Q+OjpmaW5hbGl6ZV9yZXNldDo6aGU0NDA4NTFjOThmY2M1MGVVRzxEIGFzIGRpZ2VzdDo6ZHluX2Rp\
Z2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxpemVfcmVzZXQ6Omg0YzM2MDA0ZmI2NmU0MDhiVkE8RCBhcy\
BkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmZpbmFsaXplOjpoNDdiYzc5NzYwZDQxYTlh\
N1dBPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpmaW5hbGl6ZTo6aDRhOTAzNj\
YwYTliYWFjMzJYYTxyaXBlbWQxNjA6OlJpcGVtZDE2MCBhcyBkaWdlc3Q6OmZpeGVkOjpGaXhlZE91\
dHB1dERpcnR5Pjo6ZmluYWxpemVfaW50b19kaXJ0eTo6aDVjYzU1ZjUzZDJiMjEzZThZXDxzaGEzOj\
pLZWNjYWszODQgYXMgZGlnZXN0OjpmaXhlZDo6Rml4ZWRPdXRwdXREaXJ0eT46OmZpbmFsaXplX2lu\
dG9fZGlydHk6Omg4N2JkZWM5MTM2MmJhY2QxWls8c2hhMzo6U2hhM18zODQgYXMgZGlnZXN0OjpmaX\
hlZDo6Rml4ZWRPdXRwdXREaXJ0eT46OmZpbmFsaXplX2ludG9fZGlydHk6Omg3ZDIxZjkwMzRlZmI5\
OGUwWz88RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OnVwZGF0ZTo6aDhiM2RkYj\
AyYTI2ZjU0OTZcQjxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6Ym94X2Nsb25l\
OjpoM2Q4Zjk4NjQ5MWE5MjM3Zl1CPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Oj\
pib3hfY2xvbmU6OmhkZmQ4MDFlYTc1NzU5M2VlXj88RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5\
bkRpZ2VzdD46OnVwZGF0ZTo6aDE0YWFiMjYyYmU3NGM3ZTFfVTxtZDU6Ok1kNSBhcyBkaWdlc3Q6Om\
ZpeGVkOjpGaXhlZE91dHB1dERpcnR5Pjo6ZmluYWxpemVfaW50b19kaXJ0eTo6aGY5MTE3ZDBmZDdm\
YTU4MGRgVTxtZDQ6Ok1kNCBhcyBkaWdlc3Q6OmZpeGVkOjpGaXhlZE91dHB1dERpcnR5Pjo6ZmluYW\
xpemVfaW50b19kaXJ0eTo6aGQ0YmE5ZDg3ZTU0NGIxZjFhQTxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2Vz\
dDo6RHluRGlnZXN0Pjo6ZmluYWxpemU6OmgzNGFiMTMzODRjNzExOTg1Yj88RCBhcyBkaWdlc3Q6Om\
R5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OnVwZGF0ZTo6aDY0YTk2NWM0ODQ5NzJmODdjbmdlbmVyaWNf\
YXJyYXk6OmltcGxzOjo8aW1wbCBjb3JlOjpjbG9uZTo6Q2xvbmUgZm9yIGdlbmVyaWNfYXJyYXk6Ok\
dlbmVyaWNBcnJheTxULE4+Pjo6Y2xvbmU6OmhlZDc4NGMxZGEyZDI3MmRkZFw8c2hhMzo6S2VjY2Fr\
MjI0IGFzIGRpZ2VzdDo6Zml4ZWQ6OkZpeGVkT3V0cHV0RGlydHk+OjpmaW5hbGl6ZV9pbnRvX2Rpcn\
R5OjpoZGVhNjQ2N2NhY2FlYTRhOGVcPHNoYTM6OktlY2NhazI1NiBhcyBkaWdlc3Q6OmZpeGVkOjpG\
aXhlZE91dHB1dERpcnR5Pjo6ZmluYWxpemVfaW50b19kaXJ0eTo6aDg0OGMwM2QxMTMwMzk5YTFmWz\
xzaGEzOjpTaGEzXzI1NiBhcyBkaWdlc3Q6OmZpeGVkOjpGaXhlZE91dHB1dERpcnR5Pjo6ZmluYWxp\
emVfaW50b19kaXJ0eTo6aGNjYTRlZWM0Y2ZhZjJjYzlnWzxzaGEzOjpTaGEzXzIyNCBhcyBkaWdlc3\
Q6OmZpeGVkOjpGaXhlZE91dHB1dERpcnR5Pjo6ZmluYWxpemVfaW50b19kaXJ0eTo6aDNmM2FkZGY5\
YWMzYjU5ZTVoQTxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6ZmluYWxpemU6Om\
hmZjE0ZDM4OThhYjY3NWUwaUE8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmZp\
bmFsaXplOjpoODM5YWQzNDA5YzMxNTM3N2pCPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaW\
dlc3Q+Ojpib3hfY2xvbmU6Omg2MjMyOTlhNjZmZDk5N2Ywa0I8RCBhcyBkaWdlc3Q6OmR5bl9kaWdl\
c3Q6OkR5bkRpZ2VzdD46OmJveF9jbG9uZTo6aDQ4ZDg3NWU4NTc4MTkzMmFsTmFsbG9jOjpyYXdfdm\
VjOjpSYXdWZWM8VCxBPjo6cmVzZXJ2ZTo6ZG9fcmVzZXJ2ZV9hbmRfaGFuZGxlOjpoOGUwMzQxOTEz\
OWYxOWFlY21uZ2VuZXJpY19hcnJheTo6aW1wbHM6OjxpbXBsIGNvcmU6OmNsb25lOjpDbG9uZSBmb3\
IgZ2VuZXJpY19hcnJheTo6R2VuZXJpY0FycmF5PFQsTj4+OjpjbG9uZTo6aDE2OGZhMDUxYWU1Nzgy\
MWVubmdlbmVyaWNfYXJyYXk6OmltcGxzOjo8aW1wbCBjb3JlOjpjbG9uZTo6Q2xvbmUgZm9yIGdlbm\
VyaWNfYXJyYXk6OkdlbmVyaWNBcnJheTxULE4+Pjo6Y2xvbmU6Omg2MjUyYWFkYTRjZmZhNzRkb25n\
ZW5lcmljX2FycmF5OjppbXBsczo6PGltcGwgY29yZTo6Y2xvbmU6OkNsb25lIGZvciBnZW5lcmljX2\
FycmF5OjpHZW5lcmljQXJyYXk8VCxOPj46OmNsb25lOjpoN2U1NDJiNDc1YWYwMTQxNXBuZ2VuZXJp\
Y19hcnJheTo6aW1wbHM6OjxpbXBsIGNvcmU6OmNsb25lOjpDbG9uZSBmb3IgZ2VuZXJpY19hcnJheT\
o6R2VuZXJpY0FycmF5PFQsTj4+OjpjbG9uZTo6aGFhNDRjZDZiYTc1MmMyZmFxbmdlbmVyaWNfYXJy\
YXk6OmltcGxzOjo8aW1wbCBjb3JlOjpjbG9uZTo6Q2xvbmUgZm9yIGdlbmVyaWNfYXJyYXk6Okdlbm\
VyaWNBcnJheTxULE4+Pjo6Y2xvbmU6OmhkYzYzOGNkNDllYjFjNjQ5ckI8RCBhcyBkaWdlc3Q6OmR5\
bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmJveF9jbG9uZTo6aDRhMjcwZTFlODQxOTdiMjJzQjxEIGFzIG\
RpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6Ym94X2Nsb25lOjpoYjZjNjY3ZjVkZTc0Yjll\
N3RCPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Ojpib3hfY2xvbmU6OmhhMWFmYj\
AzNmMxOTllYTc1dUI8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmJveF9jbG9u\
ZTo6aDRmZDk3ODU5MGViZmM1NjV2LmFsbG9jOjpyYXdfdmVjOjpmaW5pc2hfZ3Jvdzo6aDEzMTVlOD\
YxMzZkOTc3Yjh3QjxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6Ym94X2Nsb25l\
OjpoMWE3MTExMzkwMDg2OGNkMXhCPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Oj\
pib3hfY2xvbmU6OmgyMTczMzdhYWE0MmFjZTk3eUI8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5\
bkRpZ2VzdD46OmJveF9jbG9uZTo6aDI3M2RjYWUwMjJhYzZhMTl6QjxEIGFzIGRpZ2VzdDo6ZHluX2\
RpZ2VzdDo6RHluRGlnZXN0Pjo6Ym94X2Nsb25lOjpoOWQ4OGQyODQyNWQyMWFiZXtCPEQgYXMgZGln\
ZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Ojpib3hfY2xvbmU6OmhiZjc1ZTczNDUwZmNmMDNmfE\
I8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OmJveF9jbG9uZTo6aGMyY2NlMTRi\
ODQ2MTRiYzh9QjxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6Ym94X2Nsb25lOj\
poYzU2Yjg3MWU5NzFiYmFkMH5CPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Ojpi\
b3hfY2xvbmU6OmhjNzRjMmFjNDhlMWE1OWFify5jb3JlOjpyZXN1bHQ6OnVud3JhcF9mYWlsZWQ6Om\
hlODdjNGRhNDg3NDZlODk2gAFQPGFycmF5dmVjOjplcnJvcnM6OkNhcGFjaXR5RXJyb3I8VD4gYXMg\
Y29yZTo6Zm10OjpEZWJ1Zz46OmZtdDo6aDg2N2MxM2QzM2EzYzg5ZDOBAVA8YXJyYXl2ZWM6OmVycm\
9yczo6Q2FwYWNpdHlFcnJvcjxUPiBhcyBjb3JlOjpmbXQ6OkRlYnVnPjo6Zm10OjpoZmFkZjA2MzY2\
NDc1Y2Q3M4IBPjxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6cmVzZXQ6OmgxYj\
dkMjMxNzFlYWM2YjE3gwE+PEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpyZXNl\
dDo6aDUzZGFjNDVkNTRlMWZhMGGEAUFjb3JlOjpzbGljZTo6aW5kZXg6OnNsaWNlX3N0YXJ0X2luZG\
V4X2xlbl9mYWlsOjpoNzA4NjA1YmI4ZmViZDJmNIUBP2NvcmU6OnNsaWNlOjppbmRleDo6c2xpY2Vf\
ZW5kX2luZGV4X2xlbl9mYWlsOjpoN2VmYjBmMDBmYmNjOTI4YoYBTmNvcmU6OnNsaWNlOjo8aW1wbC\
BbVF0+Ojpjb3B5X2Zyb21fc2xpY2U6Omxlbl9taXNtYXRjaF9mYWlsOjpoYzFkMThmZTFkNTg1YzNl\
MYcBNmNvcmU6OnBhbmlja2luZzo6cGFuaWNfYm91bmRzX2NoZWNrOjpoYWFlYzg4OWJhMThkZDY4NY\
gBPWNvcmU6OnNsaWNlOjppbmRleDo6c2xpY2VfaW5kZXhfb3JkZXJfZmFpbDo6aDk5OGU2MDViNGFm\
OTRiN2KJATdnZW5lcmljX2FycmF5Ojpmcm9tX2l0ZXJfbGVuZ3RoX2ZhaWw6Omg0MjliY2M1ZDVkZm\
FjNDhhigE+PEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpyZXNldDo6aGJkZmZj\
NjJjMjcwNjhiZjWLATdzdGQ6OnBhbmlja2luZzo6cnVzdF9wYW5pY193aXRoX2hvb2s6OmgyZDkwNz\
k0MjdhMmQ5OTZhjAE6PCZtdXQgVyBhcyBjb3JlOjpmbXQ6OldyaXRlPjo6d3JpdGVfZm10OjpoMWE2\
YjAxMTg4NzJlMGRiYo0BC2RpZ2VzdF9oYXNojgE6PCZtdXQgVyBhcyBjb3JlOjpmbXQ6OldyaXRlPj\
o6d3JpdGVfc3RyOjpoZWEyOGQzYjg3Njk1ZDMwZo8BBm1lbWNtcJABE19fd2JnX2Rlbm9oYXNoX2Zy\
ZWWRAQt1cGRhdGVfaGFzaJIBQ2NvcmU6OmZtdDo6Rm9ybWF0dGVyOjpwYWRfaW50ZWdyYWw6OndyaX\
RlX3ByZWZpeDo6aDQ3ZmE5MWE3YWZmOTRmNWKTAT48RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5\
bkRpZ2VzdD46OnJlc2V0OjpoMGFkOGM4NDA2Mzk4OGJiOZQBKWNvcmU6OnBhbmlja2luZzo6cGFuaW\
M6OmgzOGNhYzcxMGI1MDQ4Y2EwlQE+PEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+\
OjpyZXNldDo6aDNlMWUwYzRmNjQwNDc1OTGWAT48RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bk\
RpZ2VzdD46OnJlc2V0OjpoYzMyYzYwNzZkOGZkMGQ2OZcBBm1lbWNweZgBEXJ1c3RfYmVnaW5fdW53\
aW5kmQE+PEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpyZXNldDo6aDU3YWUyNm\
IwMzcxNzg1YzeaAT48RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46OnJlc2V0Ojpo\
YjgxZmYyMzJhMDZjM2JjMZsBLWNvcmU6OnBhbmlja2luZzo6cGFuaWNfZm10OjpoMWZlYTYyMzc1NW\
ZmZmVkN5wBSXN0ZDo6c3lzX2NvbW1vbjo6YmFja3RyYWNlOjpfX3J1c3RfZW5kX3Nob3J0X2JhY2t0\
cmFjZTo6aDkxZTcxMTYwN2Q5MWJlNTKdAQZtZW1zZXSeARFfX3diaW5kZ2VuX21hbGxvY58BPjxEIG\
FzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6cmVzZXQ6OmhhODA3YTcxYjdkMTY1MGQ0\
oAFDc3RkOjpwYW5pY2tpbmc6OmJlZ2luX3BhbmljX2hhbmRsZXI6Ont7Y2xvc3VyZX19OjpoNGU0OW\
YzNTBkOWY0ZGUzNqEBEl9fd2JpbmRnZW5fcmVhbGxvY6IBO2NvcmU6OnB0cjo6ZHJvcF9pbl9wbGFj\
ZTxibGFrZTM6Okhhc2hlcj46OmhmY2Q1OGMwZDU3Mjc0YjBiowFFPGJsb2NrX3BhZGRpbmc6OlBhZE\
Vycm9yIGFzIGNvcmU6OmZtdDo6RGVidWc+OjpmbXQ6Omg2MjE0NGM2NGE1Y2MzOThlpAE+PGNvcmU6\
OmZtdDo6RXJyb3IgYXMgY29yZTo6Zm10OjpEZWJ1Zz46OmZtdDo6aDliOTQ0ODY4ZWM2ZjFjNWOlAT\
Jjb3JlOjpvcHRpb246Ok9wdGlvbjxUPjo6dW53cmFwOjpoNTg4NDZlYTljYjc2NjZmMaYBMDwmVCBh\
cyBjb3JlOjpmbXQ6OkRlYnVnPjo6Zm10OjpoZDYwY2EzZmU0ODAwZTNjZacBMjwmVCBhcyBjb3JlOj\
pmbXQ6OkRpc3BsYXk+OjpmbXQ6OmhhYjhjZDIyOWI5ZTIwMmM4qAFOPEkgYXMgY29yZTo6aXRlcjo6\
dHJhaXRzOjpjb2xsZWN0OjpJbnRvSXRlcmF0b3I+OjppbnRvX2l0ZXI6Omg1Y2YxYjdmMDliYWExNz\
cxqQEPX193YmluZGdlbl9mcmVlqgE0YWxsb2M6OnJhd192ZWM6OmNhcGFjaXR5X292ZXJmbG93Ojpo\
ZDYxMmU3ZWZhMTJjMzdkZqsBOWNvcmU6Om9wczo6ZnVuY3Rpb246OkZuT25jZTo6Y2FsbF9vbmNlOj\
poZGRlOTUzNDE1ODJlOGEyYawBPjxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6\
cmVzZXQ6OmgwODNlNjNiYzBjNTQ3NTBhrQE+PEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaW\
dlc3Q+OjpyZXNldDo6aDNjZjc1ZTA0MTNmZDBkMTOuAT48RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6\
OkR5bkRpZ2VzdD46OnJlc2V0OjpoNDI2NmVjMDdiNjkyMTUxMa8BPjxEIGFzIGRpZ2VzdDo6ZHluX2\
RpZ2VzdDo6RHluRGlnZXN0Pjo6cmVzZXQ6OmhjODJjZGE3ZDVlNDZlNWM4sAEfX193YmluZGdlbl9h\
ZGRfdG9fc3RhY2tfcG9pbnRlcrEBMXdhc21fYmluZGdlbjo6X19ydDo6dGhyb3dfbnVsbDo6aDUwY2\
EyNjg0N2U4NGVlNmGyATJ3YXNtX2JpbmRnZW46Ol9fcnQ6OmJvcnJvd19mYWlsOjpoOGJhMWFmZDdl\
OTcyZGRkObMBTmNvcmU6OmZtdDo6bnVtOjppbXA6OjxpbXBsIGNvcmU6OmZtdDo6RGlzcGxheSBmb3\
IgdTMyPjo6Zm10OjpoZGM0MTczNmM1M2ZjNzk3NLQBKndhc21fYmluZGdlbjo6dGhyb3dfc3RyOjpo\
NzZiMTdjYTcxNDY1NjQ3OLUBKndhc21fYmluZGdlbjo6dGhyb3dfdmFsOjpoMmVkMWZiNGI0YTBhNz\
Q3ZrYBMTxUIGFzIGNvcmU6OmFueTo6QW55Pjo6dHlwZV9pZDo6aDJkNDcxYjk2YmM0Y2JjZmO3AUQ8\
RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46Om91dHB1dF9zaXplOjpoMDU4Y2E3OT\
M1NWJlM2E5MbgBRDxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6b3V0cHV0X3Np\
emU6Omg0NDQzMjc2ZmU0ODk5ZTk4uQFEPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3\
Q+OjpvdXRwdXRfc2l6ZTo6aDUzZWQwMzk5YTIyOTNhYze6AUQ8RCBhcyBkaWdlc3Q6OmR5bl9kaWdl\
c3Q6OkR5bkRpZ2VzdD46Om91dHB1dF9zaXplOjpoOTAyNzVhZWVmMGQwZDAyZbsBRDxEIGFzIGRpZ2\
VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6b3V0cHV0X3NpemU6OmhkZTBlZTFkNTZiYTM0NThm\
vAFEPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+OjpvdXRwdXRfc2l6ZTo6aGYwMG\
ZmN2RiODliNGFmMDK9AUQ8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46Om91dHB1\
dF9zaXplOjpoNTM5M2JmZDg1NDI4Nzk3NL4BRDxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRG\
lnZXN0Pjo6b3V0cHV0X3NpemU6Omg1NTU5MjkxNGRjNjE3M2VmvwFEPEQgYXMgZGlnZXN0OjpkeW5f\
ZGlnZXN0OjpEeW5EaWdlc3Q+OjpvdXRwdXRfc2l6ZTo6aDY4ZDhmMjBhNGExYTJmZGPAAUQ8RCBhcy\
BkaWdlc3Q6OmR5bl9kaWdlc3Q6OkR5bkRpZ2VzdD46Om91dHB1dF9zaXplOjpoMjRmNGQ1ZDg3ODY3\
OGViMMEBRDxEIGFzIGRpZ2VzdDo6ZHluX2RpZ2VzdDo6RHluRGlnZXN0Pjo6b3V0cHV0X3NpemU6Om\
hmYWIxZjQxMmNmODRmZjYzwgFEPEQgYXMgZGlnZXN0OjpkeW5fZGlnZXN0OjpEeW5EaWdlc3Q+Ojpv\
dXRwdXRfc2l6ZTo6aDdjYjRmYzIwMDk2MjU1MjjDAUQ8RCBhcyBkaWdlc3Q6OmR5bl9kaWdlc3Q6Ok\
R5bkRpZ2VzdD46Om91dHB1dF9zaXplOjpoOTFjYTk4NDFjYzMyZGU2NsQBCnJ1c3RfcGFuaWPFATdz\
dGQ6OmFsbG9jOjpkZWZhdWx0X2FsbG9jX2Vycm9yX2hvb2s6OmgwZWNjZGFjMjRmZGEzNzhmxgFvY2\
9yZTo6cHRyOjpkcm9wX2luX3BsYWNlPCZjb3JlOjppdGVyOjphZGFwdGVyczo6Y29waWVkOjpDb3Bp\
ZWQ8Y29yZTo6c2xpY2U6Oml0ZXI6Okl0ZXI8dTg+Pj46OmhmN2JkMDQzN2MzZTg4NjM5AO+AgIAACX\
Byb2R1Y2VycwIIbGFuZ3VhZ2UBBFJ1c3QADHByb2Nlc3NlZC1ieQMFcnVzdGMdMS41NC4wIChhMTc4\
ZDAzMjIgMjAyMS0wNy0yNikGd2FscnVzBjAuMTkuMAx3YXNtLWJpbmRnZW4GMC4yLjc0"));
const wasmInstance = new WebAssembly.Instance(wasmModule, imports);
const wasm = wasmInstance.exports;
const hexTable = new TextEncoder().encode("0123456789abcdef");
function encode1(src) {
    const dst = new Uint8Array(src.length * 2);
    for(let i = 0; i < dst.length; i++){
        const v = src[i];
        dst[i * 2] = hexTable[v >> 4];
        dst[i * 2 + 1] = hexTable[v & 0x0f];
    }
    return dst;
}
class Hash {
    #hash;
    #digested;
    constructor(algorithm){
        this.#hash = create_hash(algorithm);
        this.#digested = false;
    }
    update(message) {
        let view;
        if (message instanceof Uint8Array) {
            view = message;
        } else if (typeof message === "string") {
            view = new TextEncoder().encode(message);
        } else if (ArrayBuffer.isView(message)) {
            view = new Uint8Array(message.buffer, message.byteOffset, message.byteLength);
        } else if (message instanceof ArrayBuffer) {
            view = new Uint8Array(message);
        } else {
            throw new Error("hash: `data` is invalid type");
        }
        const chunkSize = 65_536;
        for(let offset = 0; offset < view.byteLength; offset += chunkSize){
            update_hash(this.#hash, new Uint8Array(view.buffer, view.byteOffset + offset, Math.min(65_536, view.byteLength - offset)));
        }
        return this;
    }
    digest() {
        if (this.#digested) throw new Error("hash: already digested");
        this.#digested = true;
        return digest_hash(this.#hash);
    }
    toString(format = "hex") {
        const finalized = new Uint8Array(this.digest());
        switch(format){
            case "hex":
                return new TextDecoder().decode(encode1(finalized));
            case "base64":
                return encode(finalized);
            default:
                throw new Error("hash: invalid format");
        }
    }
}
function createHash(algorithm) {
    return new Hash(algorithm);
}
function replaceParams(sql, params) {
    if (!params) return sql;
    let paramIndex = 0;
    sql = sql.replace(/('[^'\\]*(?:\\.[^'\\]*)*')|("[^"\\]*(?:\\.[^"\\]*)*")|(\?\?)|(\?)/g, (str)=>{
        if (paramIndex >= params.length) return str;
        if (/".*"/g.test(str) || /'.*'/g.test(str)) {
            return str;
        }
        if (str === "??") {
            const val = params[paramIndex++];
            if (val instanceof Array) {
                return `(${val.map((item)=>replaceParams("??", [
                        item
                    ])).join(",")})`;
            } else if (val === "*") {
                return val;
            } else if (typeof val === "string" && val.includes(".")) {
                const _arr = val.split(".");
                return replaceParams(_arr.map(()=>"??").join("."), _arr);
            } else if (typeof val === "string" && (val.includes(" as ") || val.includes(" AS "))) {
                const newVal = val.replace(" as ", " AS ");
                const _arr1 = newVal.split(" AS ");
                return replaceParams(_arr1.map(()=>"??").join(" AS "), _arr1);
            } else {
                return [
                    "`",
                    val,
                    "`"
                ].join("");
            }
        }
        const val1 = params[paramIndex++];
        if (val1 === null) return "NULL";
        switch(typeof val1){
            case "object":
                if (val1 instanceof Date) return `"${formatDate(val1)}"`;
                if (val1 instanceof Array) {
                    return `(${val1.map((item)=>replaceParams("?", [
                            item
                        ])).join(",")})`;
                }
            case "string":
                return `"${escapeString(val1)}"`;
            case "undefined":
                return "NULL";
            case "number":
            case "boolean":
            default:
                return val1;
        }
    });
    return sql;
}
function formatDate(date) {
    const year = date.getFullYear();
    const month = (date.getMonth() + 1).toString().padStart(2, "0");
    const days = date.getDate().toString().padStart(2, "0");
    const hours = date.getHours().toString().padStart(2, "0");
    const minutes = date.getMinutes().toString().padStart(2, "0");
    const seconds = date.getSeconds().toString().padStart(2, "0");
    const milliseconds = date.getMilliseconds().toString().padStart(3, "0");
    return `${year}-${month}-${days} ${hours}:${minutes}:${seconds}.${milliseconds}`;
}
function escapeString(str) {
    return str.replaceAll("\\", "\\\\").replaceAll('"', '\\"');
}
var LogLevels;
(function(LogLevels) {
    LogLevels[LogLevels["NOTSET"] = 0] = "NOTSET";
    LogLevels[LogLevels["DEBUG"] = 10] = "DEBUG";
    LogLevels[LogLevels["INFO"] = 20] = "INFO";
    LogLevels[LogLevels["WARNING"] = 30] = "WARNING";
    LogLevels[LogLevels["ERROR"] = 40] = "ERROR";
    LogLevels[LogLevels["CRITICAL"] = 50] = "CRITICAL";
})(LogLevels || (LogLevels = {}));
Object.keys(LogLevels).filter((key)=>isNaN(Number(key)));
const byLevel = {
    [String(LogLevels.NOTSET)]: "NOTSET",
    [String(LogLevels.DEBUG)]: "DEBUG",
    [String(LogLevels.INFO)]: "INFO",
    [String(LogLevels.WARNING)]: "WARNING",
    [String(LogLevels.ERROR)]: "ERROR",
    [String(LogLevels.CRITICAL)]: "CRITICAL"
};
function getLevelByName(name) {
    switch(name){
        case "NOTSET":
            return LogLevels.NOTSET;
        case "DEBUG":
            return LogLevels.DEBUG;
        case "INFO":
            return LogLevels.INFO;
        case "WARNING":
            return LogLevels.WARNING;
        case "ERROR":
            return LogLevels.ERROR;
        case "CRITICAL":
            return LogLevels.CRITICAL;
        default:
            throw new Error(`no log level found for "${name}"`);
    }
}
function getLevelName(level) {
    const levelName = byLevel[level];
    if (levelName) {
        return levelName;
    }
    throw new Error(`no level name found for level: ${level}`);
}
class LogRecord {
    msg;
    #args;
    #datetime;
    level;
    levelName;
    loggerName;
    constructor(options){
        this.msg = options.msg;
        this.#args = [
            ...options.args
        ];
        this.level = options.level;
        this.loggerName = options.loggerName;
        this.#datetime = new Date();
        this.levelName = getLevelName(options.level);
    }
    get args() {
        return [
            ...this.#args
        ];
    }
    get datetime() {
        return new Date(this.#datetime.getTime());
    }
}
class Logger {
    #level;
    #handlers;
    #loggerName;
    constructor(loggerName, levelName, options = {}){
        this.#loggerName = loggerName;
        this.#level = getLevelByName(levelName);
        this.#handlers = options.handlers || [];
    }
    get level() {
        return this.#level;
    }
    set level(level) {
        this.#level = level;
    }
    get levelName() {
        return getLevelName(this.#level);
    }
    set levelName(levelName) {
        this.#level = getLevelByName(levelName);
    }
    get loggerName() {
        return this.#loggerName;
    }
    set handlers(hndls) {
        this.#handlers = hndls;
    }
    get handlers() {
        return this.#handlers;
    }
    _log(level, msg, ...args) {
        if (this.level > level) {
            return msg instanceof Function ? undefined : msg;
        }
        let fnResult;
        let logMessage;
        if (msg instanceof Function) {
            fnResult = msg();
            logMessage = this.asString(fnResult);
        } else {
            logMessage = this.asString(msg);
        }
        const record = new LogRecord({
            msg: logMessage,
            args: args,
            level: level,
            loggerName: this.loggerName
        });
        this.#handlers.forEach((handler)=>{
            handler.handle(record);
        });
        return msg instanceof Function ? fnResult : msg;
    }
    asString(data) {
        if (typeof data === "string") {
            return data;
        } else if (data === null || typeof data === "number" || typeof data === "bigint" || typeof data === "boolean" || typeof data === "undefined" || typeof data === "symbol") {
            return String(data);
        } else if (data instanceof Error) {
            return data.stack;
        } else if (typeof data === "object") {
            return JSON.stringify(data);
        }
        return "undefined";
    }
    debug(msg, ...args) {
        return this._log(LogLevels.DEBUG, msg, ...args);
    }
    info(msg, ...args) {
        return this._log(LogLevels.INFO, msg, ...args);
    }
    warning(msg, ...args) {
        return this._log(LogLevels.WARNING, msg, ...args);
    }
    error(msg, ...args) {
        return this._log(LogLevels.ERROR, msg, ...args);
    }
    critical(msg, ...args) {
        return this._log(LogLevels.CRITICAL, msg, ...args);
    }
}
const { Deno: Deno1  } = globalThis;
const noColor1 = typeof Deno1?.noColor === "boolean" ? Deno1.noColor : true;
let enabled1 = !noColor1;
function code1(open, close) {
    return {
        open: `\x1b[${open.join(";")}m`,
        close: `\x1b[${close}m`,
        regexp: new RegExp(`\\x1b\\[${close}m`, "g")
    };
}
function run1(str, code) {
    return enabled1 ? `${code.open}${str.replace(code.regexp, code.open)}${code.close}` : str;
}
function bold(str) {
    return run1(str, code1([
        1
    ], 22));
}
function red(str) {
    return run1(str, code1([
        31
    ], 39));
}
function yellow(str) {
    return run1(str, code1([
        33
    ], 39));
}
function blue(str) {
    return run1(str, code1([
        34
    ], 39));
}
new RegExp([
    "[\\u001B\\u009B][[\\]()#;?]*(?:(?:(?:[a-zA-Z\\d]*(?:;[-a-zA-Z\\d\\/#&.:=?%@~_]*)*)?\\u0007)",
    "(?:(?:\\d{1,4}(?:;\\d{0,4})*)?[\\dA-PR-TZcf-ntqry=><~]))",
].join("|"), "g");
async function exists(filePath) {
    try {
        await Deno.lstat(filePath);
        return true;
    } catch (err) {
        if (err instanceof Deno.errors.NotFound) {
            return false;
        }
        throw err;
    }
}
function existsSync(filePath) {
    try {
        Deno.lstatSync(filePath);
        return true;
    } catch (err) {
        if (err instanceof Deno.errors.NotFound) {
            return false;
        }
        throw err;
    }
}
function copy(src, dst, off = 0) {
    off = Math.max(0, Math.min(off, dst.byteLength));
    const dstBytesAvailable = dst.byteLength - off;
    if (src.byteLength > dstBytesAvailable) {
        src = src.subarray(0, dstBytesAvailable);
    }
    dst.set(src, off);
    return src.byteLength;
}
class DenoStdInternalError extends Error {
    constructor(message){
        super(message);
        this.name = "DenoStdInternalError";
    }
}
function assert(expr, msg = "") {
    if (!expr) {
        throw new DenoStdInternalError(msg);
    }
}
var DiffType;
(function(DiffType) {
    DiffType["removed"] = "removed";
    DiffType["common"] = "common";
    DiffType["added"] = "added";
})(DiffType || (DiffType = {}));
async function writeAll(w, arr) {
    let nwritten = 0;
    while(nwritten < arr.length){
        nwritten += await w.write(arr.subarray(nwritten));
    }
}
function writeAllSync(w, arr) {
    let nwritten = 0;
    while(nwritten < arr.length){
        nwritten += w.writeSync(arr.subarray(nwritten));
    }
}
const DEFAULT_BUF_SIZE = 4096;
const MIN_BUF_SIZE = 16;
const CR = "\r".charCodeAt(0);
const LF = "\n".charCodeAt(0);
class BufferFullError extends Error {
    name;
    constructor(partial){
        super("Buffer full");
        this.partial = partial;
        this.name = "BufferFullError";
    }
    partial;
}
class PartialReadError extends Error {
    name = "PartialReadError";
    partial;
    constructor(){
        super("Encountered UnexpectedEof, data only partially read");
    }
}
class BufReader {
    buf;
    rd;
    r = 0;
    w = 0;
    eof = false;
    static create(r, size = 4096) {
        return r instanceof BufReader ? r : new BufReader(r, size);
    }
    constructor(rd, size = 4096){
        if (size < 16) {
            size = MIN_BUF_SIZE;
        }
        this._reset(new Uint8Array(size), rd);
    }
    size() {
        return this.buf.byteLength;
    }
    buffered() {
        return this.w - this.r;
    }
    async _fill() {
        if (this.r > 0) {
            this.buf.copyWithin(0, this.r, this.w);
            this.w -= this.r;
            this.r = 0;
        }
        if (this.w >= this.buf.byteLength) {
            throw Error("bufio: tried to fill full buffer");
        }
        for(let i = 100; i > 0; i--){
            const rr = await this.rd.read(this.buf.subarray(this.w));
            if (rr === null) {
                this.eof = true;
                return;
            }
            assert(rr >= 0, "negative read");
            this.w += rr;
            if (rr > 0) {
                return;
            }
        }
        throw new Error(`No progress after ${100} read() calls`);
    }
    reset(r) {
        this._reset(this.buf, r);
    }
    _reset(buf, rd) {
        this.buf = buf;
        this.rd = rd;
        this.eof = false;
    }
    async read(p) {
        let rr = p.byteLength;
        if (p.byteLength === 0) return rr;
        if (this.r === this.w) {
            if (p.byteLength >= this.buf.byteLength) {
                const rr1 = await this.rd.read(p);
                const nread = rr1 ?? 0;
                assert(nread >= 0, "negative read");
                return rr1;
            }
            this.r = 0;
            this.w = 0;
            rr = await this.rd.read(this.buf);
            if (rr === 0 || rr === null) return rr;
            assert(rr >= 0, "negative read");
            this.w += rr;
        }
        const copied = copy(this.buf.subarray(this.r, this.w), p, 0);
        this.r += copied;
        return copied;
    }
    async readFull(p) {
        let bytesRead = 0;
        while(bytesRead < p.length){
            try {
                const rr = await this.read(p.subarray(bytesRead));
                if (rr === null) {
                    if (bytesRead === 0) {
                        return null;
                    } else {
                        throw new PartialReadError();
                    }
                }
                bytesRead += rr;
            } catch (err) {
                err.partial = p.subarray(0, bytesRead);
                throw err;
            }
        }
        return p;
    }
    async readByte() {
        while(this.r === this.w){
            if (this.eof) return null;
            await this._fill();
        }
        const c = this.buf[this.r];
        this.r++;
        return c;
    }
    async readString(delim) {
        if (delim.length !== 1) {
            throw new Error("Delimiter should be a single character");
        }
        const buffer = await this.readSlice(delim.charCodeAt(0));
        if (buffer === null) return null;
        return new TextDecoder().decode(buffer);
    }
    async readLine() {
        let line;
        try {
            line = await this.readSlice(LF);
        } catch (err) {
            if (err instanceof Deno.errors.BadResource) {
                throw err;
            }
            let { partial  } = err;
            assert(partial instanceof Uint8Array, "bufio: caught error from `readSlice()` without `partial` property");
            if (!(err instanceof BufferFullError)) {
                throw err;
            }
            if (!this.eof && partial.byteLength > 0 && partial[partial.byteLength - 1] === CR) {
                assert(this.r > 0, "bufio: tried to rewind past start of buffer");
                this.r--;
                partial = partial.subarray(0, partial.byteLength - 1);
            }
            return {
                line: partial,
                more: !this.eof
            };
        }
        if (line === null) {
            return null;
        }
        if (line.byteLength === 0) {
            return {
                line,
                more: false
            };
        }
        if (line[line.byteLength - 1] == LF) {
            let drop = 1;
            if (line.byteLength > 1 && line[line.byteLength - 2] === CR) {
                drop = 2;
            }
            line = line.subarray(0, line.byteLength - drop);
        }
        return {
            line,
            more: false
        };
    }
    async readSlice(delim) {
        let s = 0;
        let slice;
        while(true){
            let i = this.buf.subarray(this.r + s, this.w).indexOf(delim);
            if (i >= 0) {
                i += s;
                slice = this.buf.subarray(this.r, this.r + i + 1);
                this.r += i + 1;
                break;
            }
            if (this.eof) {
                if (this.r === this.w) {
                    return null;
                }
                slice = this.buf.subarray(this.r, this.w);
                this.r = this.w;
                break;
            }
            if (this.buffered() >= this.buf.byteLength) {
                this.r = this.w;
                const oldbuf = this.buf;
                const newbuf = this.buf.slice(0);
                this.buf = newbuf;
                throw new BufferFullError(oldbuf);
            }
            s = this.w - this.r;
            try {
                await this._fill();
            } catch (err) {
                err.partial = slice;
                throw err;
            }
        }
        return slice;
    }
    async peek(n) {
        if (n < 0) {
            throw Error("negative count");
        }
        let avail = this.w - this.r;
        while(avail < n && avail < this.buf.byteLength && !this.eof){
            try {
                await this._fill();
            } catch (err) {
                err.partial = this.buf.subarray(this.r, this.w);
                throw err;
            }
            avail = this.w - this.r;
        }
        if (avail === 0 && this.eof) {
            return null;
        } else if (avail < n && this.eof) {
            return this.buf.subarray(this.r, this.r + avail);
        } else if (avail < n) {
            throw new BufferFullError(this.buf.subarray(this.r, this.w));
        }
        return this.buf.subarray(this.r, this.r + n);
    }
}
class AbstractBufBase {
    buf;
    usedBufferBytes = 0;
    err = null;
    size() {
        return this.buf.byteLength;
    }
    available() {
        return this.buf.byteLength - this.usedBufferBytes;
    }
    buffered() {
        return this.usedBufferBytes;
    }
}
class BufWriter extends AbstractBufBase {
    static create(writer, size = 4096) {
        return writer instanceof BufWriter ? writer : new BufWriter(writer, size);
    }
    constructor(writer, size = 4096){
        super();
        this.writer = writer;
        if (size <= 0) {
            size = DEFAULT_BUF_SIZE;
        }
        this.buf = new Uint8Array(size);
    }
    reset(w) {
        this.err = null;
        this.usedBufferBytes = 0;
        this.writer = w;
    }
    async flush() {
        if (this.err !== null) throw this.err;
        if (this.usedBufferBytes === 0) return;
        try {
            await writeAll(this.writer, this.buf.subarray(0, this.usedBufferBytes));
        } catch (e) {
            this.err = e;
            throw e;
        }
        this.buf = new Uint8Array(this.buf.length);
        this.usedBufferBytes = 0;
    }
    async write(data) {
        if (this.err !== null) throw this.err;
        if (data.length === 0) return 0;
        let totalBytesWritten = 0;
        let numBytesWritten = 0;
        while(data.byteLength > this.available()){
            if (this.buffered() === 0) {
                try {
                    numBytesWritten = await this.writer.write(data);
                } catch (e) {
                    this.err = e;
                    throw e;
                }
            } else {
                numBytesWritten = copy(data, this.buf, this.usedBufferBytes);
                this.usedBufferBytes += numBytesWritten;
                await this.flush();
            }
            totalBytesWritten += numBytesWritten;
            data = data.subarray(numBytesWritten);
        }
        numBytesWritten = copy(data, this.buf, this.usedBufferBytes);
        this.usedBufferBytes += numBytesWritten;
        totalBytesWritten += numBytesWritten;
        return totalBytesWritten;
    }
    writer;
}
class BufWriterSync extends AbstractBufBase {
    static create(writer, size = 4096) {
        return writer instanceof BufWriterSync ? writer : new BufWriterSync(writer, size);
    }
    constructor(writer, size = 4096){
        super();
        this.writer = writer;
        if (size <= 0) {
            size = DEFAULT_BUF_SIZE;
        }
        this.buf = new Uint8Array(size);
    }
    reset(w) {
        this.err = null;
        this.usedBufferBytes = 0;
        this.writer = w;
    }
    flush() {
        if (this.err !== null) throw this.err;
        if (this.usedBufferBytes === 0) return;
        try {
            writeAllSync(this.writer, this.buf.subarray(0, this.usedBufferBytes));
        } catch (e) {
            this.err = e;
            throw e;
        }
        this.buf = new Uint8Array(this.buf.length);
        this.usedBufferBytes = 0;
    }
    writeSync(data) {
        if (this.err !== null) throw this.err;
        if (data.length === 0) return 0;
        let totalBytesWritten = 0;
        let numBytesWritten = 0;
        while(data.byteLength > this.available()){
            if (this.buffered() === 0) {
                try {
                    numBytesWritten = this.writer.writeSync(data);
                } catch (e) {
                    this.err = e;
                    throw e;
                }
            } else {
                numBytesWritten = copy(data, this.buf, this.usedBufferBytes);
                this.usedBufferBytes += numBytesWritten;
                this.flush();
            }
            totalBytesWritten += numBytesWritten;
            data = data.subarray(numBytesWritten);
        }
        numBytesWritten = copy(data, this.buf, this.usedBufferBytes);
        this.usedBufferBytes += numBytesWritten;
        totalBytesWritten += numBytesWritten;
        return totalBytesWritten;
    }
    writer;
}
const DEFAULT_FORMATTER = "{levelName} {msg}";
class BaseHandler {
    level;
    levelName;
    formatter;
    constructor(levelName, options = {}){
        this.level = getLevelByName(levelName);
        this.levelName = levelName;
        this.formatter = options.formatter || DEFAULT_FORMATTER;
    }
    handle(logRecord) {
        if (this.level > logRecord.level) return;
        const msg = this.format(logRecord);
        return this.log(msg);
    }
    format(logRecord) {
        if (this.formatter instanceof Function) {
            return this.formatter(logRecord);
        }
        return this.formatter.replace(/{(\S+)}/g, (match, p1)=>{
            const value = logRecord[p1];
            if (value == null) {
                return match;
            }
            return String(value);
        });
    }
    log(_msg) {}
    async setup() {}
    async destroy() {}
}
class ConsoleHandler extends BaseHandler {
    format(logRecord) {
        let msg = super.format(logRecord);
        switch(logRecord.level){
            case LogLevels.INFO:
                msg = blue(msg);
                break;
            case LogLevels.WARNING:
                msg = yellow(msg);
                break;
            case LogLevels.ERROR:
                msg = red(msg);
                break;
            case LogLevels.CRITICAL:
                msg = bold(red(msg));
                break;
            default:
                break;
        }
        return msg;
    }
    log(msg) {
        console.log(msg);
    }
}
class WriterHandler extends BaseHandler {
    _writer;
    #encoder = new TextEncoder();
}
class FileHandler extends WriterHandler {
    _file;
    _buf;
    _filename;
    _mode;
    _openOptions;
    _encoder = new TextEncoder();
     #unloadCallback() {
        this.destroy();
    }
    constructor(levelName, options){
        super(levelName, options);
        this._filename = options.filename;
        this._mode = options.mode ? options.mode : "a";
        this._openOptions = {
            createNew: this._mode === "x",
            create: this._mode !== "x",
            append: this._mode === "a",
            truncate: this._mode !== "a",
            write: true
        };
    }
    async setup() {
        this._file = await Deno.open(this._filename, this._openOptions);
        this._writer = this._file;
        this._buf = new BufWriterSync(this._file);
        addEventListener("unload", this.#unloadCallback.bind(this));
    }
    handle(logRecord) {
        super.handle(logRecord);
        if (logRecord.level > LogLevels.ERROR) {
            this.flush();
        }
    }
    log(msg) {
        this._buf.writeSync(this._encoder.encode(msg + "\n"));
    }
    flush() {
        if (this._buf?.buffered() > 0) {
            this._buf.flush();
        }
    }
    destroy() {
        this.flush();
        this._file?.close();
        this._file = undefined;
        removeEventListener("unload", this.#unloadCallback);
        return Promise.resolve();
    }
}
class RotatingFileHandler extends FileHandler {
    #maxBytes;
    #maxBackupCount;
    #currentFileSize = 0;
    constructor(levelName, options){
        super(levelName, options);
        this.#maxBytes = options.maxBytes;
        this.#maxBackupCount = options.maxBackupCount;
    }
    async setup() {
        if (this.#maxBytes < 1) {
            this.destroy();
            throw new Error("maxBytes cannot be less than 1");
        }
        if (this.#maxBackupCount < 1) {
            this.destroy();
            throw new Error("maxBackupCount cannot be less than 1");
        }
        await super.setup();
        if (this._mode === "w") {
            for(let i = 1; i <= this.#maxBackupCount; i++){
                if (await exists(this._filename + "." + i)) {
                    await Deno.remove(this._filename + "." + i);
                }
            }
        } else if (this._mode === "x") {
            for(let i1 = 1; i1 <= this.#maxBackupCount; i1++){
                if (await exists(this._filename + "." + i1)) {
                    this.destroy();
                    throw new Deno.errors.AlreadyExists("Backup log file " + this._filename + "." + i1 + " already exists");
                }
            }
        } else {
            this.#currentFileSize = (await Deno.stat(this._filename)).size;
        }
    }
    log(msg) {
        const msgByteLength = this._encoder.encode(msg).byteLength + 1;
        if (this.#currentFileSize + msgByteLength > this.#maxBytes) {
            this.rotateLogFiles();
            this.#currentFileSize = 0;
        }
        this._buf.writeSync(this._encoder.encode(msg + "\n"));
        this.#currentFileSize += msgByteLength;
    }
    rotateLogFiles() {
        this._buf.flush();
        Deno.close(this._file.rid);
        for(let i = this.#maxBackupCount - 1; i >= 0; i--){
            const source = this._filename + (i === 0 ? "" : "." + i);
            const dest = this._filename + "." + (i + 1);
            if (existsSync(source)) {
                Deno.renameSync(source, dest);
            }
        }
        this._file = Deno.openSync(this._filename, this._openOptions);
        this._writer = this._file;
        this._buf = new BufWriterSync(this._file);
    }
}
class LoggerConfig {
    level;
    handlers;
}
const DEFAULT_LEVEL = "INFO";
const DEFAULT_CONFIG = {
    handlers: {
        default: new ConsoleHandler(DEFAULT_LEVEL)
    },
    loggers: {
        default: {
            level: DEFAULT_LEVEL,
            handlers: [
                "default"
            ]
        }
    }
};
const state = {
    handlers: new Map(),
    loggers: new Map(),
    config: DEFAULT_CONFIG
};
const handlers = {
    BaseHandler,
    ConsoleHandler,
    WriterHandler,
    FileHandler,
    RotatingFileHandler
};
function getLogger(name) {
    if (!name) {
        const d = state.loggers.get("default");
        assert(d != null, `"default" logger must be set for getting logger without name`);
        return d;
    }
    const result = state.loggers.get(name);
    if (!result) {
        const logger = new Logger(name, "NOTSET", {
            handlers: []
        });
        state.loggers.set(name, logger);
        return logger;
    }
    return result;
}
function debug(msg, ...args) {
    if (msg instanceof Function) {
        return getLogger("default").debug(msg, ...args);
    }
    return getLogger("default").debug(msg, ...args);
}
function info(msg, ...args) {
    if (msg instanceof Function) {
        return getLogger("default").info(msg, ...args);
    }
    return getLogger("default").info(msg, ...args);
}
function warning(msg, ...args) {
    if (msg instanceof Function) {
        return getLogger("default").warning(msg, ...args);
    }
    return getLogger("default").warning(msg, ...args);
}
function error(msg, ...args) {
    if (msg instanceof Function) {
        return getLogger("default").error(msg, ...args);
    }
    return getLogger("default").error(msg, ...args);
}
function critical(msg, ...args) {
    if (msg instanceof Function) {
        return getLogger("default").critical(msg, ...args);
    }
    return getLogger("default").critical(msg, ...args);
}
async function setup(config) {
    state.config = {
        handlers: {
            ...DEFAULT_CONFIG.handlers,
            ...config.handlers
        },
        loggers: {
            ...DEFAULT_CONFIG.loggers,
            ...config.loggers
        }
    };
    state.handlers.forEach((handler)=>{
        handler.destroy();
    });
    state.handlers.clear();
    const handlers = state.config.handlers || {};
    for(const handlerName in handlers){
        const handler = handlers[handlerName];
        await handler.setup();
        state.handlers.set(handlerName, handler);
    }
    state.loggers.clear();
    const loggers = state.config.loggers || {};
    for(const loggerName in loggers){
        const loggerConfig = loggers[loggerName];
        const handlerNames = loggerConfig.handlers || [];
        const handlers1 = [];
        handlerNames.forEach((handlerName)=>{
            const handler = state.handlers.get(handlerName);
            if (handler) {
                handlers1.push(handler);
            }
        });
        const levelName = loggerConfig.level || DEFAULT_LEVEL;
        const logger = new Logger(loggerName, levelName, {
            handlers: handlers1
        });
        state.loggers.set(loggerName, logger);
    }
}
await setup(DEFAULT_CONFIG);
const mod = await async function() {
    return {
        LogLevels: LogLevels,
        Logger: Logger,
        LoggerConfig: LoggerConfig,
        handlers: handlers,
        getLogger: getLogger,
        debug: debug,
        info: info,
        warning: warning,
        error: error,
        critical: critical,
        setup: setup
    };
}();
let logger = mod.getLogger();
let isDebug = false;
function debug1(func) {
    if (isDebug) {
        func();
    }
}
async function configLogger(config) {
    let { enable =true , level ="INFO"  } = config;
    if (config.logger) level = config.logger.levelName;
    isDebug = level == "DEBUG";
    if (!enable) {
        logger = new mod.Logger("fakeLogger", "NOTSET", {});
        logger.level = 100;
    } else {
        if (!config.logger) {
            await mod.setup({
                handlers: {
                    console: new mod.handlers.ConsoleHandler(level)
                },
                loggers: {
                    default: {
                        level: "DEBUG",
                        handlers: [
                            "console"
                        ]
                    }
                }
            });
            logger = mod.getLogger();
        } else {
            logger = config.logger;
        }
    }
}
function xor(a, b) {
    return a.map((__byte, index)=>{
        return __byte ^ b[index];
    });
}
const encoder = new TextEncoder();
const decoder = new TextDecoder();
function encode2(input) {
    return encoder.encode(input);
}
function decode1(input) {
    return decoder.decode(input);
}
class BufferReader {
    pos;
    constructor(buffer){
        this.buffer = buffer;
        this.pos = 0;
    }
    get finished() {
        return this.pos >= this.buffer.length;
    }
    skip(len) {
        this.pos += len;
        return this;
    }
    readBuffer(len) {
        const buffer = this.buffer.slice(this.pos, this.pos + len);
        this.pos += len;
        return buffer;
    }
    readUints(len) {
        let num = 0;
        for(let n = 0; n < len; n++){
            num += this.buffer[this.pos++] << 8 * n;
        }
        return num;
    }
    readUint8() {
        return this.buffer[this.pos++];
    }
    readUint16() {
        return this.readUints(2);
    }
    readUint32() {
        return this.readUints(4);
    }
    readUint64() {
        return this.readUints(8);
    }
    readNullTerminatedString() {
        let end = this.buffer.indexOf(0x00, this.pos);
        if (end === -1) end = this.buffer.length;
        const buf = this.buffer.slice(this.pos, end);
        this.pos += buf.length + 1;
        return decode1(buf);
    }
    readRestOfPacketString() {
        return this.buffer.slice(this.pos);
    }
    readString(len) {
        const str = decode1(this.buffer.slice(this.pos, this.pos + len));
        this.pos += len;
        return str;
    }
    readEncodedLen() {
        const first = this.readUint8();
        if (first < 251) {
            return first;
        } else {
            if (first == 0xfc) {
                return this.readUint16();
            } else if (first == 0xfd) {
                return this.readUints(3);
            } else if (first == 0xfe) {
                return this.readUints(8);
            }
        }
        return -1;
    }
    readLenCodeString() {
        const len = this.readEncodedLen();
        if (len == -1) return null;
        return this.readString(len);
    }
    buffer;
}
class BufferWriter {
    pos;
    constructor(buffer){
        this.buffer = buffer;
        this.pos = 0;
    }
    get wroteData() {
        return this.buffer.slice(0, this.pos);
    }
    get length() {
        return this.pos;
    }
    get capacity() {
        return this.buffer.length - this.pos;
    }
    skip(len) {
        this.pos += len;
        return this;
    }
    writeBuffer(buffer) {
        if (buffer.length > this.capacity) {
            buffer = buffer.slice(0, this.capacity);
        }
        this.buffer.set(buffer, this.pos);
        this.pos += buffer.length;
        return this;
    }
    write(__byte) {
        this.buffer[this.pos++] = __byte;
        return this;
    }
    writeInt16LE(num) {}
    writeIntLE(num, len) {
        const __int = new Int32Array(1);
        __int[0] = 40;
        console.log(__int);
    }
    writeUint16(num) {
        return this.writeUints(2, num);
    }
    writeUint32(num) {
        return this.writeUints(4, num);
    }
    writeUint64(num) {
        return this.writeUints(8, num);
    }
    writeUints(len, num) {
        for(let n = 0; n < len; n++){
            this.buffer[this.pos++] = num >> n * 8 & 0xff;
        }
        return this;
    }
    writeNullTerminatedString(str) {
        return this.writeString(str).write(0x00);
    }
    writeString(str) {
        const buf = encode2(str);
        this.buffer.set(buf, this.pos);
        this.pos += buf.length;
        return this;
    }
    buffer;
}
function hash(algorithm, data) {
    return new Uint8Array(createHash(algorithm).update(data).digest());
}
function mysqlNativePassword(password, seed) {
    const pwd1 = hash("sha1", encode2(password));
    const pwd2 = hash("sha1", pwd1);
    let seedAndPwd2 = new Uint8Array(seed.length + pwd2.length);
    seedAndPwd2.set(seed);
    seedAndPwd2.set(pwd2, seed.length);
    seedAndPwd2 = hash("sha1", seedAndPwd2);
    return xor(seedAndPwd2, pwd1);
}
function cachingSha2Password(password, seed) {
    const stage1 = hash("sha256", encode2(password));
    const stage2 = hash("sha256", stage1);
    const stage3 = hash("sha256", Uint8Array.from([
        ...stage2,
        ...seed
    ]));
    return xor(stage1, stage3);
}
function auth(authPluginName, password, seed) {
    switch(authPluginName){
        case "mysql_native_password":
            return mysqlNativePassword(password, seed.slice(0, 20));
        case "caching_sha2_password":
            return cachingSha2Password(password, seed);
        default:
            throw new Error("Not supported");
    }
}
var ServerCapabilities;
(function(ServerCapabilities) {
    ServerCapabilities[ServerCapabilities["CLIENT_PROTOCOL_41"] = 0x00000200] = "CLIENT_PROTOCOL_41";
    ServerCapabilities[ServerCapabilities["CLIENT_CONNECT_WITH_DB"] = 0x00000008] = "CLIENT_CONNECT_WITH_DB";
    ServerCapabilities[ServerCapabilities["CLIENT_LONG_FLAG"] = 0x00000004] = "CLIENT_LONG_FLAG";
    ServerCapabilities[ServerCapabilities["CLIENT_DEPRECATE_EOF"] = 0x01000000] = "CLIENT_DEPRECATE_EOF";
    ServerCapabilities[ServerCapabilities["CLIENT_LONG_PASSWORD"] = 0x00000001] = "CLIENT_LONG_PASSWORD";
    ServerCapabilities[ServerCapabilities["CLIENT_TRANSACTIONS"] = 0x00002000] = "CLIENT_TRANSACTIONS";
    ServerCapabilities[ServerCapabilities["CLIENT_MULTI_RESULTS"] = 0x00020000] = "CLIENT_MULTI_RESULTS";
    ServerCapabilities[ServerCapabilities["CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA"] = 0x00200000] = "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA";
    ServerCapabilities[ServerCapabilities["CLIENT_PLUGIN_AUTH"] = 0x80000] = "CLIENT_PLUGIN_AUTH";
    ServerCapabilities[ServerCapabilities["CLIENT_SECURE_CONNECTION"] = 0x8000] = "CLIENT_SECURE_CONNECTION";
    ServerCapabilities[ServerCapabilities["CLIENT_FOUND_ROWS"] = 0x00000002] = "CLIENT_FOUND_ROWS";
    ServerCapabilities[ServerCapabilities["CLIENT_CONNECT_ATTRS"] = 0x00100000] = "CLIENT_CONNECT_ATTRS";
    ServerCapabilities[ServerCapabilities["CLIENT_IGNORE_SPACE"] = 0x00000100] = "CLIENT_IGNORE_SPACE";
    ServerCapabilities[ServerCapabilities["CLIENT_IGNORE_SIGPIPE"] = 0x00001000] = "CLIENT_IGNORE_SIGPIPE";
    ServerCapabilities[ServerCapabilities["CLIENT_RESERVED"] = 0x00004000] = "CLIENT_RESERVED";
    ServerCapabilities[ServerCapabilities["CLIENT_PS_MULTI_RESULTS"] = 0x00040000] = "CLIENT_PS_MULTI_RESULTS";
})(ServerCapabilities || (ServerCapabilities = {}));
var Charset;
(function(Charset) {
    Charset[Charset["BIG5_CHINESE_CI"] = 1] = "BIG5_CHINESE_CI";
    Charset[Charset["LATIN2_CZECH_CS"] = 2] = "LATIN2_CZECH_CS";
    Charset[Charset["DEC8_SWEDISH_CI"] = 3] = "DEC8_SWEDISH_CI";
    Charset[Charset["CP850_GENERAL_CI"] = 4] = "CP850_GENERAL_CI";
    Charset[Charset["LATIN1_GERMAN1_CI"] = 5] = "LATIN1_GERMAN1_CI";
    Charset[Charset["HP8_ENGLISH_CI"] = 6] = "HP8_ENGLISH_CI";
    Charset[Charset["KOI8R_GENERAL_CI"] = 7] = "KOI8R_GENERAL_CI";
    Charset[Charset["LATIN1_SWEDISH_CI"] = 8] = "LATIN1_SWEDISH_CI";
    Charset[Charset["LATIN2_GENERAL_CI"] = 9] = "LATIN2_GENERAL_CI";
    Charset[Charset["SWE7_SWEDISH_CI"] = 10] = "SWE7_SWEDISH_CI";
    Charset[Charset["ASCII_GENERAL_CI"] = 11] = "ASCII_GENERAL_CI";
    Charset[Charset["UJIS_JAPANESE_CI"] = 12] = "UJIS_JAPANESE_CI";
    Charset[Charset["SJIS_JAPANESE_CI"] = 13] = "SJIS_JAPANESE_CI";
    Charset[Charset["CP1251_BULGARIAN_CI"] = 14] = "CP1251_BULGARIAN_CI";
    Charset[Charset["LATIN1_DANISH_CI"] = 15] = "LATIN1_DANISH_CI";
    Charset[Charset["HEBREW_GENERAL_CI"] = 16] = "HEBREW_GENERAL_CI";
    Charset[Charset["TIS620_THAI_CI"] = 18] = "TIS620_THAI_CI";
    Charset[Charset["EUCKR_KOREAN_CI"] = 19] = "EUCKR_KOREAN_CI";
    Charset[Charset["LATIN7_ESTONIAN_CS"] = 20] = "LATIN7_ESTONIAN_CS";
    Charset[Charset["LATIN2_HUNGARIAN_CI"] = 21] = "LATIN2_HUNGARIAN_CI";
    Charset[Charset["KOI8U_GENERAL_CI"] = 22] = "KOI8U_GENERAL_CI";
    Charset[Charset["CP1251_UKRAINIAN_CI"] = 23] = "CP1251_UKRAINIAN_CI";
    Charset[Charset["GB2312_CHINESE_CI"] = 24] = "GB2312_CHINESE_CI";
    Charset[Charset["GREEK_GENERAL_CI"] = 25] = "GREEK_GENERAL_CI";
    Charset[Charset["CP1250_GENERAL_CI"] = 26] = "CP1250_GENERAL_CI";
    Charset[Charset["LATIN2_CROATIAN_CI"] = 27] = "LATIN2_CROATIAN_CI";
    Charset[Charset["GBK_CHINESE_CI"] = 28] = "GBK_CHINESE_CI";
    Charset[Charset["CP1257_LITHUANIAN_CI"] = 29] = "CP1257_LITHUANIAN_CI";
    Charset[Charset["LATIN5_TURKISH_CI"] = 30] = "LATIN5_TURKISH_CI";
    Charset[Charset["LATIN1_GERMAN2_CI"] = 31] = "LATIN1_GERMAN2_CI";
    Charset[Charset["ARMSCII8_GENERAL_CI"] = 32] = "ARMSCII8_GENERAL_CI";
    Charset[Charset["UTF8_GENERAL_CI"] = 33] = "UTF8_GENERAL_CI";
    Charset[Charset["CP1250_CZECH_CS"] = 34] = "CP1250_CZECH_CS";
    Charset[Charset["UCS2_GENERAL_CI"] = 35] = "UCS2_GENERAL_CI";
    Charset[Charset["CP866_GENERAL_CI"] = 36] = "CP866_GENERAL_CI";
    Charset[Charset["KEYBCS2_GENERAL_CI"] = 37] = "KEYBCS2_GENERAL_CI";
    Charset[Charset["MACCE_GENERAL_CI"] = 38] = "MACCE_GENERAL_CI";
    Charset[Charset["MACROMAN_GENERAL_CI"] = 39] = "MACROMAN_GENERAL_CI";
    Charset[Charset["CP852_GENERAL_CI"] = 40] = "CP852_GENERAL_CI";
    Charset[Charset["LATIN7_GENERAL_CI"] = 41] = "LATIN7_GENERAL_CI";
    Charset[Charset["LATIN7_GENERAL_CS"] = 42] = "LATIN7_GENERAL_CS";
    Charset[Charset["MACCE_BIN"] = 43] = "MACCE_BIN";
    Charset[Charset["CP1250_CROATIAN_CI"] = 44] = "CP1250_CROATIAN_CI";
    Charset[Charset["UTF8MB4_GENERAL_CI"] = 45] = "UTF8MB4_GENERAL_CI";
    Charset[Charset["UTF8MB4_BIN"] = 46] = "UTF8MB4_BIN";
    Charset[Charset["LATIN1_BIN"] = 47] = "LATIN1_BIN";
    Charset[Charset["LATIN1_GENERAL_CI"] = 48] = "LATIN1_GENERAL_CI";
    Charset[Charset["LATIN1_GENERAL_CS"] = 49] = "LATIN1_GENERAL_CS";
    Charset[Charset["CP1251_BIN"] = 50] = "CP1251_BIN";
    Charset[Charset["CP1251_GENERAL_CI"] = 51] = "CP1251_GENERAL_CI";
    Charset[Charset["CP1251_GENERAL_CS"] = 52] = "CP1251_GENERAL_CS";
    Charset[Charset["MACROMAN_BIN"] = 53] = "MACROMAN_BIN";
    Charset[Charset["UTF16_GENERAL_CI"] = 54] = "UTF16_GENERAL_CI";
    Charset[Charset["UTF16_BIN"] = 55] = "UTF16_BIN";
    Charset[Charset["UTF16LE_GENERAL_CI"] = 56] = "UTF16LE_GENERAL_CI";
    Charset[Charset["CP1256_GENERAL_CI"] = 57] = "CP1256_GENERAL_CI";
    Charset[Charset["CP1257_BIN"] = 58] = "CP1257_BIN";
    Charset[Charset["CP1257_GENERAL_CI"] = 59] = "CP1257_GENERAL_CI";
    Charset[Charset["UTF32_GENERAL_CI"] = 60] = "UTF32_GENERAL_CI";
    Charset[Charset["UTF32_BIN"] = 61] = "UTF32_BIN";
    Charset[Charset["UTF16LE_BIN"] = 62] = "UTF16LE_BIN";
    Charset[Charset["BINARY"] = 63] = "BINARY";
    Charset[Charset["ARMSCII8_BIN"] = 64] = "ARMSCII8_BIN";
    Charset[Charset["ASCII_BIN"] = 65] = "ASCII_BIN";
    Charset[Charset["CP1250_BIN"] = 66] = "CP1250_BIN";
    Charset[Charset["CP1256_BIN"] = 67] = "CP1256_BIN";
    Charset[Charset["CP866_BIN"] = 68] = "CP866_BIN";
    Charset[Charset["DEC8_BIN"] = 69] = "DEC8_BIN";
    Charset[Charset["GREEK_BIN"] = 70] = "GREEK_BIN";
    Charset[Charset["HEBREW_BIN"] = 71] = "HEBREW_BIN";
    Charset[Charset["HP8_BIN"] = 72] = "HP8_BIN";
    Charset[Charset["KEYBCS2_BIN"] = 73] = "KEYBCS2_BIN";
    Charset[Charset["KOI8R_BIN"] = 74] = "KOI8R_BIN";
    Charset[Charset["KOI8U_BIN"] = 75] = "KOI8U_BIN";
    Charset[Charset["LATIN2_BIN"] = 77] = "LATIN2_BIN";
    Charset[Charset["LATIN5_BIN"] = 78] = "LATIN5_BIN";
    Charset[Charset["LATIN7_BIN"] = 79] = "LATIN7_BIN";
    Charset[Charset["CP850_BIN"] = 80] = "CP850_BIN";
    Charset[Charset["CP852_BIN"] = 81] = "CP852_BIN";
    Charset[Charset["SWE7_BIN"] = 82] = "SWE7_BIN";
    Charset[Charset["UTF8_BIN"] = 83] = "UTF8_BIN";
    Charset[Charset["BIG5_BIN"] = 84] = "BIG5_BIN";
    Charset[Charset["EUCKR_BIN"] = 85] = "EUCKR_BIN";
    Charset[Charset["GB2312_BIN"] = 86] = "GB2312_BIN";
    Charset[Charset["GBK_BIN"] = 87] = "GBK_BIN";
    Charset[Charset["SJIS_BIN"] = 88] = "SJIS_BIN";
    Charset[Charset["TIS620_BIN"] = 89] = "TIS620_BIN";
    Charset[Charset["UCS2_BIN"] = 90] = "UCS2_BIN";
    Charset[Charset["UJIS_BIN"] = 91] = "UJIS_BIN";
    Charset[Charset["GEOSTD8_GENERAL_CI"] = 92] = "GEOSTD8_GENERAL_CI";
    Charset[Charset["GEOSTD8_BIN"] = 93] = "GEOSTD8_BIN";
    Charset[Charset["LATIN1_SPANISH_CI"] = 94] = "LATIN1_SPANISH_CI";
    Charset[Charset["CP932_JAPANESE_CI"] = 95] = "CP932_JAPANESE_CI";
    Charset[Charset["CP932_BIN"] = 96] = "CP932_BIN";
    Charset[Charset["EUCJPMS_JAPANESE_CI"] = 97] = "EUCJPMS_JAPANESE_CI";
    Charset[Charset["EUCJPMS_BIN"] = 98] = "EUCJPMS_BIN";
    Charset[Charset["CP1250_POLISH_CI"] = 99] = "CP1250_POLISH_CI";
    Charset[Charset["UTF16_UNICODE_CI"] = 101] = "UTF16_UNICODE_CI";
    Charset[Charset["UTF16_ICELANDIC_CI"] = 102] = "UTF16_ICELANDIC_CI";
    Charset[Charset["UTF16_LATVIAN_CI"] = 103] = "UTF16_LATVIAN_CI";
    Charset[Charset["UTF16_ROMANIAN_CI"] = 104] = "UTF16_ROMANIAN_CI";
    Charset[Charset["UTF16_SLOVENIAN_CI"] = 105] = "UTF16_SLOVENIAN_CI";
    Charset[Charset["UTF16_POLISH_CI"] = 106] = "UTF16_POLISH_CI";
    Charset[Charset["UTF16_ESTONIAN_CI"] = 107] = "UTF16_ESTONIAN_CI";
    Charset[Charset["UTF16_SPANISH_CI"] = 108] = "UTF16_SPANISH_CI";
    Charset[Charset["UTF16_SWEDISH_CI"] = 109] = "UTF16_SWEDISH_CI";
    Charset[Charset["UTF16_TURKISH_CI"] = 110] = "UTF16_TURKISH_CI";
    Charset[Charset["UTF16_CZECH_CI"] = 111] = "UTF16_CZECH_CI";
    Charset[Charset["UTF16_DANISH_CI"] = 112] = "UTF16_DANISH_CI";
    Charset[Charset["UTF16_LITHUANIAN_CI"] = 113] = "UTF16_LITHUANIAN_CI";
    Charset[Charset["UTF16_SLOVAK_CI"] = 114] = "UTF16_SLOVAK_CI";
    Charset[Charset["UTF16_SPANISH2_CI"] = 115] = "UTF16_SPANISH2_CI";
    Charset[Charset["UTF16_ROMAN_CI"] = 116] = "UTF16_ROMAN_CI";
    Charset[Charset["UTF16_PERSIAN_CI"] = 117] = "UTF16_PERSIAN_CI";
    Charset[Charset["UTF16_ESPERANTO_CI"] = 118] = "UTF16_ESPERANTO_CI";
    Charset[Charset["UTF16_HUNGARIAN_CI"] = 119] = "UTF16_HUNGARIAN_CI";
    Charset[Charset["UTF16_SINHALA_CI"] = 120] = "UTF16_SINHALA_CI";
    Charset[Charset["UTF16_GERMAN2_CI"] = 121] = "UTF16_GERMAN2_CI";
    Charset[Charset["UTF16_CROATIAN_MYSQL561_CI"] = 122] = "UTF16_CROATIAN_MYSQL561_CI";
    Charset[Charset["UTF16_UNICODE_520_CI"] = 123] = "UTF16_UNICODE_520_CI";
    Charset[Charset["UTF16_VIETNAMESE_CI"] = 124] = "UTF16_VIETNAMESE_CI";
    Charset[Charset["UCS2_UNICODE_CI"] = 128] = "UCS2_UNICODE_CI";
    Charset[Charset["UCS2_ICELANDIC_CI"] = 129] = "UCS2_ICELANDIC_CI";
    Charset[Charset["UCS2_LATVIAN_CI"] = 130] = "UCS2_LATVIAN_CI";
    Charset[Charset["UCS2_ROMANIAN_CI"] = 131] = "UCS2_ROMANIAN_CI";
    Charset[Charset["UCS2_SLOVENIAN_CI"] = 132] = "UCS2_SLOVENIAN_CI";
    Charset[Charset["UCS2_POLISH_CI"] = 133] = "UCS2_POLISH_CI";
    Charset[Charset["UCS2_ESTONIAN_CI"] = 134] = "UCS2_ESTONIAN_CI";
    Charset[Charset["UCS2_SPANISH_CI"] = 135] = "UCS2_SPANISH_CI";
    Charset[Charset["UCS2_SWEDISH_CI"] = 136] = "UCS2_SWEDISH_CI";
    Charset[Charset["UCS2_TURKISH_CI"] = 137] = "UCS2_TURKISH_CI";
    Charset[Charset["UCS2_CZECH_CI"] = 138] = "UCS2_CZECH_CI";
    Charset[Charset["UCS2_DANISH_CI"] = 139] = "UCS2_DANISH_CI";
    Charset[Charset["UCS2_LITHUANIAN_CI"] = 140] = "UCS2_LITHUANIAN_CI";
    Charset[Charset["UCS2_SLOVAK_CI"] = 141] = "UCS2_SLOVAK_CI";
    Charset[Charset["UCS2_SPANISH2_CI"] = 142] = "UCS2_SPANISH2_CI";
    Charset[Charset["UCS2_ROMAN_CI"] = 143] = "UCS2_ROMAN_CI";
    Charset[Charset["UCS2_PERSIAN_CI"] = 144] = "UCS2_PERSIAN_CI";
    Charset[Charset["UCS2_ESPERANTO_CI"] = 145] = "UCS2_ESPERANTO_CI";
    Charset[Charset["UCS2_HUNGARIAN_CI"] = 146] = "UCS2_HUNGARIAN_CI";
    Charset[Charset["UCS2_SINHALA_CI"] = 147] = "UCS2_SINHALA_CI";
    Charset[Charset["UCS2_GERMAN2_CI"] = 148] = "UCS2_GERMAN2_CI";
    Charset[Charset["UCS2_CROATIAN_MYSQL561_CI"] = 149] = "UCS2_CROATIAN_MYSQL561_CI";
    Charset[Charset["UCS2_UNICODE_520_CI"] = 150] = "UCS2_UNICODE_520_CI";
    Charset[Charset["UCS2_VIETNAMESE_CI"] = 151] = "UCS2_VIETNAMESE_CI";
    Charset[Charset["UCS2_GENERAL_MYSQL500_CI"] = 159] = "UCS2_GENERAL_MYSQL500_CI";
    Charset[Charset["UTF32_UNICODE_CI"] = 160] = "UTF32_UNICODE_CI";
    Charset[Charset["UTF32_ICELANDIC_CI"] = 161] = "UTF32_ICELANDIC_CI";
    Charset[Charset["UTF32_LATVIAN_CI"] = 162] = "UTF32_LATVIAN_CI";
    Charset[Charset["UTF32_ROMANIAN_CI"] = 163] = "UTF32_ROMANIAN_CI";
    Charset[Charset["UTF32_SLOVENIAN_CI"] = 164] = "UTF32_SLOVENIAN_CI";
    Charset[Charset["UTF32_POLISH_CI"] = 165] = "UTF32_POLISH_CI";
    Charset[Charset["UTF32_ESTONIAN_CI"] = 166] = "UTF32_ESTONIAN_CI";
    Charset[Charset["UTF32_SPANISH_CI"] = 167] = "UTF32_SPANISH_CI";
    Charset[Charset["UTF32_SWEDISH_CI"] = 168] = "UTF32_SWEDISH_CI";
    Charset[Charset["UTF32_TURKISH_CI"] = 169] = "UTF32_TURKISH_CI";
    Charset[Charset["UTF32_CZECH_CI"] = 170] = "UTF32_CZECH_CI";
    Charset[Charset["UTF32_DANISH_CI"] = 171] = "UTF32_DANISH_CI";
    Charset[Charset["UTF32_LITHUANIAN_CI"] = 172] = "UTF32_LITHUANIAN_CI";
    Charset[Charset["UTF32_SLOVAK_CI"] = 173] = "UTF32_SLOVAK_CI";
    Charset[Charset["UTF32_SPANISH2_CI"] = 174] = "UTF32_SPANISH2_CI";
    Charset[Charset["UTF32_ROMAN_CI"] = 175] = "UTF32_ROMAN_CI";
    Charset[Charset["UTF32_PERSIAN_CI"] = 176] = "UTF32_PERSIAN_CI";
    Charset[Charset["UTF32_ESPERANTO_CI"] = 177] = "UTF32_ESPERANTO_CI";
    Charset[Charset["UTF32_HUNGARIAN_CI"] = 178] = "UTF32_HUNGARIAN_CI";
    Charset[Charset["UTF32_SINHALA_CI"] = 179] = "UTF32_SINHALA_CI";
    Charset[Charset["UTF32_GERMAN2_CI"] = 180] = "UTF32_GERMAN2_CI";
    Charset[Charset["UTF32_CROATIAN_MYSQL561_CI"] = 181] = "UTF32_CROATIAN_MYSQL561_CI";
    Charset[Charset["UTF32_UNICODE_520_CI"] = 182] = "UTF32_UNICODE_520_CI";
    Charset[Charset["UTF32_VIETNAMESE_CI"] = 183] = "UTF32_VIETNAMESE_CI";
    Charset[Charset["UTF8_UNICODE_CI"] = 192] = "UTF8_UNICODE_CI";
    Charset[Charset["UTF8_ICELANDIC_CI"] = 193] = "UTF8_ICELANDIC_CI";
    Charset[Charset["UTF8_LATVIAN_CI"] = 194] = "UTF8_LATVIAN_CI";
    Charset[Charset["UTF8_ROMANIAN_CI"] = 195] = "UTF8_ROMANIAN_CI";
    Charset[Charset["UTF8_SLOVENIAN_CI"] = 196] = "UTF8_SLOVENIAN_CI";
    Charset[Charset["UTF8_POLISH_CI"] = 197] = "UTF8_POLISH_CI";
    Charset[Charset["UTF8_ESTONIAN_CI"] = 198] = "UTF8_ESTONIAN_CI";
    Charset[Charset["UTF8_SPANISH_CI"] = 199] = "UTF8_SPANISH_CI";
    Charset[Charset["UTF8_SWEDISH_CI"] = 200] = "UTF8_SWEDISH_CI";
    Charset[Charset["UTF8_TURKISH_CI"] = 201] = "UTF8_TURKISH_CI";
    Charset[Charset["UTF8_CZECH_CI"] = 202] = "UTF8_CZECH_CI";
    Charset[Charset["UTF8_DANISH_CI"] = 203] = "UTF8_DANISH_CI";
    Charset[Charset["UTF8_LITHUANIAN_CI"] = 204] = "UTF8_LITHUANIAN_CI";
    Charset[Charset["UTF8_SLOVAK_CI"] = 205] = "UTF8_SLOVAK_CI";
    Charset[Charset["UTF8_SPANISH2_CI"] = 206] = "UTF8_SPANISH2_CI";
    Charset[Charset["UTF8_ROMAN_CI"] = 207] = "UTF8_ROMAN_CI";
    Charset[Charset["UTF8_PERSIAN_CI"] = 208] = "UTF8_PERSIAN_CI";
    Charset[Charset["UTF8_ESPERANTO_CI"] = 209] = "UTF8_ESPERANTO_CI";
    Charset[Charset["UTF8_HUNGARIAN_CI"] = 210] = "UTF8_HUNGARIAN_CI";
    Charset[Charset["UTF8_SINHALA_CI"] = 211] = "UTF8_SINHALA_CI";
    Charset[Charset["UTF8_GERMAN2_CI"] = 212] = "UTF8_GERMAN2_CI";
    Charset[Charset["UTF8_CROATIAN_MYSQL561_CI"] = 213] = "UTF8_CROATIAN_MYSQL561_CI";
    Charset[Charset["UTF8_UNICODE_520_CI"] = 214] = "UTF8_UNICODE_520_CI";
    Charset[Charset["UTF8_VIETNAMESE_CI"] = 215] = "UTF8_VIETNAMESE_CI";
    Charset[Charset["UTF8_GENERAL_MYSQL500_CI"] = 223] = "UTF8_GENERAL_MYSQL500_CI";
    Charset[Charset["UTF8MB4_UNICODE_CI"] = 224] = "UTF8MB4_UNICODE_CI";
    Charset[Charset["UTF8MB4_ICELANDIC_CI"] = 225] = "UTF8MB4_ICELANDIC_CI";
    Charset[Charset["UTF8MB4_LATVIAN_CI"] = 226] = "UTF8MB4_LATVIAN_CI";
    Charset[Charset["UTF8MB4_ROMANIAN_CI"] = 227] = "UTF8MB4_ROMANIAN_CI";
    Charset[Charset["UTF8MB4_SLOVENIAN_CI"] = 228] = "UTF8MB4_SLOVENIAN_CI";
    Charset[Charset["UTF8MB4_POLISH_CI"] = 229] = "UTF8MB4_POLISH_CI";
    Charset[Charset["UTF8MB4_ESTONIAN_CI"] = 230] = "UTF8MB4_ESTONIAN_CI";
    Charset[Charset["UTF8MB4_SPANISH_CI"] = 231] = "UTF8MB4_SPANISH_CI";
    Charset[Charset["UTF8MB4_SWEDISH_CI"] = 232] = "UTF8MB4_SWEDISH_CI";
    Charset[Charset["UTF8MB4_TURKISH_CI"] = 233] = "UTF8MB4_TURKISH_CI";
    Charset[Charset["UTF8MB4_CZECH_CI"] = 234] = "UTF8MB4_CZECH_CI";
    Charset[Charset["UTF8MB4_DANISH_CI"] = 235] = "UTF8MB4_DANISH_CI";
    Charset[Charset["UTF8MB4_LITHUANIAN_CI"] = 236] = "UTF8MB4_LITHUANIAN_CI";
    Charset[Charset["UTF8MB4_SLOVAK_CI"] = 237] = "UTF8MB4_SLOVAK_CI";
    Charset[Charset["UTF8MB4_SPANISH2_CI"] = 238] = "UTF8MB4_SPANISH2_CI";
    Charset[Charset["UTF8MB4_ROMAN_CI"] = 239] = "UTF8MB4_ROMAN_CI";
    Charset[Charset["UTF8MB4_PERSIAN_CI"] = 240] = "UTF8MB4_PERSIAN_CI";
    Charset[Charset["UTF8MB4_ESPERANTO_CI"] = 241] = "UTF8MB4_ESPERANTO_CI";
    Charset[Charset["UTF8MB4_HUNGARIAN_CI"] = 242] = "UTF8MB4_HUNGARIAN_CI";
    Charset[Charset["UTF8MB4_SINHALA_CI"] = 243] = "UTF8MB4_SINHALA_CI";
    Charset[Charset["UTF8MB4_GERMAN2_CI"] = 244] = "UTF8MB4_GERMAN2_CI";
    Charset[Charset["UTF8MB4_CROATIAN_MYSQL561_CI"] = 245] = "UTF8MB4_CROATIAN_MYSQL561_CI";
    Charset[Charset["UTF8MB4_UNICODE_520_CI"] = 246] = "UTF8MB4_UNICODE_520_CI";
    Charset[Charset["UTF8MB4_VIETNAMESE_CI"] = 247] = "UTF8MB4_VIETNAMESE_CI";
    Charset[Charset["UTF8_GENERAL50_CI"] = 253] = "UTF8_GENERAL50_CI";
    Charset[Charset["ARMSCII8"] = 32] = "ARMSCII8";
    Charset[Charset["ASCII"] = 11] = "ASCII";
    Charset[Charset["BIG5"] = 1] = "BIG5";
    Charset[Charset["CP1250"] = 26] = "CP1250";
    Charset[Charset["CP1251"] = 51] = "CP1251";
    Charset[Charset["CP1256"] = 57] = "CP1256";
    Charset[Charset["CP1257"] = 59] = "CP1257";
    Charset[Charset["CP866"] = 36] = "CP866";
    Charset[Charset["CP850"] = 4] = "CP850";
    Charset[Charset["CP852"] = 40] = "CP852";
    Charset[Charset["CP932"] = 95] = "CP932";
    Charset[Charset["DEC8"] = 3] = "DEC8";
    Charset[Charset["EUCJPMS"] = 97] = "EUCJPMS";
    Charset[Charset["EUCKR"] = 19] = "EUCKR";
    Charset[Charset["GB2312"] = 24] = "GB2312";
    Charset[Charset["GBK"] = 28] = "GBK";
    Charset[Charset["GEOSTD8"] = 92] = "GEOSTD8";
    Charset[Charset["GREEK"] = 25] = "GREEK";
    Charset[Charset["HEBREW"] = 16] = "HEBREW";
    Charset[Charset["HP8"] = 6] = "HP8";
    Charset[Charset["KEYBCS2"] = 37] = "KEYBCS2";
    Charset[Charset["KOI8R"] = 7] = "KOI8R";
    Charset[Charset["KOI8U"] = 22] = "KOI8U";
    Charset[Charset["LATIN1"] = 8] = "LATIN1";
    Charset[Charset["LATIN2"] = 9] = "LATIN2";
    Charset[Charset["LATIN5"] = 30] = "LATIN5";
    Charset[Charset["LATIN7"] = 41] = "LATIN7";
    Charset[Charset["MACCE"] = 38] = "MACCE";
    Charset[Charset["MACROMAN"] = 39] = "MACROMAN";
    Charset[Charset["SJIS"] = 13] = "SJIS";
    Charset[Charset["SWE7"] = 10] = "SWE7";
    Charset[Charset["TIS620"] = 18] = "TIS620";
    Charset[Charset["UCS2"] = 35] = "UCS2";
    Charset[Charset["UJIS"] = 12] = "UJIS";
    Charset[Charset["UTF16"] = 54] = "UTF16";
    Charset[Charset["UTF16LE"] = 56] = "UTF16LE";
    Charset[Charset["UTF8"] = 33] = "UTF8";
    Charset[Charset["UTF8MB4"] = 45] = "UTF8MB4";
    Charset[Charset["UTF32"] = 60] = "UTF32";
})(Charset || (Charset = {}));
function buildAuth(packet, params) {
    const clientParam = (params.db ? ServerCapabilities.CLIENT_CONNECT_WITH_DB : 0) | ServerCapabilities.CLIENT_PLUGIN_AUTH | ServerCapabilities.CLIENT_LONG_PASSWORD | ServerCapabilities.CLIENT_PROTOCOL_41 | ServerCapabilities.CLIENT_TRANSACTIONS | ServerCapabilities.CLIENT_MULTI_RESULTS | ServerCapabilities.CLIENT_SECURE_CONNECTION | ServerCapabilities.CLIENT_LONG_FLAG & packet.serverCapabilities | ServerCapabilities.CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA & packet.serverCapabilities | ServerCapabilities.CLIENT_DEPRECATE_EOF & packet.serverCapabilities;
    if (packet.serverCapabilities & ServerCapabilities.CLIENT_PLUGIN_AUTH) {
        const writer = new BufferWriter(new Uint8Array(1000));
        writer.writeUint32(clientParam).writeUint32(2 ** 24 - 1).write(Charset.UTF8_GENERAL_CI).skip(23).writeNullTerminatedString(params.username);
        if (params.password) {
            const authData = auth(packet.authPluginName, params.password, packet.seed);
            if (clientParam & ServerCapabilities.CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA || clientParam & ServerCapabilities.CLIENT_SECURE_CONNECTION) {
                writer.write(authData.length);
                writer.writeBuffer(authData);
            } else {
                writer.writeBuffer(authData);
                writer.write(0);
            }
        } else {
            writer.write(0);
        }
        if (clientParam & ServerCapabilities.CLIENT_CONNECT_WITH_DB && params.db) {
            writer.writeNullTerminatedString(params.db);
        }
        if (clientParam & ServerCapabilities.CLIENT_PLUGIN_AUTH) {
            writer.writeNullTerminatedString(packet.authPluginName);
        }
        return writer.wroteData;
    }
    return Uint8Array.from([]);
}
function buildQuery(sql, params = []) {
    const data = encode2(replaceParams(sql, params));
    const writer = new BufferWriter(new Uint8Array(data.length + 1));
    writer.write(0x03);
    writer.writeBuffer(data);
    return writer.buffer;
}
var PacketType;
(function(PacketType) {
    PacketType[PacketType["OK_Packet"] = 0x00] = "OK_Packet";
    PacketType[PacketType["EOF_Packet"] = 0xfe] = "EOF_Packet";
    PacketType[PacketType["ERR_Packet"] = 0xff] = "ERR_Packet";
    PacketType[PacketType["Result"] = 256] = "Result";
})(PacketType || (PacketType = {}));
class SendPacket {
    header;
    constructor(body, no){
        this.body = body;
        this.header = {
            size: body.length,
            no
        };
    }
    async send(conn) {
        const body = this.body;
        const data = new BufferWriter(new Uint8Array(4 + body.length));
        data.writeUints(3, this.header.size);
        data.write(this.header.no);
        data.writeBuffer(body);
        logger.debug(`send: ${data.length}B \n${format(data.buffer)}\n`);
        try {
            let wrote = 0;
            do {
                wrote += await conn.write(data.buffer.subarray(wrote));
            }while (wrote < data.length)
        } catch (error) {
            throw new WriteError(error.message);
        }
    }
    body;
}
class ReceivePacket {
    header;
    body;
    type;
    async parse(reader) {
        const header = new BufferReader(new Uint8Array(4));
        let readCount = 0;
        let nread = await this.read(reader, header.buffer);
        if (nread === null) return null;
        readCount = nread;
        const bodySize = header.readUints(3);
        this.header = {
            size: bodySize,
            no: header.readUint8()
        };
        this.body = new BufferReader(new Uint8Array(bodySize));
        nread = await this.read(reader, this.body.buffer);
        if (nread === null) return null;
        readCount += nread;
        const { OK_Packet , ERR_Packet , EOF_Packet , Result  } = PacketType;
        switch(this.body.buffer[0]){
            case OK_Packet:
                this.type = OK_Packet;
                break;
            case 0xff:
                this.type = ERR_Packet;
                break;
            case 0xfe:
                this.type = EOF_Packet;
                break;
            default:
                this.type = Result;
                break;
        }
        debug1(()=>{
            const data = new Uint8Array(readCount);
            data.set(header.buffer);
            data.set(this.body.buffer, 4);
            logger.debug(`receive: ${readCount}B, size = ${this.header.size}, no = ${this.header.no} \n${format(data)}\n`);
        });
        return this;
    }
    async read(reader, buffer) {
        const size = buffer.length;
        let haveRead = 0;
        while(haveRead < size){
            const nread = await reader.read(buffer.subarray(haveRead));
            if (nread === null) return null;
            haveRead += nread;
        }
        return haveRead;
    }
}
function parseError(reader, conn) {
    const code = reader.readUint16();
    const packet = {
        code,
        message: ""
    };
    if (conn.capabilities & ServerCapabilities.CLIENT_PROTOCOL_41) {
        packet.sqlStateMarker = reader.readUint8();
        packet.sqlState = reader.readUints(5);
    }
    packet.message = reader.readNullTerminatedString();
    return packet;
}
function parseHandshake(reader) {
    const protocolVersion = reader.readUint8();
    const serverVersion = reader.readNullTerminatedString();
    const threadId = reader.readUint32();
    const seedWriter = new BufferWriter(new Uint8Array(20));
    seedWriter.writeBuffer(reader.readBuffer(8));
    reader.skip(1);
    let serverCapabilities = reader.readUint16();
    let characterSet = 0, statusFlags = 0, authPluginDataLength = 0, authPluginName = "";
    if (!reader.finished) {
        characterSet = reader.readUint8();
        statusFlags = reader.readUint16();
        serverCapabilities |= reader.readUint16() << 16;
        if ((serverCapabilities & ServerCapabilities.CLIENT_PLUGIN_AUTH) != 0) {
            authPluginDataLength = reader.readUint8();
        } else {
            reader.skip(1);
        }
        reader.skip(10);
        if ((serverCapabilities & ServerCapabilities.CLIENT_SECURE_CONNECTION) != 0) {
            seedWriter.writeBuffer(reader.readBuffer(Math.max(13, authPluginDataLength - 8)));
        }
        if ((serverCapabilities & ServerCapabilities.CLIENT_PLUGIN_AUTH) != 0) {
            authPluginName = reader.readNullTerminatedString();
        }
    }
    return {
        protocolVersion,
        serverVersion,
        threadId,
        seed: seedWriter.buffer,
        serverCapabilities,
        characterSet,
        statusFlags,
        authPluginName
    };
}
var AuthResult;
(function(AuthResult) {
    AuthResult[AuthResult["AuthPassed"] = 0] = "AuthPassed";
    AuthResult[AuthResult["MethodMismatch"] = 1] = "MethodMismatch";
    AuthResult[AuthResult["AuthMoreRequired"] = 2] = "AuthMoreRequired";
})(AuthResult || (AuthResult = {}));
function parseAuth(packet) {
    switch(packet.type){
        case PacketType.EOF_Packet:
            return AuthResult.MethodMismatch;
        case PacketType.Result:
            return AuthResult.AuthMoreRequired;
        case PacketType.OK_Packet:
            return AuthResult.AuthPassed;
        default:
            return AuthResult.AuthPassed;
    }
}
function parseField(reader) {
    const catalog = reader.readLenCodeString();
    const schema = reader.readLenCodeString();
    const table = reader.readLenCodeString();
    const originTable = reader.readLenCodeString();
    const name = reader.readLenCodeString();
    const originName = reader.readLenCodeString();
    reader.skip(1);
    const encoding = reader.readUint16();
    const fieldLen = reader.readUint32();
    const fieldType = reader.readUint8();
    const fieldFlag = reader.readUint16();
    const decimals = reader.readUint8();
    reader.skip(1);
    const defaultVal = reader.readLenCodeString();
    return {
        catalog,
        schema,
        table,
        originName,
        fieldFlag,
        originTable,
        fieldLen,
        name,
        fieldType,
        encoding,
        decimals,
        defaultVal
    };
}
function parseRow(reader, fields) {
    const row = {};
    for (const field of fields){
        const name = field.name;
        const val = reader.readLenCodeString();
        row[name] = val === null ? null : convertType(field, val);
    }
    return row;
}
function convertType(field, val) {
    const { fieldType , fieldLen  } = field;
    switch(fieldType){
        case 0x00:
        case 0x05:
        case 0x04:
        case 0x12:
            return parseFloat(val);
        case 0xf6:
            return val;
        case 0x01:
        case 0x02:
        case 0x03:
        case 0x09:
            return parseInt(val);
        case 0x08:
            if (Number(val) < Number.MIN_SAFE_INTEGER || Number(val) > Number.MAX_SAFE_INTEGER) {
                return BigInt(val);
            } else {
                return parseInt(val);
            }
        case 0x0f:
        case 0xfd:
        case 0xfe:
        case 0x0b:
        case 0x13:
            return val;
        case 0x0a:
        case 0x07:
        case 0x0c:
        case 0x0e:
        case 0x11:
        case 0x12:
            return new Date(val);
        default:
            return val;
    }
}
async function encryptWithPublicKey(key, data) {
    const pemHeader = "-----BEGIN PUBLIC KEY-----\n";
    const pemFooter = "\n-----END PUBLIC KEY-----";
    key = key.trim();
    key = key.substring(pemHeader.length, key.length - pemFooter.length);
    const importedKey = await crypto.subtle.importKey("spki", decode(key), {
        name: "RSA-OAEP",
        hash: "SHA-256"
    }, false, [
        "encrypt"
    ]);
    return await crypto.subtle.encrypt({
        name: "RSA-OAEP"
    }, importedKey, data);
}
let scramble, password;
async function start(scramble_, password_) {
    scramble = scramble_;
    password = password_;
    return {
        done: false,
        next: authMoreResponse
    };
}
async function authMoreResponse(packet) {
    let AuthStatusFlags;
    (function(AuthStatusFlags) {
        AuthStatusFlags[AuthStatusFlags["FullAuth"] = 0x04] = "FullAuth";
        AuthStatusFlags[AuthStatusFlags["FastPath"] = 0x03] = "FastPath";
    })(AuthStatusFlags || (AuthStatusFlags = {}));
    const REQUEST_PUBLIC_KEY = 0x02;
    const statusFlag = packet.body.skip(1).readUint8();
    let authMoreData, done = true, next, quickRead = false;
    if (statusFlag === 0x04) {
        authMoreData = new Uint8Array([
            REQUEST_PUBLIC_KEY
        ]);
        done = false;
        next = encryptWithKey;
    }
    if (statusFlag === 0x03) {
        done = false;
        quickRead = true;
        next = terminate;
    }
    return {
        done,
        next,
        quickRead,
        data: authMoreData
    };
}
async function encryptWithKey(packet) {
    const publicKey = parsePublicKey(packet);
    const len = password.length;
    const passwordBuffer = new Uint8Array(len + 1);
    for(let n = 0; n < len; n++){
        passwordBuffer[n] = password.charCodeAt(n);
    }
    passwordBuffer[len] = 0x00;
    const encryptedPassword = await encrypt(passwordBuffer, scramble, publicKey);
    return {
        done: false,
        next: terminate,
        data: new Uint8Array(encryptedPassword)
    };
}
function parsePublicKey(packet) {
    return packet.body.skip(1).readNullTerminatedString();
}
async function encrypt(password, scramble, key) {
    const stage1 = xor(password, scramble);
    return await encryptWithPublicKey(key, stage1);
}
function terminate() {
    return {
        done: true
    };
}
const mod1 = {
    start: start
};
const __default = {
    caching_sha2_password: mod1
};
function parseAuthSwitch(reader) {
    const status = reader.readUint8();
    const authPluginName = reader.readNullTerminatedString();
    const authPluginData = reader.readRestOfPacketString();
    return {
        status,
        authPluginName,
        authPluginData
    };
}
var ConnectionState;
(function(ConnectionState) {
    ConnectionState[ConnectionState["CONNECTING"] = 0] = "CONNECTING";
    ConnectionState[ConnectionState["CONNECTED"] = 1] = "CONNECTED";
    ConnectionState[ConnectionState["CLOSING"] = 2] = "CLOSING";
    ConnectionState[ConnectionState["CLOSED"] = 3] = "CLOSED";
})(ConnectionState || (ConnectionState = {}));
class Connection {
    state;
    capabilities;
    serverVersion;
    conn;
    _timedOut;
    get remoteAddr() {
        return this.config.socketPath ? `unix:${this.config.socketPath}` : `${this.config.hostname}:${this.config.port}`;
    }
    constructor(config){
        this.config = config;
        this.state = ConnectionState.CONNECTING;
        this.capabilities = 0;
        this.serverVersion = "";
        this.conn = undefined;
        this._timedOut = false;
        this._timeoutCallback = ()=>{
            logger.info("connection read timed out");
            this._timedOut = true;
            this.close();
        };
    }
    async _connect() {
        const { hostname , port =3306 , socketPath , username ="" , password  } = this.config;
        logger.info(`connecting ${this.remoteAddr}`);
        this.conn = !socketPath ? await Deno.connect({
            transport: "tcp",
            hostname,
            port
        }) : await Deno.connect({
            transport: "unix",
            path: socketPath
        });
        try {
            let receive = await this.nextPacket();
            const handshakePacket = parseHandshake(receive.body);
            const data = buildAuth(handshakePacket, {
                username,
                password,
                db: this.config.db
            });
            await new SendPacket(data, 0x1).send(this.conn);
            this.state = ConnectionState.CONNECTING;
            this.serverVersion = handshakePacket.serverVersion;
            this.capabilities = handshakePacket.serverCapabilities;
            receive = await this.nextPacket();
            const authResult = parseAuth(receive);
            let handler;
            switch(authResult){
                case AuthResult.AuthMoreRequired:
                    const adaptedPlugin = __default[handshakePacket.authPluginName];
                    handler = adaptedPlugin;
                    break;
                case AuthResult.MethodMismatch:
                    const authSwitch = parseAuthSwitch(receive.body);
                    if (authSwitch.authPluginData === undefined || authSwitch.authPluginData.length === 0) {
                        authSwitch.authPluginData = handshakePacket.seed;
                    }
                    let authData;
                    if (password) {
                        authData = auth(authSwitch.authPluginName, password, authSwitch.authPluginData);
                    } else {
                        authData = Uint8Array.from([]);
                    }
                    await new SendPacket(authData, receive.header.no + 1).send(this.conn);
                    receive = await this.nextPacket();
                    const authSwitch2 = parseAuthSwitch(receive.body);
                    if (authSwitch2.authPluginName !== "") {
                        throw new Error("Do not allow to change the auth plugin more than once!");
                    }
            }
            let result;
            if (handler) {
                result = await handler.start(handshakePacket.seed, password);
                while(!result.done){
                    if (result.data) {
                        const sequenceNumber = receive.header.no + 1;
                        await new SendPacket(result.data, sequenceNumber).send(this.conn);
                        receive = await this.nextPacket();
                    }
                    if (result.quickRead) {
                        await this.nextPacket();
                    }
                    if (result.next) {
                        result = await result.next(receive);
                    }
                }
            }
            const header = receive.body.readUint8();
            if (header === 0xff) {
                const error = parseError(receive.body, this);
                logger.error(`connect error(${error.code}): ${error.message}`);
                this.close();
                throw new Error(error.message);
            } else {
                logger.info(`connected to ${this.remoteAddr}`);
                this.state = ConnectionState.CONNECTED;
            }
            if (this.config.charset) {
                await this.execute(`SET NAMES ${this.config.charset}`);
            }
        } catch (error1) {
            this.close();
            throw error1;
        }
    }
    async connect() {
        await this._connect();
    }
    async nextPacket() {
        if (!this.conn) {
            throw new ConnnectionError("Not connected");
        }
        const timeoutTimer = this.config.timeout ? setTimeout(this._timeoutCallback, this.config.timeout) : null;
        let packet;
        try {
            packet = await new ReceivePacket().parse(this.conn);
        } catch (error) {
            if (this._timedOut) {
                throw new ResponseTimeoutError("Connection read timed out");
            }
            timeoutTimer && clearTimeout(timeoutTimer);
            this.close();
            throw error;
        }
        timeoutTimer && clearTimeout(timeoutTimer);
        if (!packet) {
            this.close();
            throw new ReadError("Connection closed unexpectedly");
        }
        if (packet.type === PacketType.ERR_Packet) {
            packet.body.skip(1);
            const error1 = parseError(packet.body, this);
            throw new Error(error1.message);
        }
        return packet;
    }
    _timeoutCallback;
    close() {
        if (this.state != ConnectionState.CLOSED) {
            logger.info("close connection");
            this.conn?.close();
            this.state = ConnectionState.CLOSED;
        }
    }
    async query(sql, params) {
        const result = await this.execute(sql, params);
        if (result && result.rows) {
            return result.rows;
        } else {
            return result;
        }
    }
    async execute(sql, params, iterator = false) {
        if (this.state != ConnectionState.CONNECTED) {
            if (this.state == ConnectionState.CLOSED) {
                throw new ConnnectionError("Connection is closed");
            } else {
                throw new ConnnectionError("Must be connected first");
            }
        }
        const data = buildQuery(sql, params);
        try {
            await new SendPacket(data, 0).send(this.conn);
            let receive = await this.nextPacket();
            if (receive.type === PacketType.OK_Packet) {
                receive.body.skip(1);
                return {
                    affectedRows: receive.body.readEncodedLen(),
                    lastInsertId: receive.body.readEncodedLen()
                };
            } else if (receive.type !== PacketType.Result) {
                throw new ProtocolError();
            }
            let fieldCount = receive.body.readEncodedLen();
            const fields = [];
            while(fieldCount--){
                const packet = await this.nextPacket();
                if (packet) {
                    const field = parseField(packet.body);
                    fields.push(field);
                }
            }
            const rows = [];
            if (!(this.capabilities & ServerCapabilities.CLIENT_DEPRECATE_EOF)) {
                receive = await this.nextPacket();
                if (receive.type !== PacketType.EOF_Packet) {
                    throw new ProtocolError();
                }
            }
            if (!iterator) {
                while(true){
                    receive = await this.nextPacket();
                    if (receive.type === PacketType.EOF_Packet || receive.type === PacketType.OK_Packet) {
                        break;
                    } else {
                        const row = parseRow(receive.body, fields);
                        rows.push(row);
                    }
                }
                return {
                    rows,
                    fields
                };
            }
            return {
                fields,
                iterator: this.buildIterator(fields)
            };
        } catch (error) {
            this.close();
            throw error;
        }
    }
    buildIterator(fields) {
        const next = async ()=>{
            const receive = await this.nextPacket();
            if (receive.type === PacketType.EOF_Packet) {
                return {
                    done: true
                };
            }
            const value = parseRow(receive.body, fields);
            return {
                done: false,
                value
            };
        };
        return {
            [Symbol.asyncIterator]: ()=>{
                return {
                    next
                };
            }
        };
    }
    config;
}
class DeferredStack {
    _queue;
    _size;
    constructor(_maxSize, _array = [], creator){
        this._maxSize = _maxSize;
        this._array = _array;
        this.creator = creator;
        this._queue = [];
        this._size = 0;
        this._size = _array.length;
    }
    get size() {
        return this._size;
    }
    get maxSize() {
        return this._maxSize;
    }
    get available() {
        return this._array.length;
    }
    async pop() {
        if (this._array.length) {
            return this._array.pop();
        } else if (this._size < this._maxSize) {
            this._size++;
            let item;
            try {
                item = await this.creator();
            } catch (err) {
                this._size--;
                throw err;
            }
            return item;
        }
        const defer = deferred();
        this._queue.push(defer);
        return await defer;
    }
    push(item) {
        if (this._queue.length) {
            this._queue.shift().resolve(item);
            return false;
        } else {
            this._array.push(item);
            return true;
        }
    }
    tryPopAvailable() {
        return this._array.pop();
    }
    remove(item) {
        const index = this._array.indexOf(item);
        if (index < 0) return false;
        this._array.splice(index, 1);
        this._size--;
        return true;
    }
    reduceSize() {
        this._size--;
    }
    _maxSize;
    _array;
    creator;
}
class PoolConnection extends Connection {
    _pool = undefined;
    _idleTimer = undefined;
    _idle = false;
    enterIdle() {
        this._idle = true;
        if (this.config.idleTimeout) {
            this._idleTimer = setTimeout(()=>{
                logger.info("connection idle timeout");
                this._pool.remove(this);
                try {
                    this.close();
                } catch (error) {
                    logger.warning(`error closing idle connection`, error);
                }
            }, this.config.idleTimeout);
            try {
                Deno.unrefTimer(this._idleTimer);
            } catch (_error) {}
        }
    }
    exitIdle() {
        this._idle = false;
        if (this._idleTimer !== undefined) {
            clearTimeout(this._idleTimer);
        }
    }
    removeFromPool() {
        this._pool.reduceSize();
        this._pool = undefined;
    }
    returnToPool() {
        this._pool?.push(this);
    }
}
class ConnectionPool {
    _deferred;
    _connections = [];
    _closed = false;
    constructor(maxSize, creator){
        this._deferred = new DeferredStack(maxSize, this._connections, async ()=>{
            const conn = await creator();
            conn._pool = this;
            return conn;
        });
    }
    get info() {
        return {
            size: this._deferred.size,
            maxSize: this._deferred.maxSize,
            available: this._deferred.available
        };
    }
    push(conn) {
        if (this._closed) {
            conn.close();
            this.reduceSize();
        }
        if (this._deferred.push(conn)) {
            conn.enterIdle();
        }
    }
    async pop() {
        if (this._closed) {
            throw new Error("Connection pool is closed");
        }
        let conn = this._deferred.tryPopAvailable();
        if (conn) {
            conn.exitIdle();
        } else {
            conn = await this._deferred.pop();
        }
        return conn;
    }
    remove(conn) {
        return this._deferred.remove(conn);
    }
    close() {
        this._closed = true;
        let conn;
        while(conn = this._deferred.tryPopAvailable()){
            conn.exitIdle();
            conn.close();
            this.reduceSize();
        }
    }
    reduceSize() {
        this._deferred.reduceSize();
    }
}
class Client {
    config = {};
    _pool;
    async createConnection() {
        let connection = new PoolConnection(this.config);
        await connection.connect();
        return connection;
    }
    get pool() {
        return this._pool?.info;
    }
    async connect(config) {
        this.config = {
            hostname: "127.0.0.1",
            username: "root",
            port: 3306,
            poolSize: 1,
            timeout: 30 * 1000,
            idleTimeout: 4 * 3600 * 1000,
            ...config
        };
        Object.freeze(this.config);
        this._pool = new ConnectionPool(this.config.poolSize || 10, this.createConnection.bind(this));
        return this;
    }
    async query(sql, params) {
        return await this.useConnection(async (connection)=>{
            return await connection.query(sql, params);
        });
    }
    async execute(sql, params) {
        return await this.useConnection(async (connection)=>{
            return await connection.execute(sql, params);
        });
    }
    async useConnection(fn) {
        if (!this._pool) {
            throw new Error("Unconnected");
        }
        const connection = await this._pool.pop();
        try {
            return await fn(connection);
        } finally{
            if (connection.state == ConnectionState.CLOSED) {
                connection.removeFromPool();
            } else {
                connection.returnToPool();
            }
        }
    }
    async transaction(processor) {
        return await this.useConnection(async (connection)=>{
            try {
                await connection.execute("BEGIN");
                const result = await processor(connection);
                await connection.execute("COMMIT");
                return result;
            } catch (error) {
                if (connection.state == ConnectionState.CONNECTED) {
                    logger.info(`ROLLBACK: ${error.message}`);
                    await connection.execute("ROLLBACK");
                }
                throw error;
            }
        });
    }
    async close() {
        if (this._pool) {
            this._pool.close();
            this._pool = undefined;
        }
    }
}
export { Client as Client };
export { Connection as Connection };
export { configLogger as configLogger };
export { mod as log };

