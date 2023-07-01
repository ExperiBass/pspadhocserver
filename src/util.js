const COMMON = {
    // Opcodes and shit from https://github.com/Souler/ppsspp-adhoc-server/blob/master/src/packets.h
    CLIENT_OPCODES: {
        PING: 0,
        LOGIN: 1,
        CONNECT: 2,
        DISCONNECT: 3,
        SCAN: 4,
        SCAN_COMPLETE: 5,
        CONNECT_BSSID: 6,
        CHAT: 7 // MAYBE: implement chat? or tell client chat is unsupported?
    },
    LIMITS: {
        CLIENT_NICKNAME_LENGTH: 128,
        CLIENT_PRODUCT_CODE_LENGTH: 9,
        CLIENT_GROUPNAME_LENGTH: 8
    },
    SOCKET_TIMEOUT: 3000, // ms
    SANITIZER: /[\x00-\x1F\x7F]+/gu
}
// MAYBE: move to ts?
class BufferReader {
    constructor(buf) {
        this.buffer = Buffer.from(buf) // copy
        this.offset = 0
    }
    readNext(type, extraOffset = 0) {
        if (!this.canRead()) {
            throw Error('no more data to read')
        }
        switch (type) {
            case 'uint8': {
                this.offset += extraOffset
                const result = this.buffer.readUInt8(this.offset)
                this.offset += 1
                return result
            }
            default: {
                throw new Error("Unknown datatype")
            }
        }
    }
    canRead() {
        return (this.offset < this.buffer.length)
    }
}

function parseIP(ip) {
    // check for ipv4 and strip the v6 header if it exists
    const template = /^:(ffff)?:(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$/
    template.test(ip) ? "" : ip = ip.replace(/^.*:/, '')
    return ip || false
}
function ipToInt(ip) {
    return ip.split('.').reduce((int, value) => int * 256 + +value)
}
async function sleep(millis) {
    return new Promise(resolve => setTimeout(resolve, millis))
}
function stringToHex(str) {
    return str.split("")
        .map(c => c.charCodeAt(0).toString(16).padStart(2, "0"))
        .join("")
}

module.exports = {
    BufferReader,
    parseIP,
    ipToInt,
    sleep,
    stringToHex,
    COMMON
}