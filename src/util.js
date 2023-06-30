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
        CHAT: 7
    },
    LIMITS: {
        CLIENT_NICKNAME_LENGTH: 128,
        CLIENT_PRODUCT_CODE_LENGTH: 9,
        CLIENT_GROUPNAME_LENGTH: 8
    },
    SOCKET_TIMEOUT: 3000, // ms
    SANITIZER: /[\x00-\x1F\x7F]+/gu
}
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
// TODO: Have AdhocClient manage timeouts
//   maybe set the socket timeout instead?
// TODO: Ratelimiting/banning
class AdhocClient {
    constructor(socket) {
        this.socket = socket
        this.ip = parseIP(socket.remoteAddress)
        this.isLoggedIn = false
        this.isDestroyed = false
        this.isConnected = false

        if (!this.ip) {
            // ip isnt valid
            this.destroy('invalid ip')
            return
        }

        console.log(`New connection from ${this.ip}`)
        this.socket.setKeepAlive(true)
        this.socket.setTimeout(COMMON.SOCKET_TIMEOUT)
        // MAYBE: .setNoDelay? we do want to proxy...
        this.socket.on('data', (data) => {
            this.onData(data)
        })
        this.socket.on('timeout', () => {
            this.destroy('socket timeout')
        })
    }
    onData(data) {
        try {
            const { opcode, result } = this.parsePacket(data)
        } catch (e) {
            switch (e.message) {
                case 'Invalid Opcode': {
                    return
                }
                default: {
                    console.error(e)
                }
            }
        }
    }
    destroy(reason) {
        this.socket.destroy()
        this.isDestroyed = true
        console.log(`Connection from ${this.ip} closed: "${reason}"`)
        return
    }
    parsePacket(packet) {
        const packetBuffer = new BufferReader(packet)
        const opcode = packetBuffer.readNext('uint8')
        let result;
        switch (opcode) {
            case COMMON.CLIENT_OPCODES.PING: {
                this.lastPing = Date.now()
                break;
            }
            case COMMON.CLIENT_OPCODES.LOGIN: {
                if (this.isLoggedIn) {
                    // already logged in, what are you doing?
                    break;
                }
                result = this.parseLogin(packetBuffer)
                // save client info
                this.macaddr = result.mac
                this.macBytes = result.macBytes
                this.nickname = result.nickname
                this.productcode = result.productcode
                console.log(`"${this.nickname}" (${this.macaddr}) started playing ${this.productcode}.`)
                this.isLoggedIn = true
                break;
            }
            case COMMON.CLIENT_OPCODES.CONNECT: {
                if (!this.isLoggedIn) {
                    // login first
                    break
                }
                result = this.parseConnect(packetBuffer)
                this.group = `${result}`
                this.isConnected = true
                console.log(`"${this.nickname}" (${this.macaddr}) has connected to ${this.productcode} group "${this.group}".`)
                break;
            }
            case COMMON.CLIENT_OPCODES.DISCONNECT: {
                if (!this.isConnected) {
                    // youre already disconnected
                    break
                }
                console.log(`"${this.nickname}" (${this.macaddr}) has disconnected from ${this.productcode} group "${this.group}".`)
                this.isConnected = false
                break;
            }
            default: {
                console.error(`Invalid Opcode ${opcode} from ${this.ip} (${this.macaddr})`)
                result = packet.toString('hex')
            }
        }
        return { opcode, result }
    }
    parseLogin(packet) {
        let loginResults = {
            nickname: "",
            mac: "",
            macBytes: [],
            productcode: ""
        }
        // read the 6 mac address bytes
        // FIXME: pls better mac addr parsin
        for (let i = 0; i < 6; i++) {
            loginResults.macBytes.push(packet.readNext('uint8').toString(16).toUpperCase())
        }
        if (loginResults.macBytes.length !== 6) {
            this.destroy('invalid mac addr')
            return
        }
        loginResults.mac = loginResults.macBytes.join(':')

        // now get the client nickname
        nickLoop:
        for (let i = 0; i < COMMON.LIMITS.CLIENT_NICKNAME_LENGTH; i++) {
            // read the next byte
            const newByte = packet.readNext('uint8')
            if (newByte === 0x00) {
                // if theres a null byte, thats the end of the string
                break nickLoop;
            }
            loginResults.nickname += String.fromCharCode(newByte)
        }
        loginResults.nickname = loginResults.nickname.replace(COMMON.SANITIZER, '')
        // the nickname field is 128 bytes and padded, so calculate how far we need to jump
        // - 1 byte because readNext adds one (uint8 size)
        const padding = COMMON.LIMITS.CLIENT_NICKNAME_LENGTH - loginResults.nickname.length - 1
        productCodeLoop:
        for (let i = 0; i < COMMON.LIMITS.CLIENT_PRODUCT_CODE_LENGTH; i++) {
            // add the padding on the first run
            const newByte = i === 0 ? packet.readNext('uint8', padding) : packet.readNext('uint8')
            if (newByte === 0x00) {
                // if theres a null byte, thats the end of the string
                break productCodeLoop;
            }
            loginResults.productcode += String.fromCharCode(newByte)
        }

        return loginResults
    }
    parseConnect(packet) {
        let groupName = ""
        groupNameLoop:
        for (let i = 0; i < COMMON.LIMITS.CLIENT_GROUPNAME_LENGTH; i++) {
            const newByte = packet.readNext('uint8')
            if (newByte === 0x00) {
                // if theres a null byte, thats the end of the string
                break groupNameLoop;
            }
            groupName += String.fromCharCode(newByte)
        }
        // sanitize groupname
        groupName = groupName.replace(COMMON.SANITIZER, '')

        // now send the BSSID code and echo their info
        const returnBSSIDPacket = Buffer.from(`${COMMON.CLIENT_OPCODES.CONNECT_BSSID.toString().padStart(2, 0)}${this.macBytes.join('')}`, 'hex')
        this.socket.write(returnBSSIDPacket)
        //this.socket.write(returnConnectPacket)
        return groupName || '__unnamed'
    }
}
// TODO: extract common data (connected clients, etc)
//   for clustering/sharding
class AdhocServer {
    constructor() {
        this.games = {}
        this.connectedClients = []
    }
    getGroupPeers(productcode, group) {
        return this.games[productcode]?.[group]
    }
    getGroups(productcode) {
        if (!this.games[productcode]) {
            return undefined
        }
        return Object.keys(this.games[productcode])
    }
    async addPeerToGroup(peer) {
        console.log(`${peer.ip} connected as "${peer.nickname}".`)

        // create the group and add the peer
        if (!this.games[peer.productcode]) {
            this.games[peer.productcode] = {}
        }
        if (!this.games[peer.productcode][peer.group]) {
            this.games[peer.productcode][peer.group] = {}
            // since a new group was created, mark this client as the creator
            this.games[peer.productcode][peer.group].macBytes = peer.macBytes
            this.games[peer.productcode][peer.group].peers = []
        }
        this.games[peer.productcode][peer.group].peers.push(peer)

        // broadcast client to group
        const clientAnnouncement = Buffer.from(`${COMMON.CLIENT_OPCODES.CONNECT.toString().padStart(2, 0)}${stringToHex(peer.nickname)}${peer.macBytes.join('')}${ipToInt(peer.ip).toString(16)}`, 'hex')
        for (const currPeer of this.games[peer.productcode][peer.group].peers) {
            if (currPeer === peer) {
                continue
            }
            const peerAnnouncement = Buffer.from(`${COMMON.CLIENT_OPCODES.CONNECT.toString().padStart(2, 0)}${stringToHex(currPeer.nickname)}${currPeer.macBytes.join('')}${ipToInt(currPeer.ip).toString(16)}`, 'hex')

            await peer.socket.write(peerAnnouncement)
            await currPeer.socket.write(clientAnnouncement)
        }
        return true
    }
    async removePeerFromGroup(peer) {
        if (!this.games[peer.productcode] || !this.games[peer.productcode][peer.group]) {
            return true
        }
        const clientAnnouncement = Buffer.from(`${COMMON.CLIENT_OPCODES.DISCONNECT.toString().padStart(2, 0)}${stringToHex(peer.nickname)}${peer.macBytes.join('')}${ipToInt(peer.ip).toString(16)}`, 'hex')
        for (const currPeer of this.games[peer.productcode][peer.group].peers) {
            if (currPeer === peer) {
                continue
            }
            const peerAnnouncement = Buffer.from(`${COMMON.CLIENT_OPCODES.DISCONNECT.toString().padStart(2, 0)}${stringToHex(currPeer.nickname)}${currPeer.macBytes.join('')}${ipToInt(currPeer.ip).toString(16)}`, 'hex')

            await peer.socket.write(peerAnnouncement)
            await currPeer.socket.write(clientAnnouncement)
        }

        const index = this.games[peer.productcode][peer.group].peers.findIndex((v) => v === peer)
        this.games[peer.productcode][peer.group].peers.splice(index, 1)
        if (this.games[peer.productcode][peer.group].peers.length === 0) {
            delete this.games[peer.productcode][peer.group]
        }
        return true
    }
    async handleConnection(conn) {
        // socket is managed by AdhocClient
        const newClient = new AdhocClient(conn)

        // wait for the client to login and connect to a group
        let loginWait = 0
        while (!newClient.isLoggedIn) {
            if (loginWait > 100) { // 100 * 10ms
                newClient.destroy('login timeout')
                break
            }
            // wait for the peer to go through the login first
            console.log(`Waiting for ${newClient.ip} to login...`)
            loginWait++
            await sleep(10)
        }

        // handle closing out here
        newClient.socket.on('close', (hadError) => {
            this.removePeerFromGroup(newClient)
            const index = this.connectedClients.findIndex(v => v === newClient)
            this.connectedClients.splice(index, 1)
            console.log(`Closed connection to ${newClient.nickname}@${newClient.ip} (${newClient.macaddr})`)
        })
        // add client to list
        this.connectedClients.push(newClient)
        this.addPeerToGroup(newClient)
    }
    async destroy() {
        for (const client of this.connectedClients) {
            await client.destroy()
        }
        process.exit()
    }
}

function parseIP(ip) {
    // check for ipv4 and strip the v6 header if it exists
    const template = /^:(ffff)?:(?!0)(?!.*\.$)((1?\d?\d|25[0-5]|2[0-4]\d)(\.|$)){4}$/
    template.test(ip) ? "" : ip = ip.replace(/^.*:/, '')
    return ip
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
    AdhocClient,
    AdhocServer,
    COMMON
}