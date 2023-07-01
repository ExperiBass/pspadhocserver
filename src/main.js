const {COMMON, sleep, parseIP, ipToInt, stringToHex, BufferReader } = require('./util')
const net = require('node:net')
// TODO: Have AdhocClient manage timeouts
//   maybe set the socket timeout instead?
// TODO: Ratelimiting/banning
// TODO: better logging (console.log is blocking)
class AdhocClient {
    #server = null
    constructor(socket, server) {
        this.socket = socket
        this.#server = server
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
        this.socket.setTimeout(COMMON.SOCKET_TIMEOUT)
        // MAYBE: .setNoDelay? we do want to proxy...
        this.socket.on('data', (data) => {
            this.onData(data)
        })
        this.socket.on('timeout', () => {
            this.destroy('socket timeout')
        })
        // AdhocServer has a listener for closure
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
                this.isLoggedIn = true
                break;
            }
            case COMMON.CLIENT_OPCODES.CONNECT: {
                if (!this.isLoggedIn || this.isConnected) {
                    // login first
                    break
                }
                result = this.parseConnect(packetBuffer)
                this.group = `${result}`
                this.isConnected = this.#server.addClientToGroup(this)
                break;
            }
            case COMMON.CLIENT_OPCODES.DISCONNECT: {
                if (!this.isConnected) {
                    // youre already disconnected
                    break
                }
                this.isConnected = this.#server.removeClientFromGroup(this)
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
            if (newByte < 0x14 || newByte > 0x7A) {// " " - z
            }
            loginResults.nickname += String.fromCharCode(newByte)
        }
        loginResults.nickname = loginResults.nickname.replace(COMMON.SANITIZER, '')
        // the nickname field is 128 bytes and padded, so calculate how far we need to jump
        // - 1 byte because readNext adds one (uint8 size)
        const padding = COMMON.LIMITS.CLIENT_NICKNAME_LENGTH - loginResults.nickname.length - 1
        productCodeLoop:
        // TODO: validate each byte
        for (let i = 0; i < COMMON.LIMITS.CLIENT_PRODUCT_CODE_LENGTH; i++) {
            // add the padding on the first run
            const newByte = i === 0 ? packet.readNext('uint8', padding) : packet.readNext('uint8')
            if (newByte === 0x00) {
                // if theres a null byte, thats the end of the string
                break productCodeLoop
            }
            if (newByte < 0x20 || newByte > 0x7A) {
                // invalid character
                this.destroy('invalid product code byte')
                break productCodeLoop
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
                break groupNameLoop
            }
            if (newByte < 0x20 || newByte > 0x7A) {
                // invalid character
                this.destroy('invalid group name byte')
                break groupNameLoop
            }
            groupName += String.fromCharCode(newByte)
        }

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
    #games = {}
    #connectedClients = []
    constructor(addr = '0.0.0.0', options) {
        this.addr = addr
        const server = net.createServer(options)
        server.on('listening', () => {
            console.log(`listening on port ${server.address()?.port}`)
        })
        // relay connections to adhoc class
        server.on('connection', this.handleConnection)
        server.on('error', console.error)
    }
    getGroupPeers(productcode, group) {
        return this.#games[productcode]?.[group]
    }
    getGroups(productcode) {
        if (!this.#games[productcode]) {
            return undefined
        }
        return Object.keys(this.#games[productcode])
    }
    async addClientToGroup(client) {
        if (client.isDestroyed || !client.isLoggedIn || client.isConnected) {
            return false
        }

        // create the group and add the peer
        if (!this.#games[client.productcode]) {
            this.#games[client.productcode] = {}
        }
        if (!this.#games[client.productcode][client.group]) {
            this.#games[client.productcode][client.group] = {}
            // since a new group was created, mark this client as the creator
            this.#games[client.productcode][client.group].macBytes = client.macBytes
            this.#games[client.productcode][client.group].peers = []
        }
        this.#games[client.productcode][client.group].peers.push(client)

        // broadcast client to group
        // TODO: refactor into objects or somethin better
        const clientAnnouncement = Buffer.from(`${COMMON.CLIENT_OPCODES.CONNECT.toString().padStart(2, 0)}${stringToHex(client.nickname)}${client.macBytes.join('')}${ipToInt(client.ip).toString(16)}`, 'hex')
        for (const currPeer of this.#games[client.productcode][client.group].peers) {
            if (currPeer === client) {
                continue
            }
            const peerAnnouncement = Buffer.from(`${COMMON.CLIENT_OPCODES.CONNECT.toString().padStart(2, 0)}${stringToHex(currPeer.nickname)}${currPeer.macBytes.join('')}${ipToInt(currPeer.ip).toString(16)}`, 'hex')

            await client.socket.write(peerAnnouncement)
            await currPeer.socket.write(clientAnnouncement)
        }
        console.log(`"${client.nickname}" (${client.macaddr}) has connected to ${client.productcode} group "${client.group}".`)
        return true
    }
    async removeClientFromGroup(client) {
        if (client.isDestroyed || !client.isLoggedIn || !client.isConnected) {
            return false
        }
        if (!this.#games[client.productcode] || !this.#games[client.productcode][client.group]) {
            return true
        }
        const clientAnnouncement = Buffer.from(`${COMMON.CLIENT_OPCODES.DISCONNECT.toString().padStart(2, 0)}${stringToHex(client.nickname)}${client.macBytes.join('')}${ipToInt(client.ip).toString(16)}`, 'hex')
        for (const currPeer of this.#games[client.productcode][client.group].peers) {
            if (currPeer === client) {
                continue
            }
            const peerAnnouncement = Buffer.from(`${COMMON.CLIENT_OPCODES.DISCONNECT.toString().padStart(2, 0)}${stringToHex(currPeer.nickname)}${currPeer.macBytes.join('')}${ipToInt(currPeer.ip).toString(16)}`, 'hex')

            await client.socket.write(peerAnnouncement)
            await currPeer.socket.write(clientAnnouncement)
        }

        const index = this.#games[client.productcode][client.group].peers.findIndex((v) => v === client)
        this.#games[client.productcode][client.group].peers.splice(index, 1)
        if (this.#games[client.productcode][client.group].peers.length === 0) {
            delete this.#games[client.productcode][client.group]
        }
        console.log(`"${client.nickname}" (${client.macaddr}) has disconnected from ${client.productcode} group "${client.group}".`)
        return true
    }
    async handleConnection(conn) {
        // socket is managed by AdhocClient
        const newClient = new AdhocClient(conn, this)

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
        if (!newClient.isLoggedIn || newClient.isDestroyed) {
            return
        }

        // handle closing out here
        // MAYBE: refactor into AdhocClient? how would group management work?
        newClient.socket.on('close', (hadError) => {
            // MAYBE: unref socket?
            this.removeClientFromGroup(newClient)
            const index = this.#connectedClients.findIndex(v => v === newClient)
            this.#connectedClients.splice(index, 1)
            console.log(`Closed connection to ${newClient.nickname}@${newClient.ip} (${newClient.macaddr})`)
        })
        // add client to list
        this.#connectedClients.push(newClient)
        console.log(`"${newClient.nickname}" (${newClient.macaddr}) started playing ${newClient.productcode}.`)
    }
    async destroy() {
        for (const client of this.#connectedClients) {
            await client.destroy('server shutdown')
        }
        return true
    }
    start() {
        try {
            server.listen(27312, this.addr)
            return true
        } catch(e) {
            throw e
        }
    }
}

module.exports = AdhocServer