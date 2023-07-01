const { COMMON, sleep, parseIP, ipToInt, stringToHex, BufferReader } = require('./util')
// TODO: Ratelimiting/banning
// TODO: better logging (console.log is blocking)
// TODO: make more robust (lots of parts just dont validate, such as client destroying)
class AdhocClient {
    #server = null
    isLoggedIn = false
    isConnectedToGroup = false
    isDestroyed = false
    lastPing = 0
    constructor(socket, server, id) {
        this.socket = socket
        this.#server = server
        this.ip = parseIP(socket.remoteAddress)
        this.id = id // for finding later

        if (!this.ip) {
            this.destroy('invalid ip')
            return
        }
        console.log(`New connection from ${this.ip}`)
        this.socket.setTimeout(COMMON.SOCKET_TIMEOUT)

        this.socket.on('data', (data) => {
            try {
                const { opcode, result } = this.#parsePacket(data)
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
        })
        this.socket.on('timeout', () => {
            this.destroy('socket timeout')
        })
        this.socket.on('close', (hadError) => {
            
        })
        // AdhocServer has a listener for closure
        this.waitForLogin()
    }
    async waitForLogin() {
        // wait for the client to login
        let loginWait = 0
        while (!this.isLoggedIn) {
            if (loginWait > 100) { // 100 * 10ms
                this.destroy('login timeout')
                return false
            }
            // wait for the peer to go through the login first
            console.log(`Waiting for ${this.ip} to login...`)
            loginWait++
            await sleep(10)
        }
    }
    async destroy(reason) {
        if (this.isConnectedToGroup) {
            // invert the output because server methods return true on success,
            // and we want isConnected to be false
            this.isConnectedToGroup = !(await this.#server.removeClientFromGroup(this))
        }
        this.isLoggedIn = !(this.#server.removeClient(this))
        this.socket.destroy()
        this.isDestroyed = this.socket.destroyed
        console.log(`Closed connection to ${this.nickname}@${this.ip} (${this.macaddr}): "${reason}"`)
        return
    }
    #parsePacket(packet) {
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
                result = this.#parseLogin(packetBuffer)
                // save client info
                this.macaddr = result.mac
                this.macBytes = result.macBytes
                this.nickname = result.nickname
                this.productcode = result.productcode
                this.isLoggedIn = this.#server.addClient(this)
                break;
            }
            case COMMON.CLIENT_OPCODES.CONNECT: {
                if (!this.isLoggedIn || this.isConnectedToGroup) {
                    // login first
                    break
                }
                result = this.#parseConnect(packetBuffer)
                this.group = `${result}`
                this.isConnectedToGroup = this.#server.addClientToGroup(this)
                break;
            }
            case COMMON.CLIENT_OPCODES.DISCONNECT: {
                if (!this.isConnectedToGroup) {
                    // youre already disconnected
                    break
                }
                this.isConnectedToGroup = !(this.#server.removeClientFromGroup(this))
                break;
            }
            default: {
                console.error(`Invalid Opcode ${opcode} from ${this.ip} (${this.macaddr})`)
                result = packet.toString('hex')
            }
        }
        return { opcode, result }
    }
    #parseLogin(packet) {
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
    #parseConnect(packet) {
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
                return
            }
            groupName += String.fromCharCode(newByte)
        }

        // now send the BSSID code and echo their info
        const returnBSSIDPacket = Buffer.from(`${COMMON.CLIENT_OPCODES.CONNECT_BSSID.toString().padStart(2, 0)}${this.macBytes.join('')}`, 'hex')
        this.socket.write(returnBSSIDPacket)

        return groupName || '__unnamed'
    }
}

// TODO: extract common data (connected clients, etc)
//   for clustering/sharding
class AdhocServer {
    #games = {}
    #connectedClients = []
    #nextId = 0
    constructor() {
    }
    getGroup(productcode, group) {
        return this.#games[productcode]?.[group]
    }
    getGroups(productcode) {
        if (!this.#games[productcode]) {
            return undefined
        }
        return Object.keys(this.#games[productcode])
    }
    addClient(client) {
        if (!client.isDestroyed) {
            this.#connectedClients.push(client)
            console.log(`"${client.nickname}" (${client.macaddr}) started playing ${client.productcode}.`)
            return true
        }
        return false
    }
    removeClient(client) {
        const index = this.#connectedClients.findIndex(v => v.id === client.id)
        if (index === -1) {
            return true
        }
        const removed = this.#connectedClients.splice(index, 1)
        return (removed.length > 0)
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

        // announce client leave to peers
        const clientAnnouncement = Buffer.from(`${COMMON.CLIENT_OPCODES.DISCONNECT.toString().padStart(2, 0)}${stringToHex(client.nickname)}${client.macBytes.join('')}${ipToInt(client.ip).toString(16)}`, 'hex')
        for (const currPeer of this.#games[client.productcode][client.group].peers) {
            if (currPeer === client) {
                continue
            }
            const peerAnnouncement = Buffer.from(`${COMMON.CLIENT_OPCODES.DISCONNECT.toString().padStart(2, 0)}${stringToHex(currPeer.nickname)}${currPeer.macBytes.join('')}${ipToInt(currPeer.ip).toString(16)}`, 'hex')

            await client.socket.write(peerAnnouncement)
            await currPeer.socket.write(clientAnnouncement)
        }

        // remove group
        if (this.#games[client.productcode][client.group].peers.length === 1) {
            // client is alone
            delete this.#games[client.productcode][client.group]
        } else {
            const index = this.#games[client.productcode][client.group].peers.findIndex((c) => c === client)
            this.#games[client.productcode][client.group].peers.splice(index, 1)
        }
        console.log(`"${client.nickname}" (${client.macaddr}) has disconnected from ${client.productcode} group "${client.group}".`)
        return true
    }
    async handleConnection(conn) {
        // socket is managed by AdhocClient
        new AdhocClient(conn, this, this.#nextId++)
    }
    async destroy() {
        for (const client of this.#connectedClients) {
            await client.destroy('server shutdown')
        }
        return true
    }
}

module.exports = AdhocServer