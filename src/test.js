const net = require('node:net')
const AdhocServer = require('./main')

const server = net.createServer(options)
const adhoc = new AdhocServer()

server.on('listening', () => {
    console.log(`listening on port ${server.address()?.port}`)
})
// relay connections to adhoc class
server.on('connection', adhoc.handleConnection)
server.on('error', console.error)
server.on('close', () => {
    process.exit()
})
try {
    server.listen(27312)
} catch (e) {
    throw e
}
process.on('SIGINT', () => {
    adhoc.destroy()
    process.exit()
})