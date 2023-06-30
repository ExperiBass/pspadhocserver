const net = require('node:net')
const { COMMON, AdhocClient, AdhocServer} = require('./util')

const adhoc = new AdhocServer()
const server = net.createServer({
    keepAlive: true
})


server.on('listening', () => {
    console.log('listening')
})

// relay connections to adhoc class
server.on('connection', (conn) => {
    adhoc.handleConnection(conn)
})
server.on('error', console.error)

server.listen(27312)
process.on('SIGINT', () => {
    adhoc.destroy()
})