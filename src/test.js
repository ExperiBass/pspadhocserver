const net = require('node:net')
const AdhocServer = require('./main')

const adhoc = new AdhocServer()

adhoc.start()

process.on('SIGINT', () => {
    adhoc.destroy()
    process.exit()
})