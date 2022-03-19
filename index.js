const pcapp = require('pcap-parser')
const chalk = require('chalk')
const {clearMocksDirectory, writeMockResults} = require('./mockWriter')
const _ = require('lodash')

const packetContentsRegex = /[^]*POST\s(.*)\sHTTP\/1\.1[^]*(^{.*?)$/gm

const requests = new Map()
const parser = pcapp.parse('./sqc-portfolio-soa-impl.pcap')

console.log(chalk.green('Starting to parse pcap dump contents'))

let packetsCount = 0

parser.on('packet', (packet) => {
    const data = Buffer.from(packet.data).toString()
    if (isRESTRequest(data)) {
        const match = packetContentsRegex.exec(data)
        if (match) {
            const url = match[1]
            const body = match[2]

            if (url) {
                const bodiesOfRequest = requests.get(url)

                bodiesOfRequest
                    ? requests.set(url, bodiesOfRequest.add(body))
                    : requests.set(url, new Set([body]))
            }
        }
    }
    packetsCount++
})

parser.on('end', () => {
    console.log(chalk.green(`Finished parsing ${packetsCount} packets of pcap dump`))

    console.log(chalk.green(`Writing mock files`))
    clearMocksDirectory()
    writeMockResults(requests)
    console.log(chalk.green(`Finished writing mock files`))
});

isRESTRequest = (packetContents) => _.includes(packetContents, 'application/json')