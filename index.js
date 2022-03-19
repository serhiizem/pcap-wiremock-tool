const pcapp = require('pcap-parser')
const fs = require('fs')
const chalk = require('chalk')
const {clearMocksDirectory, writeMockResults} = require('./fileSystemUtil')
const _ = require('lodash')

const pcapsDir = 'pcaps'
const packetContentsRegex = /[^]*(GET|POST|PUT)\s(.*)\sHTTP\/1\.1[^]*(^{.*?)$/gm

const pcaps = fs.readdirSync(pcapsDir)

console.log(chalk.green('Clearing existing mocks\n'))
clearMocksDirectory()

pcaps.forEach(pcapFileName => {
    const parser = pcapp.parse(`./${pcapsDir}/${pcapFileName}`)
    console.log(chalk.green('Starting to parse pcap dump contents'))

    const requests = new Map()
    let packetsCount = 0
    parser.on('packet', (packet) => {
        const data = Buffer.from(packet.data).toString()
        if (isRESTRequest(data)) {
            const match = packetContentsRegex.exec(data)
            if (match) {
                const url = match[2]
                const body = match[3]

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
        console.log(chalk.green(`Finished parsing ${packetsCount} ${pcapFileName} dump`))

        console.log(chalk.green(`Writing mock files`))
        writeMockResults(pcapFileName, requests)
        console.log(chalk.green(`Finished writing mock files\n\n`))
    })
})

isRESTRequest = (packetContents) => _.includes(packetContents, 'application/json')