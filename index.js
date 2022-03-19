const pcapp = require('pcap-parser')
const fs = require('fs')
const chalk = require('chalk')
const {clearMocksDirectory, writeMockResults} = require('./fileSystemUtil')
const _ = require('lodash')

const pcapsDir = 'pcaps'
const requestRegex = /[^]*(GET|POST|PUT|DELETE|PATCH)\s(.*)\sHTTP\/1\.1[^]*/gm
const bodyRegex = /([^]*)(^{.*?)$/gm

const pcaps = fs.readdirSync(pcapsDir)

console.log(chalk.green('Clearing existing mocks\n'))
clearMocksDirectory()

pcaps.forEach(pcapFileName => {
    const parser = pcapp.parse(`./${pcapsDir}/${pcapFileName}`)
    console.log(chalk.green('Starting to parse pcap dump contents'))

    const requests = new Map()
    let packetsCount = 0
    parser.on('packet', (packet) => {
        const payload = Buffer.from(packet.data).toString()
        if (isRESTRequest(payload)) {
            const endpointDetails = extractEndpointDetails(payload)

            if (endpointDetails) {
                const bodiesOfRequest = requests.get(endpointDetails)
                const body = extractRequestBody(payload)

                bodiesOfRequest
                    ? requests.set(endpointDetails, bodiesOfRequest.add(body))
                    : requests.set(endpointDetails, new Set([body]))
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

extractEndpointDetails = (input) => {
    const match = requestRegex.exec(input)
    if (match) return `${match[1]} ${match[2]}`
}

extractRequestBody = (input) => {
    const match = bodyRegex.exec(input)
    if (match) return match[2]
}