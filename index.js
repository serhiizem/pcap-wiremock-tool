const pcapp = require('pcap-parser')
const chalk = require('chalk')
const fs = require('fs')
const path = require('path')
const _ = require('lodash')

const requestRegex = /[^]*POST\s(.*)\sHTTP\/1\.1[^]*/gm
const bodyRegex = /[^]*(^{.*?)$/gm

const requests = new Map();
const parser = pcapp.parse('./sqc-portfolio-soa-impl.pcap')

console.log(chalk.green('Starting to parse pcap dump contents'))

let packetsCount = 0;

parser.on('packet', (packet) => {
    const data = new Buffer(packet.data).toString()
    if (isRESTRequest(data)) {
        const url = extractByRegex(data, requestRegex)
        if (url) {
            const bodiesOfRequest = requests.get(url)
            const body = sanitizeBody(extractByRegex(data, bodyRegex))

            bodiesOfRequest
                ? requests.set(url, bodiesOfRequest.add(body))
                : requests.set(url, new Set([body]))
        }
    }
    packetsCount++;
})

let fileIndex = 0;

const mocksDirectory = 'mocks';

parser.on('end', () => {
    console.log(chalk.green(`Finished parsing ${packetsCount} packets of pcap dump`))

    console.log(chalk.green(`Writing mock files`))
    clearMocksDirectory()
    writeMockResults()
    console.log(chalk.green(`Finished writing mock files`))
});

clearMocksDirectory = () => {
    const files = fs.readdirSync(mocksDirectory)
    files.forEach(file => fs.unlinkSync(path.join(mocksDirectory, file)))
}

writeMockResults = () =>
    [...requests.entries()].forEach((entry, index) => {
        const url = entry[0]
        const bodies = entry[1]

        bodies.forEach(bodyPattern => {
            const output = {url, bodyPattern};

            fs.writeFileSync(
                path.join(mocksDirectory, `mock-${fileIndex++}.json`),
                JSON.stringify(output, null, 2)
            )
        })
    })


isRESTRequest = (packetContents) => _.includes(packetContents, 'application/json')

extractByRegex = (input, regex) => {
    const match = regex.exec(input);
    if (match) return match[1]
}

sanitizeBody = (body) => {
    if (body) return body.replace(/\\"/g, "")
}
