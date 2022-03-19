const fs = require('fs')
const path = require('path')

const mocksDirectory = 'mocks'

let fileIndex = 0;

const clearMocksDirectory = () => {
    const files = fs.readdirSync(mocksDirectory)
    files.forEach(file => fs.unlinkSync(path.join(mocksDirectory, file)))
}

const writeMockResults = (pcapFileName, requests) =>
    [...requests.entries()].forEach((entry, index) => {
        const url = entry[0]
        const bodies = entry[1]

        const mockName = path.parse(pcapFileName).name;

        bodies.forEach(bodyPattern => {
            const output = {url, bodyPattern}

            fs.writeFileSync(
                path.join(mocksDirectory, `${mockName}-${fileIndex++}.json`),
                JSON.stringify(output, null, 2)
            )
        })
    })

module.exports = {clearMocksDirectory, writeMockResults}