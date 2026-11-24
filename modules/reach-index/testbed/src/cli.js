// Banc d'essai reach-index : minimist est importé ET appelé.
const parseArgs = require('minimist')

function main () {
  const argv = parseArgs(process.argv.slice(2))
  return argv
}

module.exports = { main }
