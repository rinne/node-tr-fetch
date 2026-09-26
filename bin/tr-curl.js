#!/usr/bin/env node
'use strict';

const { main } = require('../tr-curl/main');

main(process.argv.slice(2)).then(function(code) {
    process.exitCode = code;
}, function(error) {
    process.stderr.write(`tr-curl: ${error?.stack ?? error}\n`);
    process.exitCode = 2;
});
