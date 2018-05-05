'use strict';

const spawn    = require("child_process").spawn;


/**
 * Attempts to enumerate DNS hostnames by brute force guessing of common subdomains. With the dns-brute.srv argument, dns-brute will also try to enumerate common DNS SRV records.
 * @param {String} domain
 * @param {Object} params
 * @return {Array}
 */
module.exports = (domain, params) => {
    params = params ? params : {};
    params.port = params.port ? params.port : "80";

    let process = spawn("nmap",
        ["-Pn", "-p", params.port, "-v4", "--script", "dns-brute", domain]);

    process.stdout.on("data", (data) => {
        console.log(data.toString());
    });
};