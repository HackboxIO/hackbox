'use strict';

const spawn    = require("child_process").spawn;
const cheerio  = require("cheerio");


/**
 * Attempts to enumerate DNS hostnames by brute force guessing of common subdomains. With the dns-brute.srv argument, dns-brute will also try to enumerate common DNS SRV records.
 * @param {String} domain
 * @param {Object} params
 * @return {Array}
 */
module.exports = (domain, params) => {
    params = params ? params : {};
    params.port = params.port ? params.port : "80";
    let self = {};
    let api = {
        info: [],
        output: []
    };
    let process = spawn("nmap",
        ["-Pn", "-T4", "-p", params.port, "-v4", "-oX", "-", "--script", "dns-brute", domain]);

    self.onDone = (callback) => {
        process.on("close", () => {
            callback(api);
        });
    };

    self.kill = () => {
        process.stdin.pause();
        process.kill();
    };

    self.onProcess = (callback) => {
        callback(`+ DNSEnum v0.1.0 - HackBox.IO`);
        callback("---------------------------------");
        callback("+ Initializing scan...");
        process.stdout.on("data", (data) => {
            let $ = cheerio.load(data.toString());

            $("taskbegin").each((i, element) => {
                if ($(element).attr("task") === "Connect Scan") {
                    callback("+ Connecting...");
                    callback("+ Trying to enumerate DNS...");
                }
            });

            $("status").each((i, element) => {
                if ($(element).attr("state") === "up") {
                    callback("+ Target host is UP!");
                } else {
                    callback("- Looks like target host is DOWN!");
                }
            });

            $("address").each((i, element) => {
                callback("---------------------------------");
                element = $(element);
                api.info.push({ key: "Target address", value: element.attr("addr") });
                api.info.push({ key: "Address type", value: element.attr("addrtype") });
                callback(`+ Target address:   ${element.attr("addr")}`);
                callback(`+ Address type:     ${element.attr("addrtype")}`);
            });

            $("hostname").each((i, element) => {
                element = $(element);
                api.info.push({ key: "Hostname", value: element.attr("name") });
                api.info.push({ key: "Host type", value: element.attr("type") });
                callback(`+ Hostname:         ${element.attr("name")}`);
                callback(`+ Host type:        ${element.attr("type")}`);
            });

            $("ports").children().each((i, element) => {
                element = $(element);
                api.info.push({ key: "Connected port", value: element.attr("portid") });
                api.info.push({ key: "Protocol", value: element.attr("protocol") });
                api.info.push({ key: "Connection state", value: element.find("state").attr("state") });
                api.info.push({ key: "Running service", value: element.find("service").attr("name") });
                callback(`+ Connected port:   ${element.attr("portid")}`);
                callback(`+ Protocol:         ${element.attr("protocol")}`);
                callback(`+ Connection state: ${element.find("state").attr("state")}`);
                callback(`+ Running service:  ${element.find("service").attr("name")}`);
            });

            $("hostscript").each((i, element) => {
                element = $(element);
                element.children().each((i, child) => {
                    let lines = $(child).attr("output").trim().replace("DNS Brute-force hostnames:", "").split("\n");
                    callback("---------------------------------");
                    callback("+ Found hostnames:");
                    callback("---------------------------------");
                    lines.map(line => {
                        line = line.trim();
                        if (line !== "") {
                            callback(`+ ${line}`);
                            let n = line.split(" - ");
                            let type = "IPv4";

                            if (n[1].indexOf(":") > -1) {
                                type = "IPv6";
                            }

                            api.output.push({
                                "domain": n[0].trim(),
                                "ip": n[1].trim(),
                                "type": type
                            });
                        }
                    });
                });
            });

            // callback(data.toString());
        });
    };

    self.onError = (callback) => {
        process.stderr.on("data", (data) => {
            callback("- Encounter an error while running the scan :(");
            process.stdin.pause();
            process.kill();
        });
    };

    return self;
};