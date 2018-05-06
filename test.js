'use strict';

const nmap     = require("./index").nmap;


let dnsEnumScanner = nmap.dnsEnum("google.com");

dnsEnumScanner.onProcess(output => {
    console.log(output);
});

dnsEnumScanner.onDone(api => {
    console.log(api);
});