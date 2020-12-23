const ipaddr = require('../lib/ipaddr.original');
// const ipaddr = require('../lib/ipaddr');

let DANGEROUS_IPS_V4 = [];
let DANGEROUS_IPS_V6 = [];
let blacklist_custom = [];
const NB_RUN = 10000;
console.log('Running benchmark it: ', NB_RUN)
console.time('ssrf-bench')
// console.log(ipaddr.IPv4.parseCIDR('169.254.0.0/16'));
for (let i = 0; i <= NB_RUN; i++) {
    //process.stdout.write('.')
    // 169.254.169.254 and 169.254.170.2 and instead blocked using a mask
    DANGEROUS_IPS_V4 = [ipaddr.IPv4.parseCIDR('169.254.0.0/16'), ipaddr.IPv4.parseCIDR('127.0.0.1/32'),
    ipaddr.IPv4.parseCIDR('10.0.0.0/8'), ipaddr.IPv4.parseCIDR('172.16.0.0/12'),
    ipaddr.IPv4.parseCIDR('192.168.0.0/16'), ipaddr.IPv4.parseCIDR('100.64.0.0/10')];

    //No need to check IPv4 tunnelling as our IP parsing library takes care of that
    DANGEROUS_IPS_V6 = [ipaddr.IPv6.parseCIDR('::1/128'), ipaddr.IPv6.parseCIDR('fc00::/7'),
    ipaddr.IPv6.parseCIDR('fe80::/10'), ipaddr.IPv6.parseCIDR('2001:db8:1234:1a00::/56')];

    blacklist_custom = {
        ipv4: ['125.0.0.1/16','126.0.0.1/16','127.0.0.1/32'],
        ipv6: ['2001:db8:1234:1a00::/56']
    }

    let params = [
        'google.',
        '127.0.0.1',
        '87.1',
        '2852039166',
        '[::ffff:a9fe:a9fe]',
        '::ffff:a9fe:a9fe',
        '[0:0:0:0:0:ffff:a9fe:a9fe]',
        '0:0:0:0:0:ffff:a9fe:a9fe',
        '127:/p/bla/blablabla.../BLABLABLA',
        '15:'.repeat(20),
        '101.'.repeat(10),
        '12.12.0.1',
        '8.8.8.8/12',
        '4.4.4.4/24'
    ];

    for (const param of params) {
        const ip = null;
        try{
            ip = ipaddr.process(param);
        }catch(e){ continue; }

        if(!ip) continue;
        if (ip.kind() === 'ipv4') {
            for(const sensitiveIP of DANGEROUS_IPS_V4) {
                if(ip.match(sensitiveIP)) {
                    //ok;
                }
            }
            if(blacklist_custom && blacklist_custom.ipv4) {
                for(const sensitiveIP of blacklist_custom.ipv4) {
                    if(ip.match(ipaddr.IPv4.parseCIDR(sensitiveIP))) {
                        //ok;
                    }
                }
            }
        } else {
            //Run the IPv6 logic
            for(const sensitiveIP of DANGEROUS_IPS_V6) {
                if(ip.match(sensitiveIP)) {
                    //ok;
                }
            }
            if(blacklist_custom && blacklist_custom.ipv6) {
                for(const sensitiveIP of blacklist_custom.ipv6) {
                    if(ip.match(ipaddr.IPv6.parseCIDR(sensitiveIP))) {
                        //ok;
                    }
                }
            }
        }
    }

}
console.timeEnd('ssrf-bench')