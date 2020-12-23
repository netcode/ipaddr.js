'use strict';

const assert = require('assert');

const ipaddr = require('../lib/ipaddr');

describe('ipaddr', () => {

    it('should define main classes', (done) => {
        assert.ok(ipaddr.IPv4, 'defines IPv4 class');
        assert.ok(ipaddr.IPv6, 'defines IPv6 class');
        done();
    })

    it('can construct IPv4 from octets', (done) => {
        const IPV4 = new ipaddr.IPv4([192, 168, 1, 2]);
        assert.ok(IPV4.init())
        done();
    })

    it('refuses to construct invalid IPv4', (done) => {
        const IPV4_1 = new ipaddr.IPv4([300, 1, 2, 3]);
        assert.strictEqual(IPV4_1.init(), false)

        const IPV4_2 = new ipaddr.IPv4([8, 8, 8]);
        assert.strictEqual(IPV4_2.init(), false)

        done();
    })

    it('converts IPv4 to string correctly', (done) => {
        let addr = new ipaddr.IPv4([192, 168, 1, 1]);
        addr.init()
        assert.strictEqual(addr.toString(), '192.168.1.1');
        assert.strictEqual(addr.toNormalizedString(), '192.168.1.1');
        done();
    })

    it('returns correct kind for IPv4', (done) => {
        let addr = new ipaddr.IPv4([1, 2, 3, 4]);
        addr.init()
        assert.strictEqual(addr.kind(), 'ipv4');
        done();
    })

    it('allows to access IPv4 octets', (done) => {
        let addr = new ipaddr.IPv4([42, 0, 0, 0]);
        addr.init()
        assert.strictEqual(addr.octets[0], 42);
        done();
    })

    it('checks IPv4 address format', (done) => {
        assert.strictEqual(ipaddr.IPv4.isIPv4('192.168.007.0xa'), true);
        assert.strictEqual(ipaddr.IPv4.isIPv4('1024.0.0.1'), true);
        assert.strictEqual(ipaddr.IPv4.isIPv4('8.0xa.wtf.6'), false);
        done();
    })

    it('validates IPv4 addresses', (done) => {
        assert.strictEqual(ipaddr.IPv4.isValid('192.168.007.0xa'), true);
        assert.strictEqual(ipaddr.IPv4.isValid('1024.0.0.1'), false);
        assert.strictEqual(ipaddr.IPv4.isValid('8.0xa.wtf.6'), false);
        done();
    })

    it('parses IPv4 in several weird formats', (done) => {
        assert.deepStrictEqual(ipaddr.IPv4.parse('192.168.1.1').octets, [192, 168, 1, 1]);
        assert.deepStrictEqual(ipaddr.IPv4.parse('0xc0.168.1.1').octets, [192, 168, 1, 1]);
        assert.deepStrictEqual(ipaddr.IPv4.parse('192.0250.1.1').octets, [192, 168, 1, 1]);
        assert.deepStrictEqual(ipaddr.IPv4.parse('0xc0a80101').octets, [192, 168, 1, 1]);
        assert.deepStrictEqual(ipaddr.IPv4.parse('030052000401').octets, [192, 168, 1, 1]);
        assert.deepStrictEqual(ipaddr.IPv4.parse('3232235777').octets, [192, 168, 1, 1]);
        assert.deepStrictEqual(ipaddr.IPv4.parse('127.42.258').octets, [127, 42, 1, 2]);
        assert.deepStrictEqual(ipaddr.IPv4.parse('127.66051').octets, [127, 1, 2, 3]);
        assert.deepStrictEqual(ipaddr.IPv4.parse('10.1.1.0xff').octets, [10, 1, 1, 255]);
        done();
    })

    it('barfs at invalid IPv4', (done) => {
        let res = true;
        res = ipaddr.IPv4.parse('10.0.0.wtf');
        assert.strictEqual(res,false);

        res = true;
        res = ipaddr.IPv4.parse('8.0x1ffffff');
        assert.strictEqual(res,false);

        res = true;
        res = ipaddr.IPv4.parse('8.8.0x1ffff');
        assert.strictEqual(res,false);

        res = true;
        res = ipaddr.IPv4.parse('10.048.1.1');
        assert.strictEqual(res,false);

        done();
    })

    it('matches IPv4 CIDR correctly', (done) => {
        let addr = new ipaddr.IPv4([10, 5, 0, 1]);
        addr.init()
        assert.strictEqual(addr.match(ipaddr.IPv4.parse('0.0.0.0'), 0), true);
        assert.strictEqual(addr.match(ipaddr.IPv4.parse('11.0.0.0'), 8), false);
        assert.strictEqual(addr.match(ipaddr.IPv4.parse('10.0.0.0'), 8), true);
        assert.strictEqual(addr.match(ipaddr.IPv4.parse('10.0.0.1'), 8), true);
        assert.strictEqual(addr.match(ipaddr.IPv4.parse('10.0.0.10'), 8), true);
        assert.strictEqual(addr.match(ipaddr.IPv4.parse('10.5.5.0'), 16), true);
        assert.strictEqual(addr.match(ipaddr.IPv4.parse('10.4.5.0'), 16), false);
        assert.strictEqual(addr.match(ipaddr.IPv4.parse('10.4.5.0'), 15), true);
        assert.strictEqual(addr.match(ipaddr.IPv4.parse('10.5.0.2'), 32), false);
        assert.strictEqual(addr.match(addr, 32), true);
        done();
    })

    it('parses CIDR reversible', (done) => {
        assert.strictEqual(ipaddr.parseCIDR('1.2.3.4/24').toString(), '1.2.3.4/24');
        assert.strictEqual(ipaddr.parseCIDR('::1%zone/24').toString(), '::1%zone/24');
        done();
    })

    it('parses IPv4 CIDR correctly', (done) => {
        let addr = new ipaddr.IPv4([10, 5, 0, 1]);
        addr.init()
        assert.strictEqual(addr.match(ipaddr.IPv4.parseCIDR('0.0.0.0/0')), true);
        assert.strictEqual(addr.match(ipaddr.IPv4.parseCIDR('11.0.0.0/8')), false);
        assert.strictEqual(addr.match(ipaddr.IPv4.parseCIDR('10.0.0.0/8')), true);
        assert.strictEqual(addr.match(ipaddr.IPv4.parseCIDR('10.0.0.1/8')), true);
        assert.strictEqual(addr.match(ipaddr.IPv4.parseCIDR('10.0.0.10/8')), true);
        assert.strictEqual(addr.match(ipaddr.IPv4.parseCIDR('10.5.5.0/16')), true);
        assert.strictEqual(addr.match(ipaddr.IPv4.parseCIDR('10.4.5.0/16')), false);
        assert.strictEqual(addr.match(ipaddr.IPv4.parseCIDR('10.4.5.0/15')), true);
        assert.strictEqual(addr.match(ipaddr.IPv4.parseCIDR('10.5.0.2/32')), false);
        assert.strictEqual(addr.match(ipaddr.IPv4.parseCIDR('10.5.0.1/32')), true);
        assert.strictEqual(ipaddr.IPv4.parseCIDR('10.5.0.1'), false)
        assert.strictEqual(ipaddr.IPv4.parseCIDR('0.0.0.0/-1'), false)
        assert.strictEqual(ipaddr.IPv4.parseCIDR('0.0.0.0/33'), false)

        done();
    })

    it('detects reserved IPv4 networks', (done) => {
        assert.strictEqual(ipaddr.IPv4.parse('0.0.0.0').range(), 'unspecified');
        assert.strictEqual(ipaddr.IPv4.parse('0.1.0.0').range(), 'unspecified');
        assert.strictEqual(ipaddr.IPv4.parse('10.1.0.1').range(), 'private');
        assert.strictEqual(ipaddr.IPv4.parse('100.64.0.0').range(), 'carrierGradeNat');
        assert.strictEqual(ipaddr.IPv4.parse('100.127.255.255').range(), 'carrierGradeNat');
        assert.strictEqual(ipaddr.IPv4.parse('192.168.2.1').range(), 'private');
        assert.strictEqual(ipaddr.IPv4.parse('224.100.0.1').range(), 'multicast');
        assert.strictEqual(ipaddr.IPv4.parse('169.254.15.0').range(), 'linkLocal');
        assert.strictEqual(ipaddr.IPv4.parse('127.1.1.1').range(), 'loopback');
        assert.strictEqual(ipaddr.IPv4.parse('255.255.255.255').range(), 'broadcast');
        assert.strictEqual(ipaddr.IPv4.parse('240.1.2.3').range(), 'reserved');
        assert.strictEqual(ipaddr.IPv4.parse('8.8.8.8').range(), 'unicast');
        done();
    })

    it('checks the conventional IPv4 address format', (done) => {
        assert.strictEqual(ipaddr.IPv4.isValidFourPartDecimal('0.0.0.0'), true);
        assert.strictEqual(ipaddr.IPv4.isValidFourPartDecimal('127.0.0.1'), true);
        assert.strictEqual(ipaddr.IPv4.isValidFourPartDecimal('192.168.1.1'), true);
        assert.strictEqual(ipaddr.IPv4.isValidFourPartDecimal('0xc0.168.1.1'), false);
        done();
    })

    it('refuses to construct IPv4 address with trailing and leading zeros', (done) => {
        assert.strictEqual(ipaddr.IPv4.isValidFourPartDecimal('000000192.168.100.2'), false);
        assert.strictEqual(ipaddr.IPv4.isValidFourPartDecimal('192.0000168.100.2'), false);
        assert.strictEqual(ipaddr.IPv4.isValidFourPartDecimal('192.168.100.00000002'), false);
        assert.strictEqual(ipaddr.IPv4.isValidFourPartDecimal('192.168.100.20000000'), false);
        done();
    })

    it('can construct IPv6 from 16bit parts', (done) => {
        const IPV6 = new ipaddr.IPv6([0x2001, 0xdb8, 0xf53a, 0, 0, 0, 0, 1]);
        assert.ok(IPV6.init());
        done();
    })

    it('can construct IPv6 from 8bit parts', (done) => {
        const IPV6 = new ipaddr.IPv6([0x20, 0x01, 0xd, 0xb8, 0xf5, 0x3a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert.ok(IPV6.init());

        const IPV6_1 = new ipaddr.IPv6([0x20, 0x01, 0xd, 0xb8, 0xf5, 0x3a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        IPV6_1.init();
        const IPV6_2 = new ipaddr.IPv6([0x2001, 0xdb8, 0xf53a, 0, 0, 0, 0, 1]);
        IPV6_2.init();

        assert.deepStrictEqual(IPV6_1,IPV6_2);
        done();

    })

    it('refuses to construct invalid IPv6', (done) => {
        const IPV6_1 = new ipaddr.IPv6([0xfffff, 0, 0, 0, 0, 0, 0, 1]);
        assert.strictEqual(IPV6_1.init(), false);


        const IPV6_2 = new ipaddr.IPv6([0xfffff, 0, 0, 0, 0, 0, 1]);
        assert.strictEqual(IPV6_2.init(), false);


        const IPV6_3 = new ipaddr.IPv6([0xffff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert.strictEqual(IPV6_3.init(), false);

        done();
    })

    it('converts IPv6 to string correctly', (done) => {
        let addr = new ipaddr.IPv6([0x2001, 0xdb8, 0xf53a, 0, 0, 0, 0, 1]);
        assert.ok(addr.init());

        assert.strictEqual(addr.toNormalizedString(), '2001:db8:f53a:0:0:0:0:1');
        assert.strictEqual(addr.toFixedLengthString(), '2001:0db8:f53a:0000:0000:0000:0000:0001');
        assert.strictEqual(addr.toString(), '2001:db8:f53a::1');

        const IPV6_1 = new ipaddr.IPv6([0, 0, 0, 0, 0, 0, 0, 0]); IPV6_1.init();
        const IPV6_2 = new ipaddr.IPv6([0, 0, 0, 0, 0, 0, 0, 1]); IPV6_2.init();
        const IPV6_3 = new ipaddr.IPv6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]); IPV6_3.init();
        const IPV6_4 = new ipaddr.IPv6([0, 0xff, 0, 0, 0, 0, 0, 0]); IPV6_4.init();
        const IPV6_5 = new ipaddr.IPv6([0, 0, 0, 0, 0, 0, 0xff, 0]); IPV6_5.init();
        const IPV6_6 = new ipaddr.IPv6([0, 0, 0xff, 0, 0, 0, 0, 0]); IPV6_6.init();
        const IPV6_7 = new ipaddr.IPv6([0, 0, 0, 0, 0, 0xff, 0, 0]); IPV6_7.init();
        const IPV6_8 = new ipaddr.IPv6([0x2001, 0xdb8, 0xff, 0xabc, 0xdef, 0x123b, 0x456c, 0x78d]); IPV6_8.init();
        const IPV6_9 = new ipaddr.IPv6([0x2001, 0xdb8, 0xff, 0xabc, 0, 0x123b, 0x456c, 0x78d]); IPV6_9.init();
        const IPV6_10 = new ipaddr.IPv6([0x2001, 0xdb8, 0xff, 0xabc, 0, 0, 0x456c, 0x78d]); IPV6_10.init();


        assert.strictEqual(IPV6_1.toString(), '::');
        assert.strictEqual(IPV6_2.toString(), '::1');
        assert.strictEqual(IPV6_3.toString(), '2001:db8::');
        assert.strictEqual(IPV6_4.toString(), '::ff:0:0:0:0:0:0');
        assert.strictEqual(IPV6_5.toString(), '::ff:0');
        assert.strictEqual(IPV6_6.toString(), '::ff:0:0:0:0:0');
        assert.strictEqual(IPV6_7.toString(), '::ff:0:0');
        assert.strictEqual(IPV6_8.toString(), '2001:db8:ff:abc:def:123b:456c:78d');
        assert.strictEqual(IPV6_9.toString(), '2001:db8:ff:abc::123b:456c:78d');
        assert.strictEqual(IPV6_10.toString(), '2001:db8:ff:abc::456c:78d');

        done();
    })

    it('converts IPv6 to RFC 5952 string correctly', (done) => {
        // see https://tools.ietf.org/html/rfc5952#section-4
        let addr = new ipaddr.IPv6([0x2001, 0xdb8, 0xf53a, 0, 0, 0, 0, 1]); addr.init();
        assert.strictEqual(addr.toRFC5952String(), '2001:db8:f53a::1');

        const IPV6_1 = new ipaddr.IPv6([0, 0, 0, 0, 0, 0, 0, 0]); IPV6_1.init();
        assert.strictEqual(IPV6_1.toRFC5952String(), '::');

        const IPV6_2 = new ipaddr.IPv6([0, 0, 0, 0, 0, 0, 0, 1]); IPV6_2.init();
        assert.strictEqual(IPV6_2.toRFC5952String(), '::1');

        const IPV6_3 = new ipaddr.IPv6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0]); IPV6_3.init();
        assert.strictEqual(IPV6_3.toRFC5952String(), '2001:db8::');

        // longest set of zeroes gets collapsed (section 4.2.3)
        const IPV6_4 = new ipaddr.IPv6([0, 0xff, 0, 0, 0, 0, 0, 0]); IPV6_4.init();
        assert.strictEqual(IPV6_4.toRFC5952String(), '0:ff::');

        const IPV6_5 = new ipaddr.IPv6([0, 0, 0, 0, 0, 0, 0xff, 0]); IPV6_5.init();
        assert.strictEqual(IPV6_5.toRFC5952String(), '::ff:0');

        const IPV6_6 = new ipaddr.IPv6([0, 0, 0xff, 0, 0, 0, 0, 0]); IPV6_6.init();
        assert.strictEqual(IPV6_6.toRFC5952String(), '0:0:ff::');

        const IPV6_7 = new ipaddr.IPv6([0, 0, 0, 0, 0, 0xff, 0, 0]); IPV6_7.init();
        assert.strictEqual(IPV6_7.toRFC5952String(), '::ff:0:0');

        const IPV6_8 = new ipaddr.IPv6([0x2001, 0, 0, 0, 0xff, 0, 0, 0]); IPV6_8.init();
        assert.strictEqual(IPV6_8.toRFC5952String(), '2001::ff:0:0:0');

        const IPV6_9 = new ipaddr.IPv6([0x2001, 0xdb8, 0xff, 0xabc, 0xdef, 0x123b, 0x456c, 0x78d]); IPV6_9.init();
        assert.strictEqual(IPV6_9.toRFC5952String(), '2001:db8:ff:abc:def:123b:456c:78d');

        // // don't shorten single 0s (section 4.2.2)
        const IPV6_10 = new ipaddr.IPv6([0x2001, 0xdb8, 0xff, 0xabc, 0, 0x123b, 0x456c, 0x78d]); IPV6_10.init();
        assert.strictEqual(IPV6_10.toRFC5952String(), '2001:db8:ff:abc:0:123b:456c:78d');

        const IPV6_11 = new ipaddr.IPv6([0x2001, 0xdb8, 0xff, 0xabc, 0x78d, 0x123b, 0x456c, 0]); IPV6_11.init();
        assert.strictEqual(IPV6_11.toRFC5952String(), '2001:db8:ff:abc:78d:123b:456c:0');

        const IPV6_12 = new ipaddr.IPv6([0, 0xdb8, 0xff, 0xabc, 0x78d, 0x123b, 0x456c, 0x2001]); IPV6_12.init();
        assert.strictEqual(IPV6_12.toRFC5952String(), '0:db8:ff:abc:78d:123b:456c:2001');

        const IPV6_13 = new ipaddr.IPv6([0x2001, 0xdb8, 0xff, 0xabc, 0, 0, 0x456c, 0x78d]); IPV6_13.init();
        assert.strictEqual(IPV6_13.toRFC5952String(), '2001:db8:ff:abc::456c:78d');
        done();
    })

    it('returns IPv6 zoneIndex', (done) => {
        let addr = new ipaddr.IPv6([0x2001, 0xdb8, 0xf53a, 0, 0, 0, 0, 1], 'utun0');
        addr.init();

        assert.strictEqual(addr.toNormalizedString(), '2001:db8:f53a:0:0:0:0:1%utun0');
        assert.strictEqual(addr.toString(), '2001:db8:f53a::1%utun0');

        assert.strictEqual(
            ipaddr.parse('2001:db8:f53a::1%2').toString(),
            '2001:db8:f53a::1%2'
        );
        assert.strictEqual(
            ipaddr.parse('2001:db8:f53a::1%WAT').toString(),
            '2001:db8:f53a::1%WAT'
        );
        assert.strictEqual(
            ipaddr.parse('2001:db8:f53a::1%sUp').toString(),
            '2001:db8:f53a::1%sUp'
        );

        done();
    })

    it('returns IPv6 zoneIndex for IPv4-mapped IPv6 addresses', (done) => {
        let addr = ipaddr.parse('::ffff:192.168.1.1%eth0');
        addr.init();

        assert.strictEqual(addr.toNormalizedString(), '0:0:0:0:0:ffff:c0a8:101%eth0');
        assert.strictEqual(addr.toString(), '::ffff:c0a8:101%eth0');

        assert.strictEqual(
            ipaddr.parse('::ffff:192.168.1.1%2').toString(),
            '::ffff:c0a8:101%2'
        );
        assert.strictEqual(
            ipaddr.parse('::ffff:192.168.1.1%WAT').toString(),
            '::ffff:c0a8:101%WAT'
        );
        assert.strictEqual(
            ipaddr.parse('::ffff:192.168.1.1%sUp').toString(),
            '::ffff:c0a8:101%sUp'
        );

        done();
    })

    it('returns correct kind for IPv6', (done) => {
        let addr = new ipaddr.IPv6([0x2001, 0xdb8, 0xf53a, 0, 0, 0, 0, 1]);
        addr.init();

        assert.strictEqual(addr.kind(), 'ipv6');
        done();
    })

    it('allows to access IPv6 address parts', (done) => {
        let addr = new ipaddr.IPv6([0x2001, 0xdb8, 0xf53a, 0, 0, 42, 0, 1]);
        addr.init();
        assert.strictEqual(addr.parts[5], 42);
        done();
    })

    it('checks IPv6 address format', (done) => {
        assert.strictEqual(ipaddr.IPv6.isIPv6('2001:db8:F53A::1'), true);
        assert.strictEqual(ipaddr.IPv6.isIPv6('200001::1'), true);
        assert.strictEqual(ipaddr.IPv6.isIPv6('::ffff:192.168.1.1'), true);
        assert.strictEqual(ipaddr.IPv6.isIPv6('::ffff:192.168.1.1%z'), true);
        assert.strictEqual(ipaddr.IPv6.isIPv6('::10.2.3.4'), true);
        assert.strictEqual(ipaddr.IPv6.isIPv6('::12.34.56.78%z'), true);
        assert.strictEqual(ipaddr.IPv6.isIPv6('::ffff:300.168.1.1'), false);
        assert.strictEqual(ipaddr.IPv6.isIPv6('::ffff:300.168.1.1:0'), false);
        assert.strictEqual(ipaddr.IPv6.isIPv6('fe80::wtf'), false);
        assert.strictEqual(ipaddr.IPv6.isIPv6('fe80::%'), false);
        done();
    })

    it('validates IPv6 addresses', (done) => {
        assert.strictEqual(ipaddr.IPv6.isValid('2001:db8:F53A::1'), true);
        assert.strictEqual(ipaddr.IPv6.isValid('200001::1'), false);
        assert.strictEqual(ipaddr.IPv6.isValid('::ffff:192.168.1.1'), true);
        assert.strictEqual(ipaddr.IPv6.isValid('::ffff:192.168.1.1%z'), true);
        assert.strictEqual(ipaddr.IPv6.isValid('::1.1.1.1'), true);
        assert.strictEqual(ipaddr.IPv6.isValid('::1.2.3.4%z'), true);
        assert.strictEqual(ipaddr.IPv6.isValid('::ffff:300.168.1.1'), false);
        assert.strictEqual(ipaddr.IPv6.isValid('::ffff:300.168.1.1:0'), false);
        assert.strictEqual(ipaddr.IPv6.isValid('::ffff:222.1.41.9000'), false);
        assert.strictEqual(ipaddr.IPv6.isValid('2001:db8::F53A::1'), false);
        assert.strictEqual(ipaddr.IPv6.isValid('fe80::wtf'), false);
        assert.strictEqual(ipaddr.IPv6.isValid('fe80::%'), false);
        assert.strictEqual(ipaddr.IPv6.isValid('2002::2:'), false);
        assert.strictEqual(ipaddr.IPv6.isValid('::%z'), true);

        assert.strictEqual(ipaddr.IPv6.isValid(undefined), false);
        done();
    })

    it('parses IPv6 in different formats', (done) => {
        assert.deepStrictEqual(ipaddr.IPv6.parse('2001:db8:F53A:0:0:0:0:1').parts, [0x2001, 0xdb8, 0xf53a, 0, 0, 0, 0, 1]);
        assert.deepStrictEqual(ipaddr.IPv6.parse('fe80::10').parts, [0xfe80, 0, 0, 0, 0, 0, 0, 0x10]);
        assert.deepStrictEqual(ipaddr.IPv6.parse('2001:db8:F53A::').parts, [0x2001, 0xdb8, 0xf53a, 0, 0, 0, 0, 0]);
        assert.deepStrictEqual(ipaddr.IPv6.parse('::1').parts, [0, 0, 0, 0, 0, 0, 0, 1]);
        assert.deepStrictEqual(ipaddr.IPv6.parse('::8.8.8.8').parts, [0, 0, 0, 0, 0, 0xffff, 2056, 2056]);
        assert.deepStrictEqual(ipaddr.IPv6.parse('::').parts, [0, 0, 0, 0, 0, 0, 0, 0]);
        assert.deepStrictEqual(ipaddr.IPv6.parse('::%z').parts, [0, 0, 0, 0, 0, 0, 0, 0]);
        assert.deepStrictEqual(ipaddr.IPv6.parse('::%z').zoneId, 'z');
        done();
    })

    it('barfs at invalid IPv6', (done) => {
        assert.strictEqual(ipaddr.IPv6.parse('fe80::0::1'), false)
        done();
    })

    it('matches IPv6 CIDR correctly', (done) => {
        let addr = ipaddr.IPv6.parse('2001:db8:f53a::1');
        addr.init();
        assert.strictEqual(addr.match(ipaddr.IPv6.parse('::'), 0), true);
        assert.strictEqual(addr.match(ipaddr.IPv6.parse('2001:db8:f53a::1:1'), 64), true);
        assert.strictEqual(addr.match(ipaddr.IPv6.parse('2001:db8:f53b::1:1'), 48), false);
        assert.strictEqual(addr.match(ipaddr.IPv6.parse('2001:db8:f531::1:1'), 44), true);
        assert.strictEqual(addr.match(ipaddr.IPv6.parse('2001:db8:f500::1'), 40), true);
        assert.strictEqual(addr.match(ipaddr.IPv6.parse('2001:db8:f500::1%z'), 40), true);
        assert.strictEqual(addr.match(ipaddr.IPv6.parse('2001:db9:f500::1'), 40), false);
        assert.strictEqual(addr.match(ipaddr.IPv6.parse('2001:db9:f500::1'), 40), false);
        assert.strictEqual(addr.match(ipaddr.IPv6.parse('2001:db9:f500::1%z'), 40), false);
        assert.strictEqual(addr.match(addr, 128), true);
        done();
    })

    it('parses IPv6 CIDR correctly', (done) => {
        let addr = ipaddr.IPv6.parse('2001:db8:f53a::1');
        addr.init();

        assert.strictEqual(addr.match(ipaddr.IPv6.parseCIDR('::/0')), true);
        assert.strictEqual(addr.match(ipaddr.IPv6.parseCIDR('2001:db8:f53a::1:1/64')), true);
        assert.strictEqual(addr.match(ipaddr.IPv6.parseCIDR('2001:db8:f53b::1:1/48')), false);
        assert.strictEqual(addr.match(ipaddr.IPv6.parseCIDR('2001:db8:f531::1:1/44')), true);
        assert.strictEqual(addr.match(ipaddr.IPv6.parseCIDR('2001:db8:f500::1/40')), true);
        assert.strictEqual(addr.match(ipaddr.IPv6.parseCIDR('2001:db8:f500::1%z/40')), true);
        assert.strictEqual(addr.match(ipaddr.IPv6.parseCIDR('2001:db9:f500::1/40')), false);
        assert.strictEqual(addr.match(ipaddr.IPv6.parseCIDR('2001:db9:f500::1%z/40')), false);
        assert.strictEqual(addr.match(ipaddr.IPv6.parseCIDR('2001:db8:f53a::1/128')), true);
        assert.strictEqual(ipaddr.IPv6.parseCIDR('2001:db8:f53a::1'), false);
        assert.strictEqual(ipaddr.IPv6.parseCIDR('2001:db8:f53a::1/-1'), false);
        assert.strictEqual(ipaddr.IPv6.parseCIDR('2001:db8:f53a::1/129'), false);
        // assert.throws(() => {
        //     ipaddr.IPv6.parseCIDR('2001:db8:f53a::1');
        // });
        // assert.throws(() => {
        //     ipaddr.IPv6.parseCIDR('2001:db8:f53a::1/-1');
        // });
        // assert.throws(() => {
        //     ipaddr.IPv6.parseCIDR('2001:db8:f53a::1/129');
        // });
        done();
    })

    it('converts between IPv4-mapped IPv6 addresses and IPv4 addresses', (done) => {
        let addr = ipaddr.IPv4.parse('77.88.21.11');
        let mapped = addr.toIPv4MappedAddress();
        assert.deepStrictEqual(mapped.parts, [0, 0, 0, 0, 0, 0xffff, 0x4d58, 0x150b]);
        assert.deepStrictEqual(mapped.toIPv4Address().octets, addr.octets);
        done();
    })

    it('refuses to convert non-IPv4-mapped IPv6 address to IPv4 address', (done) => {
        assert.strictEqual(ipaddr.IPv6.parse('2001:db8::1').toIPv4Address(), false)
        done();
    })

    it('detects reserved IPv6 networks', (done) => {
        assert.strictEqual(ipaddr.IPv6.parse('::').range(), 'unspecified');
        assert.strictEqual(ipaddr.IPv6.parse('fe80::1234:5678:abcd:0123').range(), 'linkLocal');
        assert.strictEqual(ipaddr.IPv6.parse('ff00::1234').range(), 'multicast');
        assert.strictEqual(ipaddr.IPv6.parse('::1').range(), 'loopback');
        assert.strictEqual(ipaddr.IPv6.parse('fc00::').range(), 'uniqueLocal');
        assert.strictEqual(ipaddr.IPv6.parse('::ffff:192.168.1.10').range(), 'ipv4Mapped');
        assert.strictEqual(ipaddr.IPv6.parse('::ffff:0:192.168.1.10').range(), 'rfc6145');
        assert.strictEqual(ipaddr.IPv6.parse('64:ff9b::1234').range(), 'rfc6052');
        assert.strictEqual(ipaddr.IPv6.parse('2002:1f63:45e8::1').range(), '6to4');
        assert.strictEqual(ipaddr.IPv6.parse('2001::4242').range(), 'teredo');
        assert.strictEqual(ipaddr.IPv6.parse('2001:db8::3210').range(), 'reserved');
        assert.strictEqual(ipaddr.IPv6.parse('2001:470:8:66::1').range(), 'unicast');
        assert.strictEqual(ipaddr.IPv6.parse('2001:470:8:66::1%z').range(), 'unicast');
        done();
    })

    it('is able to determine IP address type', (done) => {
        assert.strictEqual(ipaddr.parse('8.8.8.8').kind(), 'ipv4');
        assert.strictEqual(ipaddr.parse('2001:db8:3312::1').kind(), 'ipv6');
        assert.strictEqual(ipaddr.parse('2001:db8:3312::1%z').kind(), 'ipv6');
        done();
    })

    it('throws an error if tried to parse an invalid address', (done) => {
        assert.strictEqual(ipaddr.parse('::some.nonsense'), false);
        done();
    })

    it('correctly processes IPv4-mapped addresses', (done) => {
        assert.strictEqual(ipaddr.process('8.8.8.8').kind(), 'ipv4');
        assert.strictEqual(ipaddr.process('2001:db8:3312::1').kind(), 'ipv6');
        assert.strictEqual(ipaddr.process('::ffff:192.168.1.1').kind(), 'ipv4');
        assert.strictEqual(ipaddr.process('::ffff:192.168.1.1%z').kind(), 'ipv4');
        assert.strictEqual(ipaddr.process('::8.8.8.8').kind(), 'ipv4');
        done();
    })

    it('correctly converts IPv6 and IPv4 addresses to byte arrays', (done) => {
        assert.deepStrictEqual(
            ipaddr.parse('1.2.3.4').toByteArray(),
            [0x1, 0x2, 0x3, 0x4]
        );
        // Fuck yeah. The first byte of Google's IPv6 address is 42. 42!
        assert.deepStrictEqual(
            ipaddr.parse('2a00:1450:8007::68').toByteArray(),
            [42, 0x00, 0x14, 0x50, 0x80, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68]
        );
        assert.deepStrictEqual(
            ipaddr.parse('2a00:1450:8007::68%z').toByteArray(),
            [42, 0x00, 0x14, 0x50, 0x80, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68]
        );

        done();
    })

    it('correctly parses 1 as an IPv4 address', (done) => {
        assert.strictEqual(ipaddr.IPv6.isValid('1'), false);
        assert.strictEqual(ipaddr.IPv4.isValid('1'), true);
        const IPV4 = new ipaddr.IPv4([0, 0, 0, 1]);
        IPV4.init();
        assert.deepStrictEqual(IPV4, ipaddr.parse('1'));
        done();
    })

    it('correctly detects IPv4 and IPv6 CIDR addresses', (done) => {
        assert.deepStrictEqual(
            [ipaddr.IPv6.parse('fc00::'), 64],
            ipaddr.parseCIDR('fc00::/64')
        );
        assert.deepStrictEqual(
            [ipaddr.IPv4.parse('1.2.3.4'), 5],
            ipaddr.parseCIDR('1.2.3.4/5')
        );
        done();
    })

    it('does not consider a very large or very small number a valid IP address', (done) => {
        assert.strictEqual(ipaddr.isValid('4999999999'), false);
        assert.strictEqual(ipaddr.isValid('-1'), false);
        done();
    })

    it('does not hang on ::8:8:8:8:8:8:8:8:8', (done) => {
        assert.strictEqual(ipaddr.IPv6.isValid('::8:8:8:8:8:8:8:8:8'), false);
        assert.strictEqual(ipaddr.IPv6.isValid('::8:8:8:8:8:8:8:8:8%z'), false);
        done();
    })

    it('subnetMatch does not fail on empty range', (done) => {
        const IPV4_1 = new ipaddr.IPv4([1, 2, 3, 4]); IPV4_1.init();
        const IPV4_2 = new ipaddr.IPv4([1, 2, 3, 4]); IPV4_2.init();
        assert.strictEqual(ipaddr.subnetMatch(IPV4_1, {}, false), false);
        assert.strictEqual(ipaddr.subnetMatch(IPV4_2, { subnet: [] }, false), false);
        done();
    })

    it('subnetMatch returns default subnet on empty range', (done) => {
        const IPV4_1 = new ipaddr.IPv4([1, 2, 3, 4]); IPV4_1.init();
        const IPV4_2 = new ipaddr.IPv4([1, 2, 3, 4]); IPV4_2.init();
        assert.strictEqual(ipaddr.subnetMatch(IPV4_1, {}, false), false);
        assert.strictEqual(ipaddr.subnetMatch(IPV4_2, { subnet: [] }, false), false);
        done();
    })

    it('subnetMatch does not fail on IPv4 when looking for IPv6', (done) => {
        let rangelist = { subnet6: ipaddr.parseCIDR('fe80::/64') };
        const IPV4 = new ipaddr.IPv4([1, 2, 3, 4]); IPV4.init();
        assert.strictEqual(ipaddr.subnetMatch(IPV4, rangelist, false), false);
        done();
    })

    it('subnetMatch does not fail on IPv6 when looking for IPv4', (done) => {
        let rangelist = { subnet4: ipaddr.parseCIDR('1.2.3.0/24') };
        const IPV6 = new ipaddr.IPv6([0xfe80, 0, 0, 0, 0, 0, 0, 1]); IPV6.init();
        assert.strictEqual(ipaddr.subnetMatch(IPV6, rangelist, false), false);
        done();
    })

    it('subnetMatch can use a hybrid IPv4/IPv6 range list', (done) => {
        let rangelist = { dual64: [ipaddr.parseCIDR('1.2.4.0/24'), ipaddr.parseCIDR('2001:1:2:3::/64')] };
        const IPV4 = new ipaddr.IPv4([1, 2, 4, 1]); IPV4.init();
        const IPV6 = new ipaddr.IPv6([0x2001, 1, 2, 3, 0, 0, 0, 1]); IPV6.init();
        assert.strictEqual(ipaddr.subnetMatch(IPV4, rangelist, false), 'dual64');
        assert.strictEqual(ipaddr.subnetMatch(IPV6, rangelist, false), 'dual64');
        done();
    })

    it('is able to determine IP address type from byte array input', (done) => {
        assert.strictEqual(ipaddr.fromByteArray([0x7f, 0, 0, 1]).kind(), 'ipv4');
        assert.strictEqual(ipaddr.fromByteArray([0x20, 0x01, 0xd, 0xb8, 0xf5, 0x3a, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).kind(), 'ipv6');
        assert.strictEqual(ipaddr.fromByteArray([1]), false);
        done();
    })


    it('prefixLengthFromSubnetMask returns proper CIDR notation for standard IPv4 masks', (done) => {
        assert.strictEqual(ipaddr.IPv4.parse('255.255.255.255').prefixLengthFromSubnetMask(), 32);
        assert.strictEqual(ipaddr.IPv4.parse('255.255.255.254').prefixLengthFromSubnetMask(), 31);
        assert.strictEqual(ipaddr.IPv4.parse('255.255.255.252').prefixLengthFromSubnetMask(), 30);
        assert.strictEqual(ipaddr.IPv4.parse('255.255.255.248').prefixLengthFromSubnetMask(), 29);
        assert.strictEqual(ipaddr.IPv4.parse('255.255.255.240').prefixLengthFromSubnetMask(), 28);
        assert.strictEqual(ipaddr.IPv4.parse('255.255.255.224').prefixLengthFromSubnetMask(), 27);
        assert.strictEqual(ipaddr.IPv4.parse('255.255.255.192').prefixLengthFromSubnetMask(), 26);
        assert.strictEqual(ipaddr.IPv4.parse('255.255.255.128').prefixLengthFromSubnetMask(), 25);
        assert.strictEqual(ipaddr.IPv4.parse('255.255.255.0').prefixLengthFromSubnetMask(), 24);
        assert.strictEqual(ipaddr.IPv4.parse('255.255.254.0').prefixLengthFromSubnetMask(), 23);
        assert.strictEqual(ipaddr.IPv4.parse('255.255.252.0').prefixLengthFromSubnetMask(), 22);
        assert.strictEqual(ipaddr.IPv4.parse('255.255.248.0').prefixLengthFromSubnetMask(), 21);
        assert.strictEqual(ipaddr.IPv4.parse('255.255.240.0').prefixLengthFromSubnetMask(), 20);
        assert.strictEqual(ipaddr.IPv4.parse('255.255.224.0').prefixLengthFromSubnetMask(), 19);
        assert.strictEqual(ipaddr.IPv4.parse('255.255.192.0').prefixLengthFromSubnetMask(), 18);
        assert.strictEqual(ipaddr.IPv4.parse('255.255.128.0').prefixLengthFromSubnetMask(), 17);
        assert.strictEqual(ipaddr.IPv4.parse('255.255.0.0').prefixLengthFromSubnetMask(), 16);
        assert.strictEqual(ipaddr.IPv4.parse('255.254.0.0').prefixLengthFromSubnetMask(), 15);
        assert.strictEqual(ipaddr.IPv4.parse('255.252.0.0').prefixLengthFromSubnetMask(), 14);
        assert.strictEqual(ipaddr.IPv4.parse('255.248.0.0').prefixLengthFromSubnetMask(), 13);
        assert.strictEqual(ipaddr.IPv4.parse('255.240.0.0').prefixLengthFromSubnetMask(), 12);
        assert.strictEqual(ipaddr.IPv4.parse('255.224.0.0').prefixLengthFromSubnetMask(), 11);
        assert.strictEqual(ipaddr.IPv4.parse('255.192.0.0').prefixLengthFromSubnetMask(), 10);
        assert.strictEqual(ipaddr.IPv4.parse('255.128.0.0').prefixLengthFromSubnetMask(), 9);
        assert.strictEqual(ipaddr.IPv4.parse('255.0.0.0').prefixLengthFromSubnetMask(), 8);
        assert.strictEqual(ipaddr.IPv4.parse('254.0.0.0').prefixLengthFromSubnetMask(), 7);
        assert.strictEqual(ipaddr.IPv4.parse('252.0.0.0').prefixLengthFromSubnetMask(), 6);
        assert.strictEqual(ipaddr.IPv4.parse('248.0.0.0').prefixLengthFromSubnetMask(), 5);
        assert.strictEqual(ipaddr.IPv4.parse('240.0.0.0').prefixLengthFromSubnetMask(), 4);
        assert.strictEqual(ipaddr.IPv4.parse('224.0.0.0').prefixLengthFromSubnetMask(), 3);
        assert.strictEqual(ipaddr.IPv4.parse('192.0.0.0').prefixLengthFromSubnetMask(), 2);
        assert.strictEqual(ipaddr.IPv4.parse('128.0.0.0').prefixLengthFromSubnetMask(), 1);
        assert.strictEqual(ipaddr.IPv4.parse('0.0.0.0').prefixLengthFromSubnetMask(), 0);
        // negative cases
        assert.strictEqual(ipaddr.IPv4.parse('192.168.255.0').prefixLengthFromSubnetMask(), null);
        assert.strictEqual(ipaddr.IPv4.parse('255.0.255.0').prefixLengthFromSubnetMask(), null);
        done();
    })

    it('prefixLengthFromSubnetMask returns proper CIDR notation for standard IPv6 masks', (done) => {
        assert.strictEqual(ipaddr.IPv6.parse('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff').prefixLengthFromSubnetMask(), 128);
        assert.strictEqual(ipaddr.IPv6.parse('ffff:ffff:ffff:ffff::').prefixLengthFromSubnetMask(), 64);
        assert.strictEqual(ipaddr.IPv6.parse('ffff:ffff:ffff:ff80::').prefixLengthFromSubnetMask(), 57);
        assert.strictEqual(ipaddr.IPv6.parse('ffff:ffff:ffff::').prefixLengthFromSubnetMask(), 48);
        assert.strictEqual(ipaddr.IPv6.parse('ffff:ffff:ffff::%z').prefixLengthFromSubnetMask(), 48);
        assert.strictEqual(ipaddr.IPv6.parse('::').prefixLengthFromSubnetMask(), 0);
        assert.strictEqual(ipaddr.IPv6.parse('::%z').prefixLengthFromSubnetMask(), 0);
        // negative cases
        assert.strictEqual(ipaddr.IPv6.parse('2001:db8::').prefixLengthFromSubnetMask(), null);
        assert.strictEqual(ipaddr.IPv6.parse('ffff:0:0:ffff::').prefixLengthFromSubnetMask(), null);
        assert.strictEqual(ipaddr.IPv6.parse('ffff:0:0:ffff::%z').prefixLengthFromSubnetMask(), null);
        done();
    })

    it('subnetMaskFromPrefixLength returns correct IPv4 subnet mask given prefix length', (done) => {

        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(0).toString(), '0.0.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(1).toString(), '128.0.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(2).toString(), '192.0.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(3).toString(), '224.0.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(4).toString(), '240.0.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(5).toString(), '248.0.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(6).toString(), '252.0.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(7).toString(), '254.0.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(8).toString(), '255.0.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(9).toString(), '255.128.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(10).toString(), '255.192.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(11).toString(), '255.224.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(12).toString(), '255.240.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(13).toString(), '255.248.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(14).toString(), '255.252.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(15).toString(), '255.254.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(16).toString(), '255.255.0.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(17).toString(), '255.255.128.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(18).toString(), '255.255.192.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(19).toString(), '255.255.224.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(20).toString(), '255.255.240.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(21).toString(), '255.255.248.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(22).toString(), '255.255.252.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(23).toString(), '255.255.254.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(24).toString(), '255.255.255.0');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(25).toString(), '255.255.255.128');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(26).toString(), '255.255.255.192');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(27).toString(), '255.255.255.224');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(28).toString(), '255.255.255.240');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(29).toString(), '255.255.255.248');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(30).toString(), '255.255.255.252');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(31).toString(), '255.255.255.254');
        assert.strictEqual(ipaddr.IPv4.subnetMaskFromPrefixLength(32).toString(), '255.255.255.255');
        done();
    })

    it('broadcastAddressFromCIDR returns correct IPv4 broadcast address', (done) => {
        assert.strictEqual(ipaddr.IPv4.broadcastAddressFromCIDR('172.0.0.1/24').toString(), '172.0.0.255');
        assert.strictEqual(ipaddr.IPv4.broadcastAddressFromCIDR('172.0.0.1/26').toString(), '172.0.0.63');
        done();
    })

    it('networkAddressFromCIDR returns correct IPv4 network address', (done) => {
        assert.strictEqual(ipaddr.IPv4.networkAddressFromCIDR('172.0.0.1/24').toString(), '172.0.0.0');
        assert.strictEqual(ipaddr.IPv4.networkAddressFromCIDR('172.0.0.1/5').toString(), '168.0.0.0');
        done();
    })
})
