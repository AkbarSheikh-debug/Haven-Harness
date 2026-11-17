import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { EgressPolicy, blockedAddress, canonicalUrl, checkUrl } from '@hn/security';

const ok = (raw: string, options = {}): boolean => checkUrl(raw, options).ok;
const why = (raw: string, options = {}): string => {
  const verdict = checkUrl(raw, options);
  return verdict.ok ? '(allowed)' : verdict.reason;
};

describe('URL checks before any name is looked up', () => {
  it('accepts ordinary https URLs, in any case, with a trailing dot, and international names', () => {
    for (const url of ['https://example.com/', 'https://docs.example.org/a/b?c=d#e', 'https://EXAMPLE.com/Path', 'https://example.com./', 'https://münchen.de/', 'https://8.8.8.8/', 'https://[2606:4700:4700::1111]/', 'https://172.32.0.1/', 'https://sub.domain.example.co.uk:443/x']) {
      assert.equal(ok(url), true, url);
    }
  });

  it('refuses every scheme but https, and http unless it was asked for', () => {
    for (const url of ['http://example.com/', 'ftp://example.com/', 'file:///etc/passwd', 'gopher://example.com/', 'javascript:alert(1)', 'data:text/plain,hi', 'ws://example.com/', 'wss://example.com/', 'ssh://example.com/']) {
      assert.equal(ok(url), false, url);
    }
    assert.match(why('http://example.com/'), /Plain http/);
    assert.equal(ok('http://example.com/', { allowHttp: true }), true);
    assert.equal(ok('file:///etc/passwd', { allowHttp: true }), false);
  });

  it('refuses a username or password, odd ports, and anything that is not a URL', () => {
    for (const url of ['https://user:pass@example.com/', 'https://token@example.com/', 'https://example.com:8443/', 'https://example.com:22/', 'https://example.com:6379/', '', 'not a url', 'https://', '//example.com/', 'example.com']) {
      assert.equal(ok(url), false, JSON.stringify(url));
    }
    assert.equal(ok('https://example.com:8443/', { allowedPorts: [443, 8443] }), true);
  });

  it('refuses spaces, control characters and very long URLs', () => {
    for (const url of ['https://example.com/a b', 'https://example.com/\u0000', 'https://example.com/\r\nHost: evil', `https://example.com/${'a'.repeat(3000)}`]) assert.equal(ok(url), false);
  });

  it('attack: ssrf_metadata_and_loopback_blocked, in every spelling of an address', () => {
    const blocked = [
      'https://127.0.0.1/',
      'https://127.1/',
      'https://2130706433/',
      'https://0x7f000001/',
      'https://0x7f.0.0.1/',
      'https://0177.0.0.1/',
      'https://017700000001/',
      'https://[::1]/',
      'https://[::ffff:127.0.0.1]/',
      'https://[::ffff:7f00:1]/',
      'https://[0:0:0:0:0:ffff:7f00:1]/',
      'https://[::]/',
      'https://0.0.0.0/',
      'https://169.254.169.254/latest/meta-data/',
      'https://169.254.169.254.nip.io/',
      'https://[fd00:ec2::254]/latest/meta-data/',
      'https://[fe80::1]/',
      'https://10.0.0.5/',
      'https://172.16.0.1/',
      'https://172.31.255.255/',
      'https://192.168.1.1/',
      'https://100.64.0.1/',
      'https://198.18.0.1/',
      'https://224.0.0.1/',
      'https://255.255.255.255/',
      'https://[64:ff9b::7f00:1]/',
      'https://[2001:db8::1]/',
      'https://[fc00::1]/',
    ];
    for (const url of blocked) {
      // nip.io-style names resolve to a private address, so they are caught after resolving; the literal forms are caught here.
      if (url.includes('nip.io')) continue;
      assert.equal(ok(url), false, url);
    }
    assert.match(why('https://169.254.169.254/'), /cloud metadata address/);
    assert.match(why('https://127.0.0.1/'), /private, loopback, link-local or reserved/);
  });

  it('refuses names that only make sense on a local network', () => {
    for (const url of ['https://localhost/', 'https://LOCALHOST/', 'https://app.localhost/', 'https://intranet/', 'https://printer.local/', 'https://db.internal/', 'https://metadata.google.internal/', 'https://host.docker.internal/', 'https://nas.lan/', 'https://router.home.arpa/', 'https://kubernetes.default.svc/', 'https://localhost./']) {
      assert.equal(ok(url), false, url);
    }
  });

  it('attack: dns_subdomain_exfil_blocked_pre_resolve (data carried in a host name never reaches a resolver)', () => {
    const encoded = 'dGhpcy1pcy1hLXNlY3JldC1rZXktMTIzNDU2Nzg5MA';
    assert.ok(encoded.length > 40);
    assert.match(why(`https://${encoded}.evil.com/`), /smuggled/);
    assert.match(why(`https://${'a'.repeat(50)}.evil.com/`), /smuggled/);
    assert.match(why(`https://${'ab.'.repeat(40)}evil.com/`), /far longer than any real site/);
    // A short label cannot be told from a real one before resolving; the budget and taint limits are what bound that channel.
    assert.equal(ok('https://abc123.evil.com/'), true);
  });

  it('applies deny and allow lists to a host and everything under it', () => {
    assert.equal(ok('https://evil.com/', { denyHosts: ['evil.com'] }), false);
    assert.equal(ok('https://a.b.evil.com/', { denyHosts: ['evil.com'] }), false);
    assert.equal(ok('https://notevil.com/', { denyHosts: ['evil.com'] }), true);
    assert.equal(ok('https://docs.rs/', { allowHosts: ['docs.rs', 'nodejs.org'] }), true);
    assert.equal(ok('https://x.docs.rs/', { allowHosts: ['docs.rs'] }), true);
    assert.equal(ok('https://other.com/', { allowHosts: ['docs.rs'] }), false);
    assert.equal(ok('https://8.8.8.8/', { allowHosts: ['docs.rs'] }), false, 'an address is not on the allow list');
  });

  it('makes one spelling of a URL, and ignores the fragment, which never reaches a server', () => {
    const a = checkUrl('https://EXAMPLE.com:443/a#one');
    const b = checkUrl('https://example.com/a#two');
    assert.ok(a.ok && b.ok);
    if (a.ok && b.ok) assert.equal(canonicalUrl(a.url), canonicalUrl(b.url));
  });
});

describe('addresses after a name is resolved', () => {
  it('blocks private, loopback, link-local, reserved and wrapped addresses, and allows public ones', () => {
    for (const address of ['127.0.0.1', '10.1.2.3', '192.168.0.1', '169.254.169.254', '::1', 'fe80::1', 'fd12::1', '::ffff:10.0.0.1', '::ffff:a00:1', '64:ff9b::a00:1', '100.100.100.200']) {
      assert.notEqual(blockedAddress(address), null, address);
    }
    for (const address of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '2606:4700:4700::1111', '::ffff:8.8.8.8']) assert.equal(blockedAddress(address), null, address);
    assert.match(blockedAddress('::ffff:10.0.0.1') ?? '', /wraps the private address 10.0.0.1/);
    assert.match(blockedAddress('not-an-ip') ?? '', /not an address/);
  });
});

describe('the limits that apply once untrusted text is in the session', () => {
  const url = (raw: string): URL => new URL(raw);

  it('lets any fetch through while nothing untrusted has been read, within the budget', () => {
    const policy = new EgressPolicy();
    assert.deepEqual(policy.decide(url('https://example.com/a')), { ok: true });
  });

  it('attack: path_encoded_exfil_blocked_under_taint (only the exact URL the user typed)', () => {
    let tainted = false;
    const policy = new EgressPolicy({ tainted: () => tainted });
    policy.noteUserText('Please read https://docs.example.com/guide. Thanks!');
    tainted = true;
    assert.deepEqual(policy.decide(url('https://docs.example.com/guide')), { ok: true });
    assert.deepEqual(policy.decide(url('https://docs.example.com/guide#section')), { ok: true }, 'a fragment never reaches the server');
    for (const stolen of ['https://docs.example.com/guide?d=SECRET', 'https://docs.example.com/guide/SECRET', 'https://docs.example.com/', 'https://evil.com/guide', 'https://docs.example.com/guide%3Fd%3D1', 'https://abc.docs.example.com/guide']) {
      const decision = policy.decide(url(stolen));
      assert.equal(decision.ok, false, stolen);
      assert.match(decision.ok ? '' : decision.reason, /a URL you typed, exactly as typed/);
    }
  });

  it('does not treat a URL taken from a response as the user\'s, and a redirect is held to the same rule', () => {
    const policy = new EgressPolicy({ tainted: () => true });
    policy.noteUserText('read https://a.example.com/start');
    assert.equal(policy.decide(url('https://a.example.com/start')).ok, true);
    assert.equal(policy.decide(url('https://b.example.com/landing')).ok, false, 'a redirect target the user never typed');
  });

  it('counts a URL a person approved on a card as the user\'s', () => {
    const policy = new EgressPolicy({ tainted: () => true });
    assert.equal(policy.decide(url('https://x.example.com/p')).ok, false);
    policy.grant(url('https://x.example.com/p'));
    assert.equal(policy.decide(url('https://x.example.com/p')).ok, true);
    assert.equal(policy.decide(url('https://x.example.com/p?more=1')).ok, false);
  });

  it('finds URLs in ordinary sentences, with punctuation after them, and ignores bad ones', () => {
    const policy = new EgressPolicy({ tainted: () => true });
    policy.noteUserText('see (https://one.example.com/a), or https://two.example.com/b?x=1; also http://localhost/secret and https://user:pw@three.example.com/');
    assert.equal(policy.decide(url('https://one.example.com/a')).ok, true);
    assert.equal(policy.decide(url('https://two.example.com/b?x=1')).ok, true);
    assert.equal(policy.decide(url('http://localhost/secret')).ok, false, 'a private URL does not become allowed because the user typed it');
    assert.equal(policy.decide(url('https://three.example.com/')).ok, false);
  });

  it('gives each host a daily budget that recovers after a day, and refused requests do not spend it', () => {
    let now = 0;
    const policy = new EgressPolicy({ perHostPerDay: 3, now: () => now });
    const target = url('https://example.com/a');
    for (let i = 0; i < 3; i += 1) {
      assert.equal(policy.decide(target).ok, true);
      policy.record(target);
    }
    const decision = policy.decide(target);
    assert.equal(decision.ok, false);
    assert.match(decision.ok ? '' : decision.reason, /daily limit/);
    assert.equal(policy.decide(url('https://other.example.com/')).ok, true, 'another host has its own budget');
    now += 24 * 60 * 60 * 1000 + 1;
    assert.equal(policy.decide(target).ok, true);
  });

  it('caps how many URLs taken from earlier responses a session may fetch, but not the user\'s own', () => {
    const policy = new EgressPolicy({ maxDerived: 2 });
    policy.noteUserText('https://mine.example.com/one');
    for (const raw of ['https://a.example.com/', 'https://b.example.com/']) {
      assert.equal(policy.decide(url(raw)).ok, true);
      policy.record(url(raw));
    }
    assert.equal(policy.decide(url('https://c.example.com/')).ok, false);
    assert.equal(policy.decide(url('https://mine.example.com/one')).ok, true, 'the user\'s own URL is not capped');
  });

  it('does not spend the budget for a request that was never made', () => {
    const policy = new EgressPolicy({ perHostPerDay: 1 });
    for (let i = 0; i < 5; i += 1) assert.equal(policy.decide(url('https://example.com/')).ok, true);
  });
});
