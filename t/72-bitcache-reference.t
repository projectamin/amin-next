#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use Cwd        qw(abs_path);
use File::Temp qw(tempdir);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Bitcache::Reference;

# The single resolver shared by Amin::Machine::MachineSpec and the proxy config
# loader (proxy-plan §5.13): parse a signed bitcache:// reference, fetch it from
# the CAS, and verify its ML-DSA-87 signature — never re-implementing PQ verify.
# The shape tests below need no CAS; the fetch/verify tests need the real
# bctool the production signer uses, and skip cleanly when it is not built.

# ── Shape: parse + predicate, no CAS ───────────────────────────────────────
subtest 'is_reference predicate' => sub {
    ok Amin::Bitcache::Reference::is_reference('bitcache://blake3/' . ('a' x 64)),
        'accepts a bitcache:// ref';
    ok !Amin::Bitcache::Reference::is_reference('/etc/amin/spec.xml'),
        'rejects a filesystem path';
    ok !Amin::Bitcache::Reference::is_reference(undef), 'rejects undef';
    ok !Amin::Bitcache::Reference::is_reference(''),    'rejects empty string';
};

subtest 'parse: bitcache:// URI into fields' => sub {
    require URI::Escape;
    my $hash = 'a' x 64;
    my $uri  = sprintf 'bitcache://blake3/%s?signer=%s&ts=%s&vk=%s&sig=%s',
        $hash,
        URI::Escape::uri_escape('alice'),
        URI::Escape::uri_escape('1735689600'),
        URI::Escape::uri_escape('VKBYTES'),
        URI::Escape::uri_escape('SIGBYTES');
    my $r = Amin::Bitcache::Reference->new(uri => $uri)->parse;
    ok $r->addressed, 'addressed after parse';
    is $r->hash, $hash, 'hash extracted';
    is $r->{signer_name}, 'alice',      'signer=  mapped to signer_name';
    is $r->{signer_ts},   '1735689600', 'ts=      mapped to signer_ts';
    is $r->{signer_vk},   'VKBYTES',    'vk=      mapped to signer_vk';
    is $r->{signer_sig},  'SIGBYTES',   'sig=     mapped to signer_sig';
};

subtest 'parse: anything not a blake3 64-hex ref stays unaddressed' => sub {
    for my $bad ('/etc/amin/spec.xml', 'https://example/x',
                 'bitcache://sha256/' . ('a' x 64), 'bitcache://blake3/nothex') {
        my $r = Amin::Bitcache::Reference->new(uri => $bad)->parse;
        ok !$r->addressed, "unaddressed: $bad";
    }
};

subtest 'hash= handed directly → addressed; bc_hash= is an alias' => sub {
    my $r = Amin::Bitcache::Reference->new(hash => ('b' x 64));
    ok $r->addressed, 'hash= makes a reference addressed';
    is $r->hash, 'b' x 64, 'hash survives';

    my $a = Amin::Bitcache::Reference->new(bc_hash => ('c' x 64));
    is $a->hash, 'c' x 64, 'bc_hash= aliased to hash';
};

subtest 'path= carrying a bitcache:// URI is parsed' => sub {
    my $r = Amin::Bitcache::Reference->new(
        path => 'bitcache://blake3/' . ('d' x 64))->parse;
    ok $r->addressed, 'path=bitcache://... parsed';
    is $r->hash, 'd' x 64, 'hash from path';
};

subtest 'an unaddressed reference resolves closed (no bytes)' => sub {
    my $r = Amin::Bitcache::Reference->new(uri => '/etc/amin/spec.xml')->parse;
    is $r->get,     undef, 'get on an unaddressed ref → undef';
    is $r->verify,  0,     'verify → 0 without a hash/signature';
    is $r->resolve, undef, 'resolve → undef';
};

# ── Fetch + verify against the real CAS ────────────────────────────────────
my $BCTOOL = abs_path(dirname(__FILE__) . '/../rust/target/debug/bctool');
if (!-x $BCTOOL) {
    diag 'bctool binary not compiled; CAS-backed subtests skipped '
       . '(run `cargo build -p bitcache` at ./rust)';
}
else {
    require IPC::Run;
    my $tmp   = tempdir(CLEANUP => 1);
    my $slab  = "$tmp/r.slab";
    my $sk    = "$tmp/r.sk";
    my $bytes = "reference-payload-" . ('x' x 40) . "\n";

    my $bctool = sub (@argv) {
        my $in = '';
        $in = ${ pop @argv } if ref($argv[-1]) && ref($argv[-1]) eq 'SCALAR';
        my ($out, $err) = ('', '');
        my $h = IPC::Run::harness([$BCTOOL, @argv], \$in, \$out, \$err, debug => 0);
        IPC::Run::start($h); IPC::Run::finish($h);
        return ($? >> 8, $out, $err);
    };
    my $kv = sub ($out) {
        my %kv;
        for my $ln (split /\n/, $out) {
            my ($k, $v) = split /\t/, $ln, 2;
            $kv{$k} = $v if defined $v;
        }
        return \%kv;
    };

    my ($rc, $out, $err) = $bctool->('put', '--slab', $slab, \$bytes);
    is $rc, 0, 'put rc=0';
    my $hash = $kv->($out)->{hash};
    ok defined $hash && length($hash) == 64, '64-hex blake3 hash'
        or diag "out=$out err=$err";

    ($rc, $out, $err) = $bctool->('genkey', '--name', 'ref-signer', '--sk', $sk);
    is $rc, 0, 'genkey rc=0';
    my $vk = $kv->($out)->{vk};
    ok defined $vk && length $vk, 'VK produced';

    ($rc, $out, $err) = $bctool->('sign',
        '--slab', $slab, '--hash', $hash, '--name', 'ref-signer', '--sk', $sk);
    is $rc, 0, 'sign rc=0';
    my ($sig, $ts) = @{ $kv->($out) }{qw(sig timestamp)};
    ok defined $sig && length $sig, 'signature produced';
    ok defined $ts  && length $ts,  'timestamp produced';

    subtest 'get returns the CAS bytes; resolve returns them verified' => sub {
        my $r = Amin::Bitcache::Reference->new(
            hash => $hash, slab_path => $slab, bctool_path => $BCTOOL);
        my $raw = $r->get;
        ok ref($raw) eq 'SCALAR', 'get returns a scalar ref';
        is $$raw, $bytes, 'bytes match what was put';

        my $v = Amin::Bitcache::Reference->new(
            hash => $hash, slab_path => $slab, bctool_path => $BCTOOL,
            signer_name => 'ref-signer', signer_ts => $ts,
            signer_vk   => $vk, signer_sig => $sig);
        ok $v->verify, 'signature verifies against the inline VK';
        is $v->resolve, $bytes, 'resolve returns the verified object';
    };

    subtest 'resolve: get and verify, fail-closed on any failure' => sub {
        # Unknown hash → the CAS has nothing → undef.
        my $miss = Amin::Bitcache::Reference->new(
            hash => ('0' x 64), slab_path => $slab, bctool_path => $BCTOOL,
            signer_name => 'ref-signer', signer_ts => $ts,
            signer_vk   => $vk, signer_sig => $sig);
        is $miss->get, undef, 'unknown hash → no bytes';
        is $miss->resolve, undef, 'unknown hash → resolve undef';

        # Correct object, tampered signature → verify rejects → undef.
        my $bad = $sig;
        substr($bad, 10, 1) = ($bad =~ /^.{10}[A-Z]/) ? 'a' : 'A';
        isnt $bad, $sig, 'signature actually mutated';
        my $r = Amin::Bitcache::Reference->new(
            hash => $hash, slab_path => $slab, bctool_path => $BCTOOL,
            signer_name => 'ref-signer', signer_ts => $ts,
            signer_vk   => $vk, signer_sig => $bad);
        is $r->verify,  0,     'tampered signature does not verify';
        is $r->resolve, undef, 'tampered signature → resolve undef';

        # No signature params at all → unsigned object is not trusted.
        my $u = Amin::Bitcache::Reference->new(
            hash => $hash, slab_path => $slab, bctool_path => $BCTOOL);
        is $u->verify,  0,     'unsigned object does not verify';
        is $u->resolve, undef, 'unsigned object → resolve undef';
    };

    subtest 'URI path round-trips through resolve (inline VK)' => sub {
        require URI::Escape;
        my $uri = sprintf 'bitcache://blake3/%s?signer=%s&ts=%s&vk=%s&sig=%s',
            $hash,
            URI::Escape::uri_escape('ref-signer'),
            URI::Escape::uri_escape($ts),
            URI::Escape::uri_escape($vk),
            URI::Escape::uri_escape($sig);
        my $r = Amin::Bitcache::Reference->new(
            uri => $uri, slab_path => $slab, bctool_path => $BCTOOL)->parse;
        ok $r->addressed, 'URI parsed and addressed';
        is $r->resolve, $bytes, 'URI reference resolves to the same bytes';
    };

    subtest 'VK resolved from trust_anchor_dir (sha256(signer).vk)' => sub {
        require Digest::SHA;
        require MIME::Base64;
        my $ta = "$tmp/trust";
        mkdir $ta or die "mkdir $ta: $!";
        my $vf = "$ta/" . Digest::SHA::sha256_hex('ref-signer') . '.vk';
        open(my $fh, '>:raw', $vf) or die "open $vf: $!";
        print $fh MIME::Base64::decode_base64($vk);
        close $fh;

        my $r = Amin::Bitcache::Reference->new(
            hash => $hash, slab_path => $slab, bctool_path => $BCTOOL,
            signer_name => 'ref-signer', signer_ts => $ts, signer_sig => $sig,
            trust_anchor_dir => $ta);
        ok $r->verify, 'VK found under trust_anchor_dir → verifies';
        is $r->resolve, $bytes, 'resolve via trust_anchor_dir returns the bytes';
    };
}

done_testing;
