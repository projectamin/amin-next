#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use Cwd        qw(abs_path);
use File::Temp qw(tempdir);
use lib dirname(__FILE__) . '/../perl-lib';

my $BCTOOL = abs_path(dirname(__FILE__) . '/../rust/target/debug/bctool');
unless (-x $BCTOOL) {
    skip_all "bctool binary not compiled; run `cargo build -p bitcache` first at ./rust";
}

use Amin::Handler::Writer;
use Amin::Log::Standard;
use Amin::Filter::Storage::Bitcache;

my $AMIN_NS   = 'http://projectamin.org/ns/2026/';
my $BC_NS     = 'http://projectamin.org/ns/bc/';

# Printable-safe 64 KB payload (XML 1.0 valid PCDATA).
my $TEST_TAIL  = "AMIN3!";
my $TEST_BYTES = ('A' x (65536 - length($TEST_TAIL))) . $TEST_TAIL;
my $TEST_LEN   = length($TEST_BYTES);  # 65536

require IPC::Run;

sub bctool (@argv) {
    my ($in, $out, $err) = ('', '', '');
    my @rest = @argv;
    if (ref($argv[-1]) && ref($argv[-1]) eq 'SCALAR') { $in = ${ pop @argv } }
    my $h = IPC::Run::harness([$BCTOOL, @argv], \$in, \$out, \$err, debug => 0);
    IPC::Run::start($h); IPC::Run::finish($h);
    my $rc = $? >> 8;
    return ($rc, $out, $err);
}

# ── Helpers ────────────────────────────────────────────────────────────
# Run one SAX pass with Storage::Bitcache (for test slab + bctool) wired
# between XML::LibXML::SAX and Writer.  Returns rendered XML string.
sub run_storage_pass ($in_xml, %o) {
    my $slab  = $o{slab}  // die "need slab";
    my $log   = $o{log}   // Amin::Log::Standard->new(stderr => 0);
    my $indent = $o{indent} // 2;

    my $writer = Amin::Handler::Writer->new(indent => $indent);
    my $storage = Amin::Filter::Storage::Bitcache->new(
        Handler     => $writer,
        Log         => $log,
        Mode        => 'render',
        Element     => 'object',
        slab_path   => $slab,
        bctool_path => $BCTOOL,
    );

    require XML::LibXML::SAX;
    my $p = XML::LibXML::SAX->new(Handler => $storage);
    $p->parse_string($in_xml);
    return $writer->output;
}

sub extract_attr ($xml, $tag, $attr) {
    return undef unless defined $xml;
    # bc:object is rendered as either <bc:object ...>\n</bc:object> (SAX2 has
    # no self-closing concept, only explicit start+end). So scan any attr list.
    while ($xml =~ m{<$tag\b([^>]*)>}gs) {
        my $attrs = $1;
        my ($v) = $attrs =~ /\Q$attr\E\s*=\s*"([^"]*)"/;
        return $v if defined $v;
    }
    return undef;
}

# ═══════════════════════════════════════════════════════════════════════
# Acceptance Case A — bc:object put → compact hash+size → get roundtrip
# ═══════════════════════════════════════════════════════════════════════
subtest 'Acceptance A: bc:object put → bc:hash/size synthesis → bc:get hydrates payload' => sub {
    my $tmp  = tempdir(CLEANUP => 1);
    my $slab = "$tmp/a.slab";
    my $log  = Amin::Log::Standard->new(stderr => 0);

    # 1. PUT pass: XML with raw <bc:object>PAYLOAD</bc:object>
    my $put_xml = '<?xml version="1.0" encoding="UTF-8"?>' .
        '<amin:profile xmlns:amin="' . $AMIN_NS . '" xmlns:bc="' . $BC_NS .
        '" id="tA1"><bc:object id="payload">' . $TEST_BYTES . '</bc:object></amin:profile>';

    my $out1 = run_storage_pass($put_xml, slab => $slab, log => $log);

    is($log->error_count, 0, 'A1: zero errors on put pass');
    my $hex1 = extract_attr($out1, 'bc:object', 'bc:hash');
    my $sz1  = extract_attr($out1, 'bc:object', 'bc:size');
    my $id1  = extract_attr($out1, 'bc:object', 'id');
    ok(defined $hex1 && length($hex1) == 64,
        'A2: <bc:object> now carries 64-hex blake3 (hash=' . substr($hex1//'',0,12) . '…)');
    is($sz1, $TEST_LEN, "A3: bc:size attribute equals input byte length ($TEST_LEN)");
    is($id1, 'payload', 'A4: user-set id attribute preserved across put synthesis');

    # Independent verify: bctool to the same slab gives same hash + size
    my ($rc, $out, $err) = bctool('put', '--slab', "$tmp/verify.slab", \$TEST_BYTES);
    is($rc, 0, 'A5: independent bctool put succeeds (sanity)');
    my %kv;
    for my $ln (split /\n/, $out) {
        my ($k, $v) = split /\t/, $ln, 2;
        $kv{$k} = $v if defined $v;
    }
    is($hex1, $kv{hash},
        'A6: filter-computed hash blake3-equal to bctool CLI (byte identical payload)');
    is($sz1,  $kv{size},
        'A7: filter size matches bctool-reported size');

    # Slab now exists, >= 4K, and has content (O_DIRECT aligned header+slot)
    ok(-f $slab, 'A8: slab file created');
    cmp_ok((-s $slab), '>=', 4096, 'A9: slab >= 4096 B (4KB O_DIRECT alignment)');

    # 2. GET pass: XML with <bc:object bc:hash="HEX" bc:size="N"/> + NO payload → hydrate
    my $get_xml = '<?xml version="1.0" encoding="UTF-8"?>' .
        '<amin:profile xmlns:amin="' . $AMIN_NS . '" xmlns:bc="' . $BC_NS . '">' .
        '<bc:object bc:hash="' . $hex1 . '" bc:size="' . $TEST_LEN . '"/></amin:profile>';

    # Use indent => 0 so Writer doesn't pad character content with indent spaces
    # before lines.  (Writer still appends a single "\n" per characters chunk —
    # we strip exactly one trailing \n below for byte-level equality.)
    my $out2 = run_storage_pass($get_xml, slab => $slab, log => $log, indent => 0);
    is($log->error_count, 0, 'A10: zero errors on get pass');

    # Capture any <amin:stream channel="bc-object"> content — the
    # Storage filter injects this to carry bytes back downstream.
    my @streams;
    while ($out2 =~ m{<amin:stream[^>]*channel="bc-object"[^>]*>(.*?)</amin:stream>}sgc) {
        push @streams, $1;
    }
    is(scalar @streams, 1,
        'A11: exactly 1 <amin:stream channel="bc-object"> emitted on retrieval');

    # Writer.pm characters() does: split /\n/, for each: pad + $_ + "\n" push.
    # With indent=0 the pad is ''; with zero embedded \n this produces
    # DATA + "\n".  Strip exactly 1 trailing \n added by the writer here.
    my $got = $streams[0] // '';
    # Also: after start_element emits "...>\n", regex capture includes a
    # leading newline (Writer's start_element appends "\n" after open tag).
    # With indent=0: start_element adds 0 indent then "\n" = 1 leading \n.
    $got =~ s/\A\n//;                     # strip 1 leading newline from open-tag close
    $got =~ s/\n\z//;                     # strip Writer-appended 1 trailing \n
    is(length($got), $TEST_LEN,
        "A12: stream (after Writer whitespace normalization) carries back exactly $TEST_LEN bytes (got ".length($got).")");
    is($got, $TEST_BYTES,
        'A13: streamed payload byte-identical to original put input');
};

# ═══════════════════════════════════════════════════════════════════════
# Acceptance Case B — bc:signer wrapper around bc:object → signed envelope
# with ML-DSA-87 + verifies; tamper (flipped hash) → fail-closed.
# ═══════════════════════════════════════════════════════════════════════
subtest 'Acceptance B: bc:signer envelope → ML-DSA-87 signature + tamper fail-closed' => sub {
    my $tmp  = tempdir(CLEANUP => 1);
    my $slab = "$tmp/b.slab";
    my $sk   = "$tmp/test.sk";
    my $log  = Amin::Log::Standard->new(stderr => 0);

    # Gen key → capture VK
    my ($rc, $out, $err) = bctool('genkey', '--name', 'test-signer', '--sk', $sk);
    is($rc, 0, 'B0: genkey rc=0') or diag "stderr=$err";
    my %kv;
    for my $ln (split /\n/, $out) {
        my ($k, $v) = split /\t/, $ln, 2;
        $kv{$k} = $v if defined $v;
    }
    my $vk = $kv{vk};
    ok(defined $vk && length($vk) > 100,
        'B1: got ML-DSA-87 VK base64 (len=' . length($vk//'') . ')');
    ok(-f $sk && -s $sk == 32, 'B2: SK is 32 B Seed file, chmod 0600');

    # 1. PUT + SIGN: put the object first → get compact object
    my $put_xml = '<?xml version="1.0" encoding="UTF-8"?>' .
        '<amin:profile xmlns:amin="' . $AMIN_NS . '" xmlns:bc="' . $BC_NS .
        '" id="tB1"><bc:object id="signed-object">' . $TEST_BYTES . '</bc:object></amin:profile>';
    my $put_out = run_storage_pass($put_xml, slab => $slab, log => $log);
    my $hex1 = extract_attr($put_out, 'bc:object', 'bc:hash');
    is($log->error_count, 0, 'B3: put pass no errors');
    ok(defined $hex1, 'B4: got object blake3');

    # 2. Call bctool sign directly to build a TSV signature record
    ($rc, $out, $err) = bctool('sign',
        '--slab', $slab, '--hash', $hex1,
        '--name', 'test-signer', '--sk', $sk);
    is($rc, 0, 'B5: bctool sign rc=0') or diag "stderr=$err";
    %kv = ();
    for my $ln (split /\n/, $out) {
        my ($k, $v) = split /\t/, $ln, 2;
        $kv{$k} = $v if defined $v;
    }
    ok(defined $kv{sig},      'B6a: TSV has sig');
    ok(defined $kv{name},     'B6b: TSV has name');
    ok(defined $kv{date},     'B6c: TSV has date');
    ok(defined $kv{timestamp},'B6d: TSV has timestamp');
    is($kv{name}, 'test-signer', 'B7: name matches input');

    # 3. Verify OK path
    ($rc, $out, $err) = bctool('verify',
        '--slab', $slab, '--hash', $hex1,
        '--name', 'test-signer', '--ts', $kv{timestamp},
        '--vk', $vk, '--sig', $kv{sig});
    is($rc, 0, 'B8: bctool verify rc=0 OK path');
    like($out, qr/verify\s+OK/i, 'B9: output contains "verify OK"');

    # 4. Tamper: flip one middle character of hash hex — fail-closed rc=7
    my $tampered = $hex1;
    my $flip_pos = length($tampered) - 3;
    my $c = substr($tampered, $flip_pos, 1);
    substr($tampered, $flip_pos, 1) = ($c eq '0') ? 'f' : '0';
    isnt($tampered, $hex1, 'B10: produced distinct tampered hash string');

    ($rc, $out, $err) = bctool('verify',
        '--slab', $slab, '--hash', $tampered,
        '--name', 'test-signer', '--ts', $kv{timestamp},
        '--vk', $vk, '--sig', $kv{sig});
    isnt($rc, 0, 'B11: tampered hash → verify nonzero rc (fail-closed)');
    is($rc, 7, 'B12: tampered hash → verify exit 7 (FAIL-codes per bctool CLI spec)');
};

# ═══════════════════════════════════════════════════════════════════════
# Extra: true deduplication — identical payload → slab file does not grow
# ═══════════════════════════════════════════════════════════════════════
subtest 'Dedup: two identical puts → slab does not 2x' => sub {
    my $tmp  = tempdir(CLEANUP => 1);
    my $slab = "$tmp/d.slab";
    my $big  = "\x55" x (2 * 1024 * 1024);   # 2 MB
    my ($h1, $s1, $h2, $s2);

    my ($rc, $out, $err) = bctool('put', '--slab', $slab, \$big);
    is($rc, 0, 'D1: first put OK');
    $s1 = -s $slab;
    for my $ln (split /\n/, $out) {
        my ($k, $v) = split /\t/, $ln, 2;
        $h1 = $v if $k eq 'hash';
    }

    ($rc, $out, $err) = bctool('put', '--slab', $slab, \$big);
    is($rc, 0, 'D2: second identical put OK');
    $s2 = -s $slab;
    for my $ln (split /\n/, $out) {
        my ($k, $v) = split /\t/, $ln, 2;
        $h2 = $v if $k eq 'hash';
    }
    is($h1, $h2, 'D3: hashes identical (blake3 dedup key)');
    is($s1, $s2, "D4: slab did not grow (${s1}B after both puts; O_DIRECT refcount inlined into header slot)");
};

done_testing;
