#!/usr/bin/env perl
# End-to-end test for the `sec:` post-quantum E2EE filters.  Drives the Perl
# SAX filters over the real `rctool` binary exactly the way a profile would:
#
#   sec:bundle ──Prekey(initiator)──▶ sec:prekey ──Prekey(responder)──▶ sec:session
#   sec:seal   ──RatchetSeal───────▶ sec:sealed
#   sec:sealed ──RatchetOpen───────▶ <amin:stream channel="sec-open">plaintext
#
# Also proves the two halves compose in one chain without the seal output being
# re-opened (Seal is the innermost `end` stage, Open an element-scoped `middle`
# candidate), and that a tampered ciphertext is fail-closed.
use v5.38; use warnings; use utf8;
use experimental 'signatures';
use Test2::V0;
use File::Basename qw(dirname);
use File::Copy     qw(copy);
use File::Temp     qw(tempdir);
use Cwd            qw(abs_path);
use lib dirname(__FILE__) . '/../perl-lib';

my $RCTOOL = abs_path(dirname(__FILE__) . '/../rust/target/debug/rctool');
$RCTOOL = abs_path(dirname(__FILE__) . '/../target/debug/rctool')
    unless defined $RCTOOL && -x $RCTOOL;
unless (defined $RCTOOL && -x $RCTOOL) {
    skip_all 'rctool binary not compiled; run `cargo build -p ratchet` first at ./rust';
}
# Gate-instantiated filters resolve the binary through Amin::ToolPaths.
$ENV{AMIN_RCTOOL} = $RCTOOL;

use Amin::Log::Standard;
use Amin::Machine::MachineSpec;
use Amin::Machine::Dispatcher;
use Amin::Filter::Crypto::RatchetSeal;
use Amin::Filter::Crypto::RatchetOpen;
use Amin::Filter::Crypto::Prekey;

require IPC::Run;

my $AMIN_NS = 'http://projectamin.org/ns/2026/';
my $SEC_NS  = 'http://projectamin.org/ns/sec/1';

sub rctool (@argv) {
    my ($in, $out, $err) = ('', '', '');
    if (ref($argv[-1]) && ref($argv[-1]) eq 'SCALAR') { $in = ${ pop @argv } }
    my $h = IPC::Run::harness([$RCTOOL, @argv], \$in, \$out, \$err, debug => 0);
    IPC::Run::start($h); IPC::Run::finish($h);
    return (($? >> 8), $out, $err);
}

sub kv ($text) {
    my %kv;
    for my $ln (split /\n/, $text // '') {
        my ($k, $v) = split /\t/, $ln, 2;
        $kv{$k} = $v if defined $v;
    }
    return \%kv;
}

# Minimal SAX sink: records events so assertions read the filter's real output
# (no string round-trip through the Writer, which would mangle opaque blobs).
{
    package SecCapture;
    use v5.38; use warnings; use experimental 'signatures';

    sub new ($class, %o) { bless { events => [], %o }, $class }

    sub start_element ($self, $el) {
        push $self->{events}->@*,
            [ 'start', $el->{Name} // $el->{LocalName} // '', $el->{NamespaceURI} // '',
              $el->{Attributes} // {} ];
    }
    sub end_element ($self, $el) {
        push $self->{events}->@*, [ 'end', $el->{Name} // $el->{LocalName} // '', $el->{NamespaceURI} // '' ];
    }
    sub characters ($self, $d) { push $self->{events}->@*, [ 'chars', $d->{Data} // '' ] }

    # Events we do not assert on are consumed.
    sub start_document ($self, @) { }
    sub end_document   ($self, @) { }

    sub find ($self, $name) {
        return grep { $_->[0] eq 'start' && $_->[1] eq $name } $self->{events}->@*;
    }

    sub text_of ($self, $name) {
        my @ev = $self->{events}->@*;
        my $i;
        for ($i = 0; $i < @ev; $i++) { last if $ev[$i][0] eq 'start' && $ev[$i][1] eq $name }
        return undef if $i >= @ev;
        my $txt = '';
        for (my $j = $i + 1; $j < @ev; $j++) {
            last if $ev[$j][0] eq 'end';
            $txt .= $ev[$j][1] if $ev[$j][0] eq 'chars';
        }
        return $txt;
    }

    sub attr_of ($self, $name, $attr) {
        my ($hit) = $self->find($name) or return undef;
        my $attrs = $hit->[3] // {};
        for my $k (keys %$attrs) {
            (my $base = $k) =~ s/^\{[^}]*\}//;
            return $attrs->{$k}{Value} if $base eq $attr;
        }
        return undef;
    }
}

# One SAX pass through a single sec: filter.  Returns the capture (the log is
# owned by the caller so it can assert error_count).
sub sec_pass ($xml, %o) {
    my $cap = SecCapture->new;
    my $filter = $o{class}->new(
        Handler => $cap, Log => $o{log}, Mode => 'render',
        rctool_path  => $RCTOOL,
        ($o{element} ? (Element      => $o{element}) : ()),
        ($o{session} ? (session_path => $o{session}) : ()),
        ($o{ad}      ? (ad           => $o{ad})      : ()),
        ($o{id_dh}   ? (id_dh_path   => $o{id_dh})   : ()),
        ($o{prekeys} ? (prekeys_path => $o{prekeys}) : ()),
    );
    require XML::LibXML::SAX;
    my $p = XML::LibXML::SAX->new(Handler => $filter);
    $p->parse_string($xml);
    return $cap;
}

# sec:<name> attribute in Clark notation.
sub sec_attr ($name, $value) {
    my $local = ($name =~ /:(.+)$/) ? $1 : $name;
    return "{$SEC_NS}$local" => {
        Name => $name, LocalName => $local, Prefix => 'sec',
        NamespaceURI => $SEC_NS, Value => $value,
    };
}

# ── session fixtures: Bob (responder) publishes, Alice (initiator) consumes ──
my $tmp         = tempdir(CLEANUP => 1);
my $bob_sk      = "$tmp/bob.sk";
my $bob_prekeys = "$tmp/bob.prekeys";
my $alice_id_dh = "$tmp/alice.id_dh";
my $alice_state = "$tmp/alice.state";
my $bob_state   = "$tmp/bob.state";
my $BUNDLE;

# ═══════════════════════════════════════════════════════════════════════════
# A. PQXDH handshake through the filters, both roles.
# ═══════════════════════════════════════════════════════════════════════════
subtest 'A: Prekey initiator — sec:bundle in, sec:prekey out' => sub {
    my ($rc, $out, $err) = rctool('genkey', '--sk', $bob_sk);
    is($rc, 0, 'A0a: genkey rc=0') or diag $err;

    ($rc, $BUNDLE, $err) = rctool('prekey-gen', '--sk', $bob_sk,
        '--prekeys', $bob_prekeys, '--id', '1', '--otp');
    is($rc, 0, 'A0b: prekey-gen rc=0') or diag $err;
    my $b = kv($BUNDLE);
    ok(defined $b->{identity_vk} && length $b->{identity_vk}, 'A0c: bundle has ML-DSA-87 vk');
    ok(defined $b->{pq_prekey}  && length $b->{pq_prekey},  'A0d: bundle has ML-KEM prekey');

    ($rc, $out, $err) = rctool('dh-gen', '--path', $alice_id_dh);
    is($rc, 0, 'A0e: dh-gen rc=0') or diag $err;

    my $log = Amin::Log::Standard->new(stderr => 0);
    my $xml = '<?xml version="1.0" encoding="UTF-8"?>'
        . qq{<amin:profile xmlns:amin="$AMIN_NS" xmlns:sec="$SEC_NS">}
        . qq{<sec:bundle sec:session="$alice_state">$BUNDLE</sec:bundle></amin:profile>};
    my $cap = sec_pass($xml,
        class => 'Amin::Filter::Crypto::Prekey', element => 'bundle',
        id_dh => $alice_id_dh, log => $log);

    is($log->error_count, 0, 'A1: initiator pass logs no errors');
    is(scalar($cap->find('sec:bundle')), 0, 'A2: sec:bundle consumed (not forwarded)');
    is(scalar($cap->find('sec:prekey')), 1, 'A3: exactly one <sec:prekey> emitted');
    is(($cap->attr_of('sec:prekey', 'prekey_id') // ''), '1', 'A4: prekey_id surfaced');
    is(($cap->attr_of('sec:prekey', 'used_one_time_prekey') // ''), '1',
        'A5: one-time prekey flagged used');
    ok(length($cap->attr_of('sec:prekey', 'ephemeral') // ''),   'A6: ephemeral DH present');
    ok(length($cap->attr_of('sec:prekey', 'identity_dh') // ''), 'A7: initiator identity DH present');
    my $pq_ct = $cap->text_of('sec:prekey') // '';
    ok(length $pq_ct, 'A8: ML-KEM ciphertext carried as element text');
    is($cap->attr_of('sec:prekey', 'session'), $alice_state, 'A9: sec:session carried through');
    ok(-s $alice_state, 'A10: initiator session state written by rctool init');
};

subtest 'B: Prekey responder — sec:prekey in, sec:session out' => sub {
    # Re-run the initiator leg (A above is scoped) to obtain the initial message.
    my $log_a = Amin::Log::Standard->new(stderr => 0);
    my $xml_a = '<?xml version="1.0" encoding="UTF-8"?>'
        . qq{<amin:profile xmlns:amin="$AMIN_NS" xmlns:sec="$SEC_NS">}
        . qq{<sec:bundle sec:session="$alice_state">$BUNDLE</sec:bundle></amin:profile>};
    my $cap_a = sec_pass($xml_a,
        class => 'Amin::Filter::Crypto::Prekey', element => 'bundle',
        id_dh => $alice_id_dh, log => $log_a);
    is($log_a->error_count, 0, 'B0: initiator leg clean');

    my %a = map { $_ => $cap_a->attr_of('sec:prekey', $_) }
        qw(identity_dh ephemeral prekey_id used_one_time_prekey);
    my $pq_ct = $cap_a->text_of('sec:prekey') // '';

    my $log = Amin::Log::Standard->new(stderr => 0);
    my $xml = '<?xml version="1.0" encoding="UTF-8"?>'
        . qq{<amin:profile xmlns:amin="$AMIN_NS" xmlns:sec="$SEC_NS">}
        . qq{<sec:prekey sec:session="$bob_state"}
        . qq{ sec:identity_dh="$a{identity_dh}" sec:ephemeral="$a{ephemeral}"}
        . qq{ sec:prekey_id="$a{prekey_id}" sec:used_one_time_prekey="$a{used_one_time_prekey}">}
        . $pq_ct . '</sec:prekey></amin:profile>';
    my $cap = sec_pass($xml,
        class => 'Amin::Filter::Crypto::Prekey', element => 'prekey',
        prekeys => $bob_prekeys, log => $log);

    is($log->error_count, 0, 'B1: responder pass logs no errors');
    is(scalar($cap->find('sec:prekey')), 0,  'B2: sec:prekey consumed');
    is(scalar($cap->find('sec:session')), 1, 'B3: <sec:session> announced');
    is($cap->attr_of('sec:session', 'session'), $bob_state, 'B4: session attr echoed');
    is($cap->text_of('sec:session'), '', 'B5: session element is empty');
    ok(-s $bob_state, 'B6: responder session state written by rctool respond');
};

# ═══════════════════════════════════════════════════════════════════════════
# C/D. Per-message seal + open over the established session.
# ═══════════════════════════════════════════════════════════════════════════
my ($CT, %SEALED);
subtest 'C: RatchetSeal — sec:seal in, sec:sealed out (plaintext not leaked)' => sub {
    my $plain = 'the quick brown fox jumps over the lazy dog';
    my $log = Amin::Log::Standard->new(stderr => 0);
    my $xml = '<?xml version="1.0" encoding="UTF-8"?>'
        . qq{<amin:profile xmlns:amin="$AMIN_NS" xmlns:sec="$SEC_NS">}
        . qq{<sec:seal sec:session="$alice_state" sec:ad="room:1">$plain</sec:seal></amin:profile>};
    my $cap = sec_pass($xml,
        class => 'Amin::Filter::Crypto::RatchetSeal', element => 'seal', log => $log);

    is($log->error_count, 0, 'C1: seal pass logs no errors');
    is(scalar($cap->find('sec:seal')), 0,   'C2: sec:seal consumed');
    is(scalar($cap->find('sec:sealed')), 1, 'C3: exactly one <sec:sealed> emitted');
    ok(length($cap->attr_of('sec:sealed', 'ratchet') // ''),    'C4: sec:ratchet header present');
    like($cap->attr_of('sec:sealed', 'prev_count') // '', qr/^\d+$/, 'C5: sec:prev_count is a number');
    like($cap->attr_of('sec:sealed', 'msg_index')  // '', qr/^\d+$/, 'C6: sec:msg_index is a number');
    is($cap->attr_of('sec:sealed', 'ad'), 'room:1', 'C7: associated data preserved');
    my $ct = $cap->text_of('sec:sealed') // '';
    ok(length $ct, 'C8: ciphertext carried');
    isnt($ct, $plain, 'C9: ciphertext is not the plaintext');
    unlike($ct, qr/quick brown/, 'C10: plaintext does not leak into the sealed element');
    ok($ct =~ /^[0-9a-f]+$/, 'C11: ciphertext is lowercase hex (rctool wire form)');

    $CT = $ct;
    %SEALED = map { $_ => $cap->attr_of('sec:sealed', $_) }
        qw(ratchet prev_count msg_index);
    copy($bob_state, "$tmp/bob.bad.state");
};

subtest 'D: RatchetOpen — sec:sealed in, recovered plaintext on <amin:stream>' => sub {
    my $log = Amin::Log::Standard->new(stderr => 0);
    my $xml = '<?xml version="1.0" encoding="UTF-8"?>'
        . qq{<amin:profile xmlns:amin="$AMIN_NS" xmlns:sec="$SEC_NS">}
        . qq{<sec:sealed sec:session="$bob_state" sec:ratchet="$SEALED{ratchet}"}
        . qq{ sec:prev_count="$SEALED{prev_count}" sec:msg_index="$SEALED{msg_index}" sec:ad="room:1">}
        . $CT . '</sec:sealed></amin:profile>';
    my $cap = sec_pass($xml,
        class => 'Amin::Filter::Crypto::RatchetOpen', element => 'sealed', log => $log);

    is($log->error_count, 0, 'D1: open pass logs no errors');
    is(scalar($cap->find('sec:sealed')), 0,   'D2: sec:sealed consumed');
    is(scalar($cap->find('amin:stream')), 1,  'D3: exactly one <amin:stream> emitted');
    is($cap->attr_of('amin:stream', 'channel'), 'sec-open', 'D4: channel="sec-open"');
    is($cap->text_of('amin:stream'), 'the quick brown fox jumps over the lazy dog',
        'D5: recovered plaintext is byte-identical to the sealed input');
};

subtest 'E: tampered ciphertext is fail-closed (no stream, error logged)' => sub {
    my $bad = $CT;
    my $first = substr($bad, 0, 2);
    substr($bad, 0, 2) = ($first eq '00' ? '11' : '00');
    isnt($bad, $CT, 'E0: tampered ciphertext differs');

    my $log = Amin::Log::Standard->new(stderr => 0);
    my $xml = '<?xml version="1.0" encoding="UTF-8"?>'
        . qq{<amin:profile xmlns:amin="$AMIN_NS" xmlns:sec="$SEC_NS">}
        . qq{<sec:sealed sec:session="$tmp/bob.bad.state" sec:ratchet="$SEALED{ratchet}"}
        . qq{ sec:prev_count="$SEALED{prev_count}" sec:msg_index="$SEALED{msg_index}" sec:ad="room:1">}
        . $bad . '</sec:sealed></amin:profile>';
    my $cap = sec_pass($xml,
        class => 'Amin::Filter::Crypto::RatchetOpen', element => 'sealed', log => $log);

    cmp_ok($log->error_count, '>', 0, 'E1: AEAD failure logged');
    is(scalar($cap->find('amin:stream')), 0, 'E2: nothing emitted (fail-closed)');
};

# ═══════════════════════════════════════════════════════════════════════════
# F. Both halves in ONE chain: Seal must not be re-opened by Open.
# ═══════════════════════════════════════════════════════════════════════════
subtest 'F: chain composition — Seal (end) and Open (middle) do not loop' => sub {
    my $log = Amin::Log::Standard->new(stderr => 0);
    my $cap = SecCapture->new;
    my $spec_filters = [
        { class => 'Amin::Filter::Crypto::RatchetOpen',
          meta  => { position => 'middle', element => 'sealed', namespace => $SEC_NS } },
        { class => 'Amin::Filter::Crypto::RatchetSeal',
          meta  => { position => 'end', element => 'seal', namespace => $SEC_NS } },
    ];
    my $chain = Amin::Machine::Dispatcher::_build_chain(
        $cap, $log, 'render', {}, undef, $spec_filters);
    ok($chain, 'F0: chain built');

    my $el = sub ($ns, $ln, $pfx, $attrs) {
        return { NamespaceURI => $ns, LocalName => $ln, Name => "$pfx:$ln",
                 Prefix => $pfx, Attributes => $attrs // {} };
    };
    $chain->start_document({});
    $chain->start_element($el->($AMIN_NS, 'profile', 'amin', {}));
    $chain->start_element($el->($SEC_NS, 'seal', 'sec',
        { sec_attr('sec:session', $alice_state), sec_attr('sec:ad', 'room:1') }));
    $chain->characters({ Data => 'chain plaintext' });
    $chain->end_element($el->($SEC_NS, 'seal', 'sec', {}));
    $chain->end_element($el->($AMIN_NS, 'profile', 'amin', {}));
    $chain->end_document({});

    is(scalar($cap->find('sec:sealed')), 1,
        'F1: Seal fired and emitted <sec:sealed>');
    is(scalar($cap->find('sec:seal')), 0, 'F2: plaintext element consumed');
    is(scalar($cap->find('amin:stream')), 0,
        'F3: Open did NOT re-open Seal own output (no sec-open stream)');
    ok(length($cap->text_of('sec:sealed') // ''), 'F4: ciphertext present in the sealed output');
};

# ═══════════════════════════════════════════════════════════════════════════
# G. The stock machine spec declares the sec: filters at the intended bindings.
# ═══════════════════════════════════════════════════════════════════════════
subtest 'G: machine_spec declares the sec: elements' => sub {
    my $spec = Amin::Machine::MachineSpec->new->spec;
    my %decl;
    push $decl{ $_->{class} }->@*, $_->{meta} for $spec->{filters}->@*;

    my ($open) = @{ $decl{'Amin::Filter::Crypto::RatchetOpen'} // [] };
    ok($open, 'G1: RatchetOpen declared');
    is($open->{position}, 'middle', 'G2: RatchetOpen at middle');
    is($open->{element},  'sealed', 'G3: RatchetOpen gated on <sec:sealed>');
    is($open->{namespace}, $SEC_NS, 'G4: RatchetOpen bound to the sec: namespace');

    my ($seal) = @{ $decl{'Amin::Filter::Crypto::RatchetSeal'} // [] };
    ok($seal, 'G5: RatchetSeal declared');
    is($seal->{position}, 'end', 'G6: RatchetSeal at end (innermost)');
    is($seal->{element},  'seal', 'G7: RatchetSeal gated on <sec:seal>');

    my $pre = $decl{'Amin::Filter::Crypto::Prekey'} // [];
    is(scalar($pre->@*), 2, 'G8: Prekey declared for both PQXDH elements');
    is([sort map { $_->{element} } @$pre], ['bundle', 'prekey'],
        'G9: Prekey gates are <sec:bundle> (initiator) + <sec:prekey> (responder)');
};

done_testing;
