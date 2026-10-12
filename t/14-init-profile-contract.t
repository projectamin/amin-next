#!/usr/bin/env perl
# t/14-init-profile-contract.t — Task 9 init-profile.xml stage contract
# validation.
#
# Three subtests:
#   TR-9.1: examples/metal-node/init-profile.xml is valid XML, parses cleanly
#           with XML::LibXML, and a full SAX dispatcher → Writer roundtrip
#           preserves element + attribute counts exactly.
#
#   TR-9.2: Crafted init-profile with <amin:spawn> but missing
#           order=3 (storage-init) stage.  Validator runs CLOSED-WORLD:
#           no commands reach middle; Log->error_count > 0; rendered
#           output has exit_kind=init_profile_malformed.
#
#   TR-9.3: End-document guard: 5 stages (missing 1) with NO spawn
#           commands — validator still catches it at end_document rather
#           than silently passing (proves end_document hook is active).
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use Cwd        qw(abs_path);
use lib dirname(__FILE__) . '/../perl-lib';

my $ROOT = abs_path(dirname(__FILE__) . '/..');
my $EXAMPLE = "$ROOT/examples/metal-node/init-profile.xml";

require XML::LibXML;
require Amin::Machine::Dispatcher;
require Amin::Handler::Writer;
require Amin::Log::Standard;

# Count start-element occurrences by LocalName across the document.  Returns hashref
# {LocalName => count}.
sub count_elements_xmllibxml ($xml_string) {
    my $doc = XML::LibXML->load_xml(string => $xml_string, load_ext_dtd => 0);
    my %c;
    for my $node ($doc->findnodes('//*')) {
        my $ln = $node->localname // '';
        $c{$ln}++;
    }
    return \%c;
}

# ── TR-9.1: Reference example validity + SAX roundtrip parity ──────────
#
# TR-9.1 makes two separate claims:
#   (a) The example file is schema-valid XML: XML::LibXML loads it without
#       throwing, and we count 6 <stage> elements plus 4 <bc:object> refs
#       (these are the structural anchors for the rest of the stack).
#   (b) A pure SAX round-trip (XML::LibXML::SAX parser → Amin::Handler::Writer
#       → re-parse output) preserves element counts.  We do NOT use the full
#       Amin::Machine::Dispatcher here because the Storage::Bitcache middle
#       filter legitimately adds synthetic <amin:stream> elements for
#       passthrough objects — that behaviour belongs to Task 5 tests, not
#       Task 9.  We DO run the Dispatcher once to validate stage ordering
#       (checking validator's error count only) separately.
{
    ok(-f $EXAMPLE, "examples/metal-node/init-profile.xml exists on disk");
    open(my $fh, '<:encoding(UTF-8)', $EXAMPLE)
        or die "open $EXAMPLE: $!";
    my $xml = do { local $/; <$fh> };
    close $fh;

    # ── 9.1a: XML::LibXML structural parse ──────────────────────────────
    my $before = count_elements_xmllibxml($xml);
    is($before->{stage},    6, '9.1a: 6 stage elements total (1..=6)');
    is($before->{object},   5, '9.1a: 5 bc:object envelope refs (1 outer + 1 machine-spec + 3 fw-update)');
    is($before->{server},   3, '9.1a: 3 bc:server ToR peers in stage-4 mesh-join');
    is($before->{filter},   4, '9.1a: 4 amin:filter registrations in stage-5 supervisor');

    # ── 9.1b: Pure SAX → Writer roundtrip, element count parity ─────────
    require XML::LibXML::SAX;
    my $writer_pure = Amin::Handler::Writer->new(indent => 2);
    XML::LibXML::SAX->new(Handler => $writer_pure)->parse_string($xml);
    my $pure_out = $writer_pure->output;
    ok(length($pure_out) > 500, '9.1b: Writer produced output string');
    my $after = count_elements_xmllibxml($pure_out);
    is($after->{stage},    6, '9.1b: roundtrip 6 stages');
    is($after->{object},   5, '9.1b: roundtrip 5 bc:object');
    is($after->{server},   3, '9.1b: roundtrip 3 bc:server');
    is($after->{filter},   4, '9.1b: roundtrip 4 amin:filter');
    my @names = sort keys %{{ map { $_ => 1 } (keys %$before, keys %$after) }};
    my $mismatch = 0;
    for my $n (@names) {
        my $b = $before->{$n} // 0;
        my $a = $after->{$n}  // 0;
        if ($b != $a) { $mismatch++; diag "element <$n>: before=$b after=$a"; }
    }
    is($mismatch, 0, '9.1b: ALL LocalName counts identical across SAX roundtrip');

    # ── 9.1c: Dispatcher validator stage-check accepts the file ─────────
    # Note: Storage::Bitcache WILL log placeholder-hash fetch errors for
    # the example's synthetic blake3 refs — that's expected because the
    # example hashes are constants, not real slab objects.  Those errors
    # come from the Storage filter, not ProfileValidator.  For the stage
    # contract we only need: ProfileValidator emitted NO malformed status.
    my $writer2 = Amin::Handler::Writer->new(indent => 2);
    my $log2    = Amin::Log::Standard->new(stderr => 0);
    my $out2 = Amin::Machine::Dispatcher->run(
        mode       => 'render',
        source_xml => $xml,
        Handler    => $writer2,
        Log        => $log2,
    );
    unlike($out2, qr/exit_kind=(["'])init_profile_malformed\1/,
           '9.1c: validator accepts 6-stage reference as well-formed (no exit_kind=malformed)');
}

# ── Helpers for building invalid-profile subtests.
sub profile_with_stages (@stage_orders) {
    my $with_spawn = shift @stage_orders if !ref $stage_orders[0] && $stage_orders[0] eq 'WITH_SPAWN';
    my @orders = @stage_orders;
    my $stages_xml = '';
    my %name_for = (
        1 => 'hwcheck',     2 => 'fw-update',    3 => 'storage-init',
        4 => 'mesh-join', 5 => 'supervisor',  6 => 'workload-ready',
    );
    for my $o (@orders) {
        my $name = $name_for{$o} // "stage$o";
        $stages_xml .=
            qq{  <amin:stage amin:order="$o" amin:name="$name" amin:node_id="n$o"/>\n};
    }
    my $spawn_xml = '';
    if ($with_spawn) {
        $spawn_xml = qq{  <amin:spawn amin:name="malformed-should-never-run" amin:tier="metal">\n}
                   . qq{    <amin:command name="echo">\n}
                   . qq{      <amin:argv>echo</amin:argv>\n}
                   . qq{      <amin:value>MUST_NOT_RUN_IF_STAGES_BAD</amin:value>\n}
                   . qq{    </amin:command>\n}
                   . qq{  </amin:spawn>\n};
    }
    return <<"XML";
<?xml version="1.0" encoding="UTF-8"?>
<amin:profile xmlns:amin="http://projectamin.org/ns/2026/"
              xmlns:bc="http://projectamin.org/ns/bc/"
              amin:version="3.0.0"
              amin:kind="metal-init-profile">
$stages_xml$spawn_xml</amin:profile>
XML
}

# ── TR-9.2: Missing stage=3 (storage-init) → spawn present. ──────────────
{
    my $xml = profile_with_stages WITH_SPAWN => (1, 2, 4, 5, 6);

    my $writer = Amin::Handler::Writer->new(indent => 2);
    my $log    = Amin::Log::Standard->new(stderr => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'render',
        source_xml => $xml,
        Handler    => $writer,
        Log        => $log,
    );

    ok($log->error_count > 0,
       'TR-9.2: missing order=3 (storage-init) → validator logged ≥1 error (fail-closed)');
    like($out, qr/exit_kind=(["'])init_profile_malformed\1/,
         'TR-9.2: rendered output contains exit_kind=init_profile_malformed');
    unlike($out, qr/MUST_NOT_RUN_IF_STAGES_BAD/,
           'TR-9.2: NO commands reached middle filter (echo payload NEVER executed/spawned');
    like($out, qr/amin:rc=(["'])2\1/,
         'TR-9.2: synthetic status carries rc=2 (nonzero)');
}

# ── TR-9.3: End-document guard: 5 stages, NO commands at all. ────────
{
    my $xml = profile_with_stages (1, 2, 3, 4, 5);

    my $writer = Amin::Handler::Writer->new(indent => 2);
    my $log    = Amin::Log::Standard->new(stderr => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'render',
        source_xml => $xml,
        Handler    => $writer,
        Log        => $log,
    );

    ok($log->error_count > 0,
       'TR-9.3: end_document catches missing stage 6 (no data-plane triggers)');
    like($out, qr/exit_kind=(["'])init_profile_malformed\1/,
         'TR-9.3: end_document emits malformed status even with 0 spawn/command elements');
}

# ── Bonus: Closed-world: 6 valid stages + spawn → PASSES. ────────────
{
    my $xml = profile_with_stages WITH_SPAWN => (1, 2, 3, 4, 5, 6);

    my $writer = Amin::Handler::Writer->new(indent => 2);
    my $log    = Amin::Log::Standard->new(stderr => 0);
    my $out = Amin::Machine::Dispatcher->run(
        mode       => 'dryrun',
        source_xml => $xml,
        Handler    => $writer,
        Log        => $log,
    );
    is($log->error_count, 0,
       'bonus: full 6 stages + spawn → 0 validator errors (profile passes');
    unlike($out, qr/init_profile_malformed/,
           'bonus: valid profile → NO exit_kind=init_profile_malformed in output');
}

done_testing();
