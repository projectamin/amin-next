#!/usr/bin/env perl
# t/48-chain-selection.t — lazy chain composition via per-position gates.
#
# Architecture under test: the machine spec declares everything the machine
# *supports* (positions + element/name bindings).  The base graph keeps only
# what is always present — PERMANENT filters (always in the graph), element-
# agnostic spec filters, runtime (--with-*) registered — and spec-declared,
# element-scoped candidates are spliced into the chain by their position's
# _LazyGate the moment their element's start_element flows through it,
# un-spliced after its end_element.  No pre-scan, no DOM: the profile itself
# is the decision signal.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';
use lib dirname(__FILE__) . '/../local/lib/perl5';

require Amin::Machine::Dispatcher;
require Amin::Machine::MachineSpec;

my $DIS = 'Amin::Machine::Dispatcher';
my $NS  = 'http://projectamin.org/ns/2026/';

# ── Probe filter classes: log every seen event start/end by localname ──
BEGIN {
    $INC{'D48/Base.pm'}    = __FILE__;
    $INC{'D48/Agnostic.pm'} = __FILE__;
    $INC{'D48/Exec.pm'}     = __FILE__;
    $INC{'D48/Spawn.pm'}    = __FILE__;
    package D48::Base;
    use parent 'XML::SAX::Base';
    # XML::SAX::Base ships no constructor; without one the real Amin filters
    # (Class::Tiny) have ::new but these probes don't — and _build_chain's
    # require-guard (`require unless can('new')`) would then skip them.
    # Class::Tiny-style Handler accessor, exactly like every real Amin filter
    # (Amin::Elt & co.) has — the gate's splice/pop walks find children via it.
    sub Handler { my $s = shift; $s->{Handler} = shift if @_; $s->{Handler} }
    sub new { my ($c, %a) = @_; return bless { Handler => $a{Handler} // undef }, $c }
    our %LOG;
    sub start_element { my ($s, $e) = @_; push $LOG{ref $s}->@*, "start:" . ($e->{LocalName} // ''); $s->SUPER::start_element($e) }
    sub end_element   { my ($s, $e) = @_; push $LOG{ref $s}->@*, "end:"   . ($e->{LocalName} // ''); $s->SUPER::end_element($e) }
    sub characters    { my ($s, $d) = @_; push $LOG{ref $s}->@*, "chars:" . ($d->{Data} // ''); $s->SUPER::characters($d) }
    package D48::Agnostic; use parent -norequire, 'D48::Base';
    package D48::Exec;     use parent -norequire, 'D48::Base';
    package D48::Spawn;    use parent -norequire, 'D48::Base';
}

# Recorder — terminal handler that logs by class so we can assert what each
# element-scoped filter actually received.
BEGIN { $INC{'D48/Rec.pm'} = __FILE__;
    package D48::Rec;
    use parent 'XML::SAX::Base';
    # Same accessor contract as D48::Base (see above).
    sub Handler { my $s = shift; $s->{Handler} = shift if @_; $s->{Handler} }
    our %LOG;
    sub start_element { my ($s, $e) = @_; push $LOG{'D48::Rec'}->@*, 'rec|start|' . ($e->{LocalName} // ''); $s->SUPER::start_element($e) }
    sub end_element   { my ($s, $e) = @_; push $LOG{'D48::Rec'}->@*, 'rec|end|'   . ($e->{LocalName} // ''); $s->SUPER::end_element($e) }
}

my $SPEC = {
    allowed => { 'D48::Agnostic' => 1, 'D48::Exec' => 1, 'D48::Spawn' => 1 },
    filters => [
        { class => 'D48::Agnostic', meta => { position => 'middle', element => '',      namespace => $NS } },
        { class => 'D48::Exec',     meta => { position => 'middle', element => 'exec',  namespace => $NS } },
        { class => 'D48::Spawn',    meta => { position => 'middle', element => 'spawn', namespace => $NS } },
    ],
};

# ── 1. Base-graph composition ───────────────────────────────────────────
{
    my $writer = D48::Rec->new();
    my $chain = Amin::Machine::Dispatcher::_build_chain(
        $writer, undef, 'render', { map => 1, ui => 1, ai => 1 },
        $SPEC->{allowed}, $SPEC->{filters},
    );
    my (@klass, $node);
    $node = $chain;
    while ($node) {
        push @klass, ref $node;
        my $h = eval { $node->Handler } or last;
        $node = _next_of($node) // last;
    }
    sub _next_of { my ($n) = @_; my $h = eval { $n->Handler }; return $h }
    ok((grep { /_LazyGate/ } @klass), 'a per-position gate exists in the chain');
    ok((grep { $_ eq 'D48::Agnostic' } @klass), 'element-agnostic filter is statically chained');
    ok((!grep { defined && $_ eq 'D48::Exec' } @klass), 'element-scoped candidate NOT statically chained');
}

# ── 2. Drive SAX events through the chain; assert splice windows ────────
my $sax_src = qq{<?xml version="1.0"?><amin:profile xmlns:amin="$NS">
  <amin:exec name="hello"><amin:argv>/bin/echo</amin:argv><amin:argv>hi</amin:argv></amin:exec>
  <amin:spawn name="s1"><amin:argv>/bin/sleep</amin:argv><amin:argv>0</amin:argv></amin:spawn>
</amin:profile>};

{
    my $writer = D48::Rec->new();
    my $chain = Amin::Machine::Dispatcher::_build_chain(
        $writer, undef, 'render', { map => 1, ui => 1, ai => 1 },
        $SPEC->{allowed}, $SPEC->{filters},
    );
    my %orig_log = %D48::Base::LOG;
    for my $k (keys %$chain) {}    # noop pacify
    # Drive the source through the chain using the same generator class a
    # real dispatcher run uses.  XML::LibXML::SAX or XML::SAX::PurePerl both
    # emit namespace-aware events; pick whichever factory loads.
    my $parser = do {
        local $@;
        my $p = eval { XML::SAX::ParserFactory->parser(Handler => $chain) };
        $p // eval { require XML::SAX::PurePerl; XML::SAX::PurePerl->new(Handler => $chain) };
    };
    ok($parser, 'SAX driver constructed for event feed');
    eval { $parser->parse_string($sax_src) } or diag "parse failed: $@";
}

my ($elog, $slog, $rlog) = ($D48::Base::LOG{'D48::Exec'} // [], $D48::Base::LOG{'D48::Spawn'} // [], $D48::Rec::LOG{'D48::Rec'} // []);
my $e_start = grep { $_ eq 'start:exec' } @$elog;
my $e_argv  = grep { $_ eq 'start:argv' } @$elog;
my $e_bad   = grep { $_ eq 'start:spawn' } @$elog;
my $s_start = grep { $_ eq 'start:spawn' } @$slog;
my $s_bad   = grep { $_ eq 'start:exec'  } @$slog;
my $r_exec  = grep { $_ eq 'rec|start|exec' } @$rlog;
is($e_start, 1, 'Exec received start:exec (spliced in on hit)');
is($e_argv,  2, 'Exec received both argv children inside its window');
is($e_bad,   0, 'Exec NOT exposed to spawn events (never in graph for them)');
is($s_start, 1, 'Spawn received start:spawn');
is($s_bad,   0, 'Spawn NOT exposed to exec events');
is($r_exec,  1, 'recorder still saw exec pass through (gate is a splice, not a swallow)');

done_testing;
