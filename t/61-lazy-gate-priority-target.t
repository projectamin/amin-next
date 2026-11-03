#!/usr/bin/env perl
# t/61-lazy-gate-priority-target.t — _LazyGate candidate selection.
#
# Two facts the gate must resolve before an element-scoped candidate can be
# spliced (axa-plan §4.3):
#   • priority — candidates are tried in order and the first match wins, so
#     order IS priority (higher first).  Two candidates that bind the same
#     element + namespace + verb + target at the same priority cannot decide a
#     match, so that is a hard error, not a silent last-one-wins.
#   • target — a candidate may be bound to one render target (ios/android/…);
#     it only participates when the gate serves that target.  The gate resolves
#     its target at stream time: explicit `target` (the --os selection) wins,
#     else $ENV{AMIN_OSTYPE}.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';
use lib dirname(__FILE__) . '/../local/lib/perl5';

require Amin::Machine::Dispatcher;

my $GATE = 'Amin::Machine::Dispatcher::_LazyGate';
my $NS   = 'http://projectamin.org/ns/2026/';

BEGIN {
    for my $c (qw(Base Lo Hi Ios And Dup1 Dup2 Rec)) { $INC{"D61/$c.pm"} = __FILE__ }
    package D61::Base;
    use parent 'XML::SAX::Base';
    sub Handler { my $s = shift; $s->{Handler} = shift if @_; $s->{Handler} }
    sub new { my ($c, %a) = @_; bless { Handler => $a{Handler} // undef }, $c }
    our %LOG;
    sub start_element { my ($s, $e) = @_; push $LOG{ref $s}->@*, 'start:' . ($e->{LocalName} // ''); $s->SUPER::start_element($e) }
    sub end_element   { my ($s, $e) = @_; push $LOG{ref $s}->@*, 'end:'   . ($e->{LocalName} // ''); $s->SUPER::end_element($e) }
    package D61::Lo;   use parent -norequire, 'D61::Base';
    package D61::Hi;   use parent -norequire, 'D61::Base';
    package D61::Ios;  use parent -norequire, 'D61::Base';
    package D61::And;  use parent -norequire, 'D61::Base';
    package D61::Dup1; use parent -norequire, 'D61::Base';
    package D61::Dup2; use parent -norequire, 'D61::Base';
    package D61::Rec;
    use parent 'XML::SAX::Base';
    sub Handler { my $s = shift; $s->{Handler} = shift if @_; $s->{Handler} }
    our %LOG;
    sub start_element { my ($s, $e) = @_; push $LOG{'D61::Rec'}->@*, 'rec|start|' . ($e->{LocalName} // ''); $s->SUPER::start_element($e) }
}

sub _feed ($chain, $src) {
    my $parser = do {
        local $@;
        eval { XML::SAX::ParserFactory->parser(Handler => $chain) }
            // eval { require XML::SAX::PurePerl; XML::SAX::PurePerl->new(Handler => $chain) };
    };
    $parser->parse_string($src);
    return;
}

my $f = sub { my ($class, %m) = @_; { class => $class, meta => \%m } };

# ── 1. Priority: the first-listed match wins, so higher priority goes first ──
{
    %D61::Base::LOG = ();
    my $spec = { filters => [
        $f->('D61::Lo', position => 'middle', element => 'x', namespace => $NS, priority => 1),
        $f->('D61::Hi', position => 'middle', element => 'x', namespace => $NS, priority => 10),
    ] };
    my $chain = Amin::Machine::Dispatcher::_build_chain(
        D61::Rec->new, undef, 'render', {}, undef, $spec->{filters});
    _feed($chain, qq{<?xml version="1.0"?><amin:profile xmlns:amin="$NS"><amin:x/></amin:profile>});
    my $hi = grep { $_ eq 'start:x' } ($D61::Base::LOG{'D61::Hi'} // [])->@*;
    my $lo = grep { $_ eq 'start:x' } ($D61::Base::LOG{'D61::Lo'} // [])->@*;
    is($hi, 1, 'higher-priority candidate is the one spliced in');
    is($lo, 0, 'lower-priority candidate is never spliced (first match wins)');
}

# ── 2. Target scoping: only the candidate bound to the served target participates ──
for my $case ([ ios => 'D61::Ios', 'D61::And' ], [ android => 'D61::And', 'D61::Ios' ]) {
    my ($os, $want, $skip) = @$case;
    %D61::Base::LOG = ();
    my $spec = { filters => [
        $f->('D61::Ios', position => 'middle', element => 'y', namespace => $NS, target => 'ios'),
        $f->('D61::And', position => 'middle', element => 'y', namespace => $NS, target => 'android'),
    ] };
    my $chain = Amin::Machine::Dispatcher::_build_chain(
        D61::Rec->new, undef, 'render', {}, undef, $spec->{filters}, undef, $os);
    _feed($chain, qq{<?xml version="1.0"?><amin:profile xmlns:amin="$NS"><amin:y/></amin:profile>});
    my $got  = grep { $_ eq 'start:y' } ($D61::Base::LOG{$want} // [])->@*;
    my $nope = grep { $_ eq 'start:y' } ($D61::Base::LOG{$skip} // [])->@*;
    is($got,  1, "--os=$os: the $want candidate is spliced in");
    is($nope, 0, "--os=$os: the $skip candidate is not");
}

# ── 3. Target resolution order: explicit target beats the environment ──
{
    local $ENV{AMIN_OSTYPE} = 'ios';
    my $env = $GATE->new(Handler => D61::Rec->new, candidates => []);
    is($env->effective_target, 'ios', 'no explicit target → $ENV{AMIN_OSTYPE}');
    my $exp = $GATE->new(Handler => D61::Rec->new, candidates => [], target => 'android');
    is($exp->effective_target, 'android', 'explicit target overrides the environment');
}
{
    # %ENV is tied; local on a tied element is fiddly, so save/restore by hand.
    my $saved = delete $ENV{AMIN_OSTYPE};
    my $none = $GATE->new(Handler => D61::Rec->new, candidates => []);
    is($none->effective_target, '', 'no target anywhere → platform-neutral');
    $ENV{AMIN_OSTYPE} = $saved if defined $saved;
}

# ── 4. Equal priority on the same binding is a hard error, not a coin toss ──
{
    my @cands = (
        $f->('D61::Dup1', position => 'middle', element => 'dup', namespace => $NS, priority => 5),
        $f->('D61::Dup2', position => 'middle', element => 'dup', namespace => $NS, priority => 5),
    );
    like(dies { $GATE->new(Handler => D61::Rec->new, candidates => \@cands) },
        qr/ambiguous element filters bound to <dup>/,
        'same element/namespace/verb/target at equal priority dies');
}

# ── 5. Differing target disambiguates the same binding (no false conflict) ──
{
    my @cands = (
        $f->('D61::Ios', position => 'middle', element => 'z', namespace => $NS, target => 'ios'),
        $f->('D61::And', position => 'middle', element => 'z', namespace => $NS, target => 'android'),
    );
    ok(lives { $GATE->new(Handler => D61::Rec->new, candidates => \@cands) },
       'same element/verb at equal priority but distinct targets is fine');
}

done_testing;
