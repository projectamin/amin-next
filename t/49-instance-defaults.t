#!/usr/bin/env perl
# §4.9 landmine regression: Class::Tiny assigns non-CODE defaults BY
# REFERENCE on first accessor read, so one arrayref is shared by every
# instance of a class.  This test pins two things:
#   1. the declared default is CODE (catches latent/dead defaults too, even
#      where the class reads by direct hash access and never materializes),
#   2. two fresh instances never share a reference-valued attribute,
#      swept over every filter class in the stock machine spec,
#   3. the original repro: Amin::Handler::BSAX — instance 2 must not start
#      with instance 1's unclosed nesting.
# (This fails on Amin::Handler::BSAX, SwiftUIView, Topology, Bitcache, Elt
#  and Generator::BSAX before the fix — see docs/axa-plan.md §4.9/M1.)
use v5.38; use warnings; use utf8;
use Test2::V0;
use Scalar::Util qw(refaddr);
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Machine::MachineSpec;

my $spec = Amin::Machine::MachineSpec->new->spec;

my @classes = (
    (map { $_->{class} } $spec->{filters}->@*),
    # classes outside the spec that also hold ref-valued defaults
    qw(
        Amin::Handler::Writer
        Amin::Handler::BSAX
        Amin::Generator::BSAX
        Amin::Elt
        Amin::Filter::UI::SwiftUIView
        Amin::Filter::Map::Topology
        Amin::Filter::Storage::Bitcache
        Amin::Test::RecordingHandler
        Amin::Test::StreamCapture
        Amin::Test::Dispatch::TraceEnd
        Amin::Test::Dispatch::TraceLate
        Amin::Test::Dispatch::CountPerm
        Amin::Test::Dispatch::DropBegin
        Amin::Test::ElementCounter
        Amin::Test::Handler
    ),
);

my %seen;
my ($swept, $ref_defaults) = (0, 0);

for my $c (grep { !$seen{$_}++ } @classes) {
    (my $file = "$c.pm") =~ s{::}{/}g;
    eval { require $file; 1 } or next;

    # gate on the API itself, not on an inheritance shape Class::Tiny does
    # not actually provide: non-Class::Tiny classes return no defaults hash
    my $defaults = eval { Class::Tiny->get_all_attribute_defaults_for($c) };
    next unless $defaults && ref $defaults eq 'HASH' && keys %$defaults;

    # 1. declared ref defaults must be CODE — one fresh ref per instance
    for my $name (sort keys %$defaults) {
        my $d = $defaults->{$name};
        next unless ref $d;
        $ref_defaults++;
        is(ref $d, 'CODE', "$c\::$name declared ref default is CODE (not a " . ref($d) . ")");
    }

    # 2. behavioral sweep: two instances must never share a ref attribute
    my ($i1, $i2) = (
        eval { $c->new(Handler => undef, Log => undef, Mode => 'render') },
        eval { $c->new(Handler => undef, Log => undef, Mode => 'render') },
    );
    next unless $i1 && $i2;
    $swept++;
    for my $name (sort keys %$defaults) {
        my $v1 = eval { $i1->$name };
        next unless ref $v1;
        my $v2 = eval { $i2->$name };
        ok(ref $v2, "$c\::$name second instance also materializes a ref")
            or next;
        isnt(refaddr($v2), refaddr($v1), "$c\::$name instances do not share the ref");
    }
}

cmp_ok($swept, '>=', 30, 'sweep instantiated the spec (not an empty pass)');
cmp_ok($ref_defaults, '>=', 10, 'sweep saw reference-valued defaults (test is not vacuous)');
ok(grep { $_ eq 'Amin::Handler::BSAX' } keys %seen, 'BSAX covered by the sweep');

# 3. the original repro, end to end through the accessor
my $b1 = Amin::Handler::BSAX->new(Handler => undef);
my $b2 = Amin::Handler::BSAX->new(Handler => undef);
my $el = { LocalName => 'stage', NamespaceURI => 'http://projectamin.org/ns/2026/',
           Name => 'amin:stage', Prefix => 'amin', Attributes => {} };
$b1->start_element($el) for 1 .. 3;
is(scalar $b1->stack->@*, 3, 'first instance holds its own nesting');
is(scalar $b2->stack->@*, 0, 'second instance starts clean — no leftover nesting');
isnt(refaddr($b1->stack), refaddr($b2->stack), 'BSAX stacks are distinct refs');

done_testing;
