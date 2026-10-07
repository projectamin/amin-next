#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Machine::Dispatcher;
use Amin::Handler::Writer;
use Amin::Log::Standard;

my $reg = \%Amin::Machine::Dispatcher::FILTERS;
for my $pos (qw(begin middle late)) {
    ok(exists $reg->{$pos} && ref $reg->{$pos} eq 'ARRAY',
       "registry position '$pos' populated as ARRAY");
}
ok(ref($reg->{permanent} // []) eq 'ARRAY', 'permanent position valid (empty is OK)');
ok(ref($reg->{end}       // []) eq 'ARRAY', 'end position valid       (empty is OK)');

my $late = [ map { $_->{class} } $reg->{late}->@* ];
like($late, array {
    item 'Amin::Filter::Map::Topology';
    item 'Amin::Filter::UI::SwiftUIView';
    end;
}, 'late position = Map::Topology + UI::SwiftUIView');

my $bare_chain = Amin::Machine::Dispatcher::_build_chain(
    Amin::Handler::Writer->new, Amin::Log::Standard->new(stderr=>0), 'render',
    { map => 0, ui => 0 });
isa_ok($bare_chain, ['Amin::Cond::OS'],
       'late=00 still composes Cond::OS; no Topology/SwiftUIView wrappers');

my $mid = [ map { $_->{class} } $reg->{middle}->@* ];
like($mid, array {
    item 'Amin::Command::Mkdir';
    item 'Amin::Command::Echo';
    item 'Amin::Command::Remove';
    end;
}, 'middle position registers our 3 command filters');

is($reg->{begin}[0]{class}, 'Amin::Cond::OS', 'begin position = Cond::OS');

my $chain = Amin::Machine::Dispatcher::_build_chain(
    Amin::Handler::Writer->new,
    Amin::Log::Standard->new(stderr => 0),
    'dryrun');
ok($chain, '_build_chain returns truthy head');
isa_ok($chain, ['Amin::Cond::OS'],
       'outermost wrapper is begin-position Cond::OS (filters applied inward last)');
can_ok($chain, qw(start_element end_element characters));
ok(exists $chain->{Handler}, 'chain head has Handler slot set (inner chain wired)');

my $d = Amin::Machine::Dispatcher->new(
    Handler => Amin::Handler::Writer->new,
    Log     => Amin::Log::Standard->new(stderr=>0),
    Mode    => 'render');
ok($d->{chain}, 'Dispatcher->new populates chain via constructor');

done_testing;
