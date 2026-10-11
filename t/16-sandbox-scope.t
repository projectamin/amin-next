#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Sandbox;
use Amin::Machine::Dispatcher;
use Amin::Handler::Writer;
use Amin::Log::Standard;
use Amin qw(NS);

# ── TR-1.2a: Empty process stack before use ──
is(Amin::Sandbox->_scope_count_for_tests, 0, 'scope stack starts at 0');
ok(!defined Amin::Sandbox->current_scope_attrs, 'current_scope_attrs undef when no scope');

# ── TR-1.2b: build chain, fire synthetic <sandbox open> + <spawn> + close ──
my $writer = Amin::Handler::Writer->new;
my $log = Amin::Log::Standard->new(stderr => 0);
my $chain = Amin::Machine::Dispatcher::_build_chain(
    $writer, $log, 'render', { map => 0, ui => 0 });
ok($chain, '_build_chain ok');

# Fire synthetic events by walking through SAX API
# Using direct Amin::Sandbox instance for testing scope lifecycle
my $sb = Amin::Sandbox->new(
    Handler => Amin::Handler::Writer->new,
    Log     => $log,
    Mode    => 'render',
);

my $NS = NS();
my $sandbox_open = {
    NamespaceURI => $NS,
    LocalName    => 'sandbox',
    Name         => "{$NS}sandbox",
    Attributes   => {
        "{$NS}cpu_max" => {
            NamespaceURI => $NS, LocalName => 'cpu_max',
            Name => "{$NS}cpu_max", Value => '100000,100000',
        },
        "{$NS}landlock_ro" => {
            NamespaceURI => $NS, LocalName => 'landlock_ro',
            Name => "{$NS}landlock_ro", Value => '/usr:/lib64',
        },
    },
};

# start sandbox
$sb->start_element($sandbox_open);
is(Amin::Sandbox->_scope_count_for_tests, 1, 'after sandbox start: stack count = 1');
my $attrs = Amin::Sandbox->current_scope_attrs;
ok(ref($attrs) eq 'HASH' && keys %$attrs >= 2, 'current_scope_attrs is HASH with attrs');
is($attrs->{cpu_max}, '100000,100000', 'cpu_max attr captured correctly');
is($attrs->{landlock_ro}, '/usr:/lib64', 'landlock_ro attr captured correctly');

# synthetic spawn sibling inside scope
my $spawn_open = {
    NamespaceURI => $NS, LocalName => 'spawn',
    Name => "{$NS}spawn", Attributes => {},
};
$sb->start_element($spawn_open);
$attrs = Amin::Sandbox->current_scope_attrs;
ok(defined $attrs, 'scope still active when inside sibling spawn');
$sb->end_element({ %$spawn_open });
is(Amin::Sandbox->_scope_count_for_tests, 1, 'spawn close did NOT affect sandbox count');

# end sandbox
$sb->end_element({ NamespaceURI => $NS, LocalName => 'sandbox', Name => "{$NS}sandbox" });
is(Amin::Sandbox->_scope_count_for_tests, 0, 'after </sandbox>: stack back to 0');
ok(!defined Amin::Sandbox->current_scope_attrs, 'current_scope_attrs undef after scope end');

# ── TR-1.2d: multiple sequential sandbox scopes ──
my $s1 = { NamespaceURI => $NS, LocalName => 'sandbox', Name => "{$NS}sandbox",
    Attributes => {
        "{$NS}memory_max" => { NamespaceURI => $NS, LocalName => 'memory_max',
            Name => "{$NS}memory_max", Value => '256M' },
    }};
my $s2 = { NamespaceURI => $NS, LocalName => 'sandbox', Name => "{$NS}sandbox",
    Attributes => {
        "{$NS}pids_max" => { NamespaceURI => $NS, LocalName => 'pids_max',
            Name => "{$NS}pids_max", Value => '64' },
    }};
$sb->start_element($s1);
is(Amin::Sandbox->_scope_count_for_tests, 1, 's1 open: count=1');
is(Amin::Sandbox->current_scope_attrs->{memory_max}, '256M', 's1 attrs = 256M memory_max');
$sb->end_element({ NamespaceURI => $NS, LocalName => 'sandbox', Name => "{$NS}sandbox" });
is(Amin::Sandbox->_scope_count_for_tests, 0, 's1 close: count=0');

$sb->start_element($s2);
is(Amin::Sandbox->_scope_count_for_tests, 1, 's2 open: count=1');
is(Amin::Sandbox->current_scope_attrs->{pids_max}, '64', 's2 attrs = 64 pids_max');
# stash_for_spawn: returns current scope regardless of spawn_id
is(Amin::Sandbox->stash_for_spawn('anything')->{pids_max}, '64',
    'stash_for_spawn() package method returns active attrs for Exec/Spawn use');
$sb->end_element({ NamespaceURI => $NS, LocalName => 'sandbox', Name => "{$NS}sandbox" });
is(Amin::Sandbox->_scope_count_for_tests, 0, 's2 close: count=0 (sequential balanced)');

done_testing;
