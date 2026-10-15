#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Cond::OS;
use Amin qw(NS);
require Amin::Test::StreamCapture;

# Host-OS resolution mirrors Amin::Cond::OS::_resolve_os (drop 'gnu', map
# $^O value → branch tag). AMIN_OSTYPE override is cleared so the suite
# exercises the real host OS, not an environment-dependent one.
delete $ENV{AMIN_OSTYPE};
my %VALUE2TAG = (linux => 'linux', freebsd => 'freebsd', openbsd => 'openbsd',
                 darwin => 'darwin', ios => 'ios',  solaris => 'illumos',
                 netbsd => 'netbsd', android => 'android');
my $HOST_RAW = do { my $o = $^O; $o =~ s/gnu//; $o };
my $HOST = $VALUE2TAG{$HOST_RAW} // 'posix';

my @BRANCHES = map {
    [ $_, ($_ eq $HOST ? 1 : 0), "always " . ($_ eq $HOST ? "pass" : "drop") . " $_ on \$^O=$HOST" ]
} qw(linux freebsd openbsd darwin illumos netbsd);
push @BRANCHES, ['posix', 1, 'posix passes on all hosts'];

sub run_case ($tag, $inner_handler) {
    my $c = Amin::Cond::OS->new(
        Handler => $inner_handler,
        Log     => do { require Amin::Log::Standard;
                        Amin::Log::Standard->new(stderr => 0) });
    $c->start_element({ NamespaceURI => NS(), LocalName => $tag,
                        Name => "amin:$tag", Prefix => 'amin',
                        Attributes => {} });
    $c->start_element({ NamespaceURI => NS(), LocalName => 'command',
                        Name => 'amin:command', Prefix => 'amin',
                        Attributes => { '{}name' => { LocalName => 'name',
                            Value => 'echo', NamespaceURI => '' } } });
    $c->characters({ Data => 'inner text' });
    $c->end_element({ NamespaceURI => NS(), LocalName => 'command',
                      Name => 'amin:command', Prefix => 'amin' });
    $c->end_element({ NamespaceURI => NS(), LocalName => $tag,
                      Name => "amin:$tag", Prefix => 'amin' });
}

for my $case (@BRANCHES) {
    my ($tag, $pass, $desc) = @$case;
    my $cap = Amin::Test::StreamCapture->new;
    run_case($tag, $cap);

    my $events = scalar $cap->captured->@*;
    if ($pass) {
        cmp_ok($events, '>=', 4, "$desc: events forwarded (start+chars+2end)");
        my @ce = grep { $_->[0] eq 'characters' } $cap->captured->@*;
        is(scalar @ce, 1, "$desc: characters forwarded exactly once");
        is($ce[0][1]{Data}, 'inner text', "$desc: characters payload untouched");
    } else {
        is($events, 0, "$desc: events dropped completely");
    }
}

my $cap = Amin::Test::StreamCapture->new;
my $c = Amin::Cond::OS->new(Handler => $cap,
    Log => Amin::Log::Standard->new(stderr=>0));

# Outer branch is the host OS tag; inner branch is guaranteed non-host, so
# the predicate (outer passes, nested inner is dropped) is host-independent.
my $outer = $HOST;
my @inner_candidates = grep { $_ ne $HOST } qw(linux freebsd openbsd darwin illumos netbsd);
my $inner = $inner_candidates[0] // 'freebsd';

$c->start_element({ NamespaceURI => NS(), LocalName => $outer, Prefix=>'amin',
                    Name => "amin:$outer", Attributes => {} });
  $c->start_element({ %{e('x')}, LocalName => 'outer_pass' });
  $c->end_element  ({ %{e('x')}, LocalName => 'outer_pass' });
  $c->start_element({ NamespaceURI => NS(), LocalName => $inner,
                      Prefix=>'amin', Name => "amin:$inner", Attributes => {} });
    $c->start_element({ %{e('x')}, LocalName => 'inner_drop' });
    $c->end_element  ({ %{e('x')}, LocalName => 'inner_drop' });
  $c->end_element  ({ NamespaceURI => NS(), LocalName => $inner,
                      Prefix=>'amin', Name => "amin:$inner" });
$c->end_element  ({ NamespaceURI => NS(), LocalName => $outer,
                    Prefix=>'amin', Name => "amin:$outer" });

sub e { +{ Name => "amin:$_[0]", Prefix => 'amin', NamespaceURI => NS(),
           Attributes => {} } }

my @forwarded_names = map { $_->[1]{LocalName} // () } grep { $_->[0] eq 'start_element' } $cap->captured->@*;
is(\@forwarded_names, [$outer, 'outer_pass'],
   "nested bypass: $outer tag + outer_pass pass; nested $inner + inner_drop dropped");

done_testing;
