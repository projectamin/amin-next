#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Cond::OS;
use Amin qw(NS);
require Amin::Test::StreamCapture;

my @BRANCHES = (
    ['linux',       1,  'always pass linux  on $^O=linux'],
    ['freebsd',     0,  'always drop freebsd on linux host'],
    ['openbsd',     0,  'drop openbsd'],
    ['darwin',      0,  'drop darwin (macOS)'],
    ['illumos',     0,  'drop illumos/solaris'],
    ['netbsd',      0,  'drop netbsd'],
    ['posix',       1,  'posix passes on all hosts'],
);

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
$c->start_element({ NamespaceURI => NS(), LocalName => 'linux', Prefix=>'amin',
                    Name => 'amin:linux', Attributes => {} });
  $c->start_element({ %{e('x')}, LocalName => 'outer_pass' });
  $c->end_element  ({ %{e('x')}, LocalName => 'outer_pass' });
  $c->start_element({ NamespaceURI => NS(), LocalName => 'freebsd',
                      Prefix=>'amin', Name => 'amin:freebsd', Attributes => {} });
    $c->start_element({ %{e('x')}, LocalName => 'inner_drop' });
    $c->end_element  ({ %{e('x')}, LocalName => 'inner_drop' });
  $c->end_element  ({ NamespaceURI => NS(), LocalName => 'freebsd',
                      Prefix=>'amin', Name => 'amin:freebsd' });
$c->end_element  ({ NamespaceURI => NS(), LocalName => 'linux',
                    Prefix=>'amin', Name => 'amin:linux' });

sub e { +{ Name => "amin:$_[0]", Prefix => 'amin', NamespaceURI => NS(),
           Attributes => {} } }

my @forwarded_names = map { $_->[1]{LocalName} // () } grep { $_->[0] eq 'start_element' } $cap->captured->@*;
is(\@forwarded_names, ['linux', 'outer_pass'],
   'nested bypass: linux tag + outer_pass pass; nested freebsd + inner_drop dropped');

done_testing;
