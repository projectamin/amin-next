#!/usr/bin/env perl
# t/42-billing-cpu-accuracy.t — Task 15: Billing::CgroupV2 cpu_ms accuracy.
#
# TR-15.1: 1.2 s CPU-bound process → cpu_ms in [1190, 1210] ms.
#
# Direct filter test: fork a CPU-burn child, feed its pid to the Billing
# filter, let it run ~1.2 s, feed status, assert cpu_ms ∈ [1190, 1210].
# No ZCap tokens, no XML parsing, no Dispatcher.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

require Amin::Filter::Billing::CgroupV2;
require Amin::Test::StreamCapture;
require Amin::Log::Standard;
require Amin::Auth::ZCap;
require Time::HiRes;

my $NS = 'http://projectamin.org/ns/2026/';

sub el ($ln, %attrs) {
    my $a = {};
    while (my ($k, $v) = each %attrs) {
        $a->{"{}$k"} = {
            Name => $k, LocalName => $k, Prefix => 'amin',
            NamespaceURI => $NS, Value => "$v",
        };
    }
    +{ NamespaceURI => $NS, LocalName => $ln, Name => "amin:$ln",
       Prefix => 'amin', Attributes => $a };
}

sub attr ($el, $name) {
    my $a = $el->{Attributes} // {};
    for my $k (keys %$a) {
        next unless ref $a->{$k} eq 'HASH';
        return $a->{$k}{Value} if ($a->{$k}{LocalName} // '') eq $name;
    }
    return undef;
}

Amin::Auth::ZCap->_test_override_scope({ tenant_id => 't-test-001' });

# ── TR-42.1: 1.2 s CPU-bound child → cpu_ms ∈ [1190, 1210] ─────────────────
{
    my $child_pid = fork();
    if (!defined $child_pid) {
        skip_all("fork failed: $!");
    }
    if ($child_pid == 0) {
        my $end = Time::HiRes::time() + 1.2;
        1 while Time::HiRes::time() < $end;
        exit 0;
    }

    my $cap = Amin::Test::StreamCapture->new;
    my $log = Amin::Log::Standard->new(stderr => 0);
    my $b = Amin::Filter::Billing::CgroupV2->new(Handler => $cap, Log => $log, Mode => 'run');

    $b->start_element(el('result', kind => 'running'));
      $b->start_element(el('stream', channel => 'pid'));
        $b->characters({Data => "$child_pid"});
      $b->end_element(el('stream'));
    $b->end_element(el('result'));

    waitpid($child_pid, 0);

    $b->start_element(el('status', pid => $child_pid, duration => '1.200', exit_kind => 'ok', rc => 0));
    $b->end_element(el('status'));

    my @ev = $cap->captured->@*;
    my @billing = grep { $_->[0] eq 'start_element' && ($_->[1]{LocalName} // '') eq 'billing' } @ev;
    is(scalar(@billing), 1, 'TR-42.1: billing emitted for real CPU-bound child');

    my $cpu_ms = attr($billing[0][1], 'cpu_ms') + 0;
    diag "cpu_ms = $cpu_ms";
    cmp_ok($cpu_ms, '>=', 1190, 'TR-42.1: cpu_ms >= 1190 (1.2s CPU burn)');
    cmp_ok($cpu_ms, '<=', 1210, 'TR-42.1: cpu_ms <= 1210 (1.2s CPU burn)');
}

done_testing();
