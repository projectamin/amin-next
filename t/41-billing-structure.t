#!/usr/bin/env perl
# t/41-billing-structure.t — Task 15: Billing::CgroupV2 structural assertions.
#
# Direct filter test: instantiate Billing with a StreamCapture handler, feed
# synthetic SAX events, assert the emitted <billing> sibling structure.
# No ZCap token building, no XML parsing, no Dispatcher pipeline.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

require Amin::Filter::Billing::CgroupV2;
require Amin::Test::StreamCapture;
require Amin::Log::Standard;
require Amin::Auth::ZCap;

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

# ── TR-41.1: real spawn (running + pid) → <billing> emitted after </status> ─
{
    my $cap = Amin::Test::StreamCapture->new;
    my $log = Amin::Log::Standard->new(stderr => 0);
    my $b = Amin::Filter::Billing::CgroupV2->new(Handler => $cap, Log => $log, Mode => 'run');

    $b->start_element(el('result', kind => 'running'));
      $b->start_element(el('stream', channel => 'pid'));
        $b->characters({Data => "$$"});
      $b->end_element(el('stream'));
    $b->end_element(el('result'));

    $b->start_element(el('status', pid => $$, duration => '0.001', exit_kind => 'ok', rc => 0));
    $b->end_element(el('status'));

    my @ev = $cap->captured->@*;
    my @starts = grep { $_->[0] eq 'start_element' } @ev;
    my @billing = grep { ($_->[1]{LocalName} // '') eq 'billing' } @starts;

    is(scalar(@billing), 1, 'TR-41.1: exactly one <billing> element emitted');
    my $bill = $billing[0][1];
    is(attr($bill, 'pid'), "$$", 'TR-41.1: billing pid matches spawn pid');
    is(attr($bill, 'tenant_id'), 't-test-001', 'TR-41.1: billing tenant_id matches ZCap scope');
    like(attr($bill, 'cpu_ms'), qr/^\d+$/, 'TR-41.1: cpu_ms is numeric');
    like(attr($bill, 'rss_kb'), qr/^\d+$/, 'TR-41.1: rss_kb is numeric');
    like(attr($bill, 'egress_bytes'), qr/^\d+$/, 'TR-41.1: egress_bytes is numeric');
    like(attr($bill, 'disk_rw_bytes'), qr/^\d+$/, 'TR-41.1: disk_rw_bytes is numeric');

    my @ends = grep { $_->[0] eq 'end_element' } @ev;
    my $status_end_idx = (grep { ($ends[$_][1]{LocalName} // '') eq 'status' } 0..$#ends)[0];
    my $billing_start_idx = (grep { ($starts[$_][1]{LocalName} // '') eq 'billing' } 0..$#starts)[0];
    cmp_ok($billing_start_idx, '>', $status_end_idx,
        'TR-41.1: <billing> start occurs after </status> end (sibling, not child)');
}

# ── TR-41.2: original <status> attrs forwarded verbatim (additive-only) ────
{
    my $cap = Amin::Test::StreamCapture->new;
    my $b = Amin::Filter::Billing::CgroupV2->new(Handler => $cap, Log => Amin::Log::Standard->new(stderr => 0), Mode => 'run');

    $b->start_element(el('result', kind => 'running'));
      $b->start_element(el('stream', channel => 'pid'));
        $b->characters({Data => "$$"});
      $b->end_element(el('stream'));
    $b->end_element(el('result'));

    $b->start_element(el('status', pid => $$, duration => '1.234', exit_kind => 'signal', rc => -9, signal => 9));
    $b->end_element(el('status'));

    my @ev = $cap->captured->@*;
    my $status_start = (grep { $_->[0] eq 'start_element' && ($_->[1]{LocalName} // '') eq 'status' } @ev)[0];
    ok(defined $status_start, 'TR-41.2: status start forwarded');
    is(attr($status_start->[1], 'duration'), '1.234', 'TR-41.2: status duration unchanged');
    is(attr($status_start->[1], 'exit_kind'), 'signal', 'TR-41.2: status exit_kind unchanged');
    is(attr($status_start->[1], 'rc'), '-9', 'TR-41.2: status rc unchanged');
    is(attr($status_start->[1], 'signal'), '9', 'TR-41.2: status signal unchanged');
}

# ── TR-41.3: dryrun result (no pid stream) → no <billing> ──────────────────
{
    my $cap = Amin::Test::StreamCapture->new;
    my $b = Amin::Filter::Billing::CgroupV2->new(Handler => $cap, Log => Amin::Log::Standard->new(stderr => 0), Mode => 'run');

    $b->start_element(el('result', kind => 'dryrun'));
    $b->end_element(el('result'));
    $b->start_element(el('status', pid => $$, duration => '0.000', exit_kind => 'ok', rc => 0));
    $b->end_element(el('status'));

    my @starts = grep { $_->[0] eq 'start_element' && ($_->[1]{LocalName} // '') eq 'billing' } $cap->captured->@*;
    is(scalar(@starts), 0, 'TR-41.3: no <billing> for dryrun result (no pid stream)');
}

# ── TR-41.4: running result with no pid stream → no <billing> ──────────────
{
    my $cap = Amin::Test::StreamCapture->new;
    my $b = Amin::Filter::Billing::CgroupV2->new(Handler => $cap, Log => Amin::Log::Standard->new(stderr => 0), Mode => 'run');

    $b->start_element(el('result', kind => 'running'));
    $b->end_element(el('result'));
    $b->start_element(el('status', pid => 99999, duration => '0.000', exit_kind => 'ok', rc => 0));
    $b->end_element(el('status'));

    my @starts = grep { $_->[0] eq 'start_element' && ($_->[1]{LocalName} // '') eq 'billing' } $cap->captured->@*;
    is(scalar(@starts), 0, 'TR-41.4: no <billing> when no pid stream captured');
}

done_testing();
