#!/usr/bin/env perl
# t/63-music.t — Amin::AI::Music: a profile-scoped AI filter that drives a
# provider submit → poll loop and emits ai:update events as it advances, then
# stores the finished audio as a bc:object ref.
#
#   AI::Provider::Registry  api id → adapter (openrouter / deepinfra / stub)
#   AI::Music       (middle) submit → poll → ai:update … → bc:object
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

package FakeProviderUA {
    use v5.38;
    use experimental 'signatures';
    sub new ($class, %o) { bless { %o }, $class }
    sub post ($self, $url, $opts = {}) {
        $self->{last} = { method => 'POST', url => $url, %$opts };
        return $self->{fail} if $self->{fail};
        return { success => 1, status => 200, reason => 'OK',
                 content => $self->{payload} // '' };
    }
    sub get ($self, $url, $opts = {}) {
        $self->{last} = { method => 'GET', url => $url, %$opts };
        return $self->{fail} if $self->{fail};
        return { success => 1, status => 200, reason => 'OK',
                 content => $self->{payload} // '' };
    }
}

require Amin::Machine::Dispatcher;
require Amin::Handler::Writer;
require Amin::Log::Standard;

my $AMIN_NS = 'http://projectamin.org/ns/2026/';
my $AI_NS   = 'http://projectamin.org/ns/ai/1';

sub build_zcap_token (%o) {
    my %o = (
        tiers          => [qw(shared metal-32c metal-16c metal-96c)],
        zones          => [qw(us-east-1 us-west-2 global shared)],
        netpols        => [ map "vpc-$_", 'a'..'z' ],
        max_redundancy => 255,
        vpc_quota      => 0xFFFFFFFF,
        memory_tier    => 5,
        tenant_id      => 't-test-permissive-00000000',
        ts             => 1735689600,
        @_,
    );
    require Amin::Test::ZCapSign;
    return Amin::Test::ZCapSign::make_zcap_token(%o);
}

my $ZC = build_zcap_token();

sub run_ai ($inner, %o) {
    my $mode = $o{mode} // 'render';
    my $xml = qq{<?xml version="1.0"?>}
        . qq{<amin:profile xmlns:amin="$AMIN_NS" xmlns:ai="$AI_NS">}
        . qq{<amin:zcap amin:token="$ZC"/>}
        . $inner
        . qq{</amin:profile>};
    return Amin::Machine::Dispatcher->run(
        source_xml => $xml,
        Handler    => Amin::Handler::Writer->new(indent => 0),
        Log        => Amin::Log::Standard->new(stderr => 0),
        mode       => $mode,
    );
}

# ── TR-MU.1: stub provider drives submit → poll → updates → bc:object ──
{
    my $out = run_ai(<<'TEN');
  <ai:provider id="stub" api="stub"/>
  <ai:model id="ace-step" provider="stub" upstream="acestep" kind="music"/>
  <ai:music ai:model="ace-step">
    <ai:style>lo-fi, warm tape hiss</ai:style>
    <ai:prompt>rain on a tin roof</ai:prompt>
  </ai:music>
TEN
    my @updates = ($out =~ /<ai:update\b/g);
    is(scalar @updates, 3, 'TR-MU.1: one ai:update per submit + poll step');
    like($out, qr/<ai:update[^>]*ai:progress="0"/,   'TR-MU.1: submit update progress=0');
    like($out, qr/<ai:update[^>]*ai:progress="50"/,  'TR-MU.1: first poll progress=50');
    like($out, qr/<ai:update[^>]*ai:progress="100"/, 'TR-MU.1: terminal poll progress=100');
    like($out, qr/<ai:update[^>]*ai:state="running"/, 'TR-MU.1: running state emitted');
    like($out, qr/<bc:object[^>]*bc:kind="audio"/, 'TR-MU.1: bc:object kind=audio emitted');
    like($out, qr/<bc:object[^>]*bc:hash="[0-9a-f]{64}"/, 'TR-MU.1: audio object carries a 64-hex hash');
    like($out, qr/<bc:object[^>]*bc:mime="audio\/stub"/, 'TR-MU.1: mime from the provider');
    like($out, qr/<bc:object[^>]*bc:model="ace-step"/, 'TR-MU.1: artifact names the model');
    unlike($out, qr/<ai:result[^>]*ai:kind="error"/, 'TR-MU.1: no error result on success');
}

# ── TR-MU.2: prod mode drops Tier-0 update events, keeps the bc:object ──
{
    my $out = run_ai(<<'TEN', mode => 'prod');
  <ai:provider id="stub" api="stub"/>
  <ai:model id="ace-step" provider="stub" upstream="acestep" kind="music"/>
  <ai:music ai:model="ace-step">
    <ai:prompt>rain on a tin roof</ai:prompt>
  </ai:music>
TEN
    unlike($out, qr/<ai:update/, 'TR-MU.2: Tier-0 updates dropped in prod');
    like($out, qr/<bc:object[^>]*bc:kind="audio"/, 'TR-MU.2: audio ref survives prod');
}

# ── TR-MU.3: unapproved model → rc=-6145 denial ─────────────────────────
{
    my $out = run_ai(<<'TEN');
  <ai:music ai:model="evil-music">
    <ai:prompt>do bad things</ai:prompt>
  </ai:music>
TEN
    like($out, qr/<ai:result[^>]*ai:kind="error"/, 'TR-MU.3: unapproved model → error');
    like($out, qr/ai:rc="-6145"/, 'TR-MU.3: rc=-6145 (AI_MODEL_DENIED)');
    like($out, qr/ai:exit_kind="ai_model_denied"/, 'TR-MU.3: exit_kind=ai_model_denied');
    unlike($out, qr/<bc:object[^>]*bc:kind="audio"/, 'TR-MU.3: no artifact for a denied model');
}

# ── TR-MU.4: provider hop failure → rc=-6147, key not leaked ────────────
{
    require Amin::AI::Provider::Base;
    my $ua = FakeProviderUA->new(fail => {
        success => 0, status => 401, reason => 'Unauthorized',
        content => '{"error":{"message":"bad key"}}',
    });
    local $Amin::AI::Provider::Base::UA = $ua;
    my $out = run_ai(<<'TEN');
  <ai:provider id="deepinfra" api="deepinfra" base="http://127.0.0.1:9/v1" key="sk-test-not-for-output"/>
  <ai:model id="ace-step" provider="deepinfra" upstream="acestep-v15-xl-sft" kind="music"/>
  <ai:music ai:model="ace-step">
    <ai:prompt>rain on a tin roof</ai:prompt>
  </ai:music>
TEN
    like($out, qr/<ai:result[^>]*ai:kind="error"/, 'TR-MU.4: provider failure → error');
    like($out, qr/ai:rc="-6147"/, 'TR-MU.4: rc=-6147 (AI_PROVIDER_ERROR)');
    like($out, qr/ai:exit_kind="ai_provider_error"/, 'TR-MU.4: exit_kind=ai_provider_error');
    unlike($out, qr/ai:msg="[^"]*sk-test-not-for-output/, 'TR-MU.4: key not in the error msg');
    unlike($out, qr/<bc:object[^>]*bc:kind="audio"/, 'TR-MU.4: no artifact after failure');
    like($ua->{last}{url}, qr{/v1/inference/acestep-v15-xl-sft$},
        'TR-MU.4: deepinfra POST v1/inference/<model>');
}

# ── TR-MU.5: a profile with no ai:music element is untouched ────────────
{
    my $out = run_ai(<<'TEN');
  <ai:request ai:model="amin-chat-7b">
    <ai:prompt>hello</ai:prompt>
  </ai:request>
TEN
    unlike($out, qr/<ai:update/, 'TR-MU.5: no music filter work without ai:music');
    unlike($out, qr/<bc:object[^>]*bc:kind="audio"/, 'TR-MU.5: no audio object');
    like($out, qr/\[stub:amin-chat-7b\]/, 'TR-MU.5: unrelated chat path unchanged');
}

done_testing();
