package Amin::AI::Provider::Stub;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI::Provider::Base';

# ═══════════════════════════════════════════════════════════════════════════
# Deterministic, offline.  Emits a fake artifact across two poll steps so
# the submit → poll → emit-update path can be exercised with no network and
# no keys.  Never selected unless the profile asks for api="stub".
# ═══════════════════════════════════════════════════════════════════════════

sub submit ($self, $req) {
    return { state => 'running', handle => 'stub-1', progress => 0,
             model => $req->{model} // '' };
}

sub has_hop   ($self) { 1 }
sub poll_delay ($self) { 0 }

sub poll ($self, $job) {
    my $p = ($job->{progress} // 0) + 50;
    return { %$job, progress => $p } if $p < 100;
    my $bytes = "STUBAUDIO:" . ($job->{model} // '') . ':' . ('x' x 64);
    return { %$job, state => 'done', progress => 100, mime => 'audio/stub', audio => $bytes };
}

1;
