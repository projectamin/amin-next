package Amin::Filter::Crypto::Prekey;

# PQXDH handshake establishment — the `sec:` pair that turns published prekeys
# into a live Double Ratchet session.  It owns two sec: elements and picks the
# role from which one arrives:
#
#   <sec:bundle sec:session="alice.state">…bundle TSV…</sec:bundle>
#       initiator: verify a peer's published prekeys, run PQXDH, create the
#       session with `rctool init`, and emit the initial message:
#         ⇒ <sec:prekey sec:identity_dh="…" sec:ephemeral="…"
#                        sec:prekey_id="3" sec:used_one_time_prekey="1"
#                        sec:session="alice.state">…pq_ciphertext…</sec:prekey>
#
#   <sec:prekey sec:session="bob.state" sec:identity_dh="…" sec:ephemeral="…"
#               sec:prekey_id="3" sec:used_one_time_prekey="1">…pq_ciphertext…</sec:prekey>
#       responder: run PQXDH against the local private prekeys, create the
#       session with `rctool respond`, and announce it:
#         ⇒ <sec:session sec:session="bob.state"/>
#
# The initiator's private identity DH comes from `id_dh_path`; the responder's
# private prekey set from `prekeys_path`.  Both are filter configuration (host
# secrets never travel in the profile).  Every failure is fail-closed.

use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Filter::Crypto::Base';
use Class::Tiny qw(prekeys_path id_dh_path);

sub _capture_names ($self) { qw(bundle prekey) }

sub _handle ($self, $name, $attrs, $data) {
    return $name eq 'bundle'
        ? $self->_initiator($attrs, $data)
        : $self->_responder($attrs, $data);
}

# <sec:bundle> → session + <sec:prekey>
sub _initiator ($self, $attrs, $data) {
    my $h = $self->Handler or return;

    my $state = $self->_session_file($attrs);
    unless (length $state) {
        $self->Log && $self->Log->error('[sec/prekey] init: no session (sec:session attr or session_path)');
        return;
    }
    my $id_dh = $self->id_dh_path // '';
    unless (length $id_dh) {
        $self->Log && $self->Log->error('[sec/prekey] init: no id_dh_path configured');
        return;
    }
    my $bundle = $self->_trim($data);
    unless (length $bundle) {
        $self->Log && $self->Log->error('[sec/prekey] init: empty prekey bundle');
        return;
    }

    my ($rc, $out, $err) = $self->_rctool_run(
        ['init', '--bundle', '-', '--id-dh', $id_dh, '--state', $state], $bundle);
    if ($rc != 0) {
        $self->Log && $self->Log->error(
            "[sec/prekey] init rctool rc=$rc" . (length $err ? " stderr=$err" : ''));
        return;
    }

    my $kv  = $self->_tsv($out);
    my $SEC = $self->_sec_ns;
    my $oa  = {};
    my $sess = $self->_find_attr($attrs, 'session');
    $self->_set_attr_ns($oa, $SEC, 'session', $sess, 'sec') if defined $sess && length $sess;
    for my $k (qw(identity_dh ephemeral prekey_id used_one_time_prekey)) {
        $self->_set_attr_ns($oa, $SEC, $k, $kv->{$k} // '', 'sec');
    }

    $h->start_element({
        NamespaceURI => $SEC, LocalName => 'prekey',
        Name => 'sec:prekey', Prefix => 'sec', Attributes => $oa,
    });
    $h->characters({ Data => $kv->{pq_ciphertext} // '' });
    $h->end_element({
        NamespaceURI => $SEC, LocalName => 'prekey',
        Name => 'sec:prekey', Prefix => 'sec',
    });
    return;
}

# <sec:prekey> → <sec:session>
sub _responder ($self, $attrs, $data) {
    my $h = $self->Handler or return;

    my $state = $self->_session_file($attrs);
    unless (length $state) {
        $self->Log && $self->Log->error('[sec/prekey] respond: no session (sec:session attr or session_path)');
        return;
    }
    my $prekeys = $self->prekeys_path // '';
    unless (length $prekeys) {
        $self->Log && $self->Log->error('[sec/prekey] respond: no prekeys_path configured');
        return;
    }

    # Rebuild rctool's initial-message TSV from the element (small fields as
    # attributes, the ML-KEM ciphertext as the element text).
    my @rows;
    for my $k (qw(identity_dh ephemeral prekey_id used_one_time_prekey)) {
        my $v = $self->_find_attr($attrs, $k);
        return $self->Log->error("[sec/prekey] respond: missing sec:$k")
            if !defined $v || !length $v;
        push @rows, "$k\t$v";
    }
    push @rows, "pq_ciphertext\t" . $self->_trim($data);
    my $msg = join("\n", @rows) . "\n";

    my ($rc, $out, $err) = $self->_rctool_run(
        ['respond', '--msg', '-', '--prekeys', $prekeys, '--state', $state], $msg);
    if ($rc != 0) {
        $self->Log && $self->Log->error(
            "[sec/prekey] respond rctool rc=$rc" . (length $err ? " stderr=$err" : ''));
        return;
    }

    my $SEC = $self->_sec_ns;
    my $oa  = {};
    my $sess = $self->_find_attr($attrs, 'session');
    $self->_set_attr_ns($oa, $SEC, 'session', $sess, 'sec') if defined $sess && length $sess;

    $h->start_element({
        NamespaceURI => $SEC, LocalName => 'session',
        Name => 'sec:session', Prefix => 'sec', Attributes => $oa,
    });
    $h->end_element({
        NamespaceURI => $SEC, LocalName => 'session',
        Name => 'sec:session', Prefix => 'sec',
    });
    return;
}

1;
