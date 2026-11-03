package Amin::Filter::Crypto::RatchetSeal;

# sec:seal  (application plaintext)  →  sec:sealed  (wire form)
#
# The per-message *sending* half of the post-quantum Double Ratchet.  It owns
# the innermost (`end`) chain position, so the plaintext it seals has already
# passed every other filter — sealing is the last thing to happen before the
# bytes reach the writer/transport.
#
# Its output (`sec:sealed`) is exactly the wire element RatchetOpen consumes.
# Because Seal is innermost, its emission flows only downstream and can never
# re-enter a gate, so a chain carrying both halves does not seal-then-immediately-
# open its own message.
#
#   <sec:seal sec:session="state.file" sec:ad="room:1">hello</sec:seal>
#     ⇒ <sec:sealed sec:session="state.file" sec:ratchet="…64h…"
#                   sec:prev_count="0" sec:msg_index="7" sec:ad="room:1">…ct…</sec:sealed>
#
# Every failure is fail-closed: nothing is emitted, one line is logged.

use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Filter::Crypto::Base';

sub _capture_name ($self) { 'seal' }

sub _handle ($self, $name, $attrs, $data) {
    my $h = $self->Handler or return;

    my $state = $self->_session_file($attrs);
    unless (length $state) {
        $self->Log && $self->Log->error('[sec/seal] no session (sec:session attr or session_path)');
        return;
    }
    my $ad = $self->_ad($attrs);

    my @args = ('seal', '--state', $state);
    push @args, '--ad', $ad if length $ad;
    my ($rc, $out, $err) = $self->_rctool_run(\@args, $data // '');
    if ($rc != 0) {
        $self->Log && $self->Log->error(
            "[sec/seal] rctool rc=$rc" . (length $err ? " stderr=$err" : ''));
        return;
    }

    my $kv = $self->_tsv($out);
    my $ct = $kv->{ct} // '';
    unless (length $ct) {
        $self->Log && $self->Log->error('[sec/seal] rctool produced no ciphertext');
        return;
    }

    my $SEC = $self->_sec_ns;
    my $oa  = {};
    my $sess = $self->_find_attr($attrs, 'session');
    $self->_set_attr_ns($oa, $SEC, 'session',    $sess,     'sec') if defined $sess && length $sess;
    $self->_set_attr_ns($oa, $SEC, 'ratchet',    $kv->{dh} // '',  'sec');
    $self->_set_attr_ns($oa, $SEC, 'prev_count', $kv->{pn} // '0', 'sec');
    $self->_set_attr_ns($oa, $SEC, 'msg_index',  $kv->{n}  // '0', 'sec');
    $self->_set_attr_ns($oa, $SEC, 'ad',         $ad,       'sec') if length $ad;

    $h->start_element({
        NamespaceURI => $SEC, LocalName => 'sealed',
        Name => 'sec:sealed', Prefix => 'sec', Attributes => $oa,
    });
    $h->characters({ Data => $ct });
    $h->end_element({
        NamespaceURI => $SEC, LocalName => 'sealed',
        Name => 'sec:sealed', Prefix => 'sec',
    });
    return;
}

1;
