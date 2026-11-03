package Amin::Filter::Crypto::RatchetOpen;

# sec:sealed  (wire form)  →  recovered plaintext as <amin:stream channel="sec-open">
#
# The per-message *receiving* half of the post-quantum Double Ratchet.  It is
# an element-scoped `middle` candidate: dormant until a <sec:sealed> element
# appears, then spliced in for that element and un-spliced after its close —
# the profile itself is the switch, no pre-scan.
#
# It sits *outside* RatchetSeal (`end`), so the sealed element Seal emits flows
# only downstream and is never re-opened here.
#
#   <sec:sealed sec:session="state.file" sec:ratchet="…64h…"
#               sec:prev_count="0" sec:msg_index="7">…ct…</sec:sealed>
#     ⇒ <amin:stream channel="sec-open">hello</amin:stream>
#
# Every failure is fail-closed: no stream element, one line logged.

use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Filter::Crypto::Base';

sub _capture_name ($self) { 'sealed' }

sub _handle ($self, $name, $attrs, $data) {
    my $h = $self->Handler or return;

    my $state = $self->_session_file($attrs);
    unless (length $state) {
        $self->Log && $self->Log->error('[sec/open] no session (sec:session attr or session_path)');
        return;
    }
    my $dh = $self->_find_attr($attrs, 'ratchet') // '';
    unless (length $dh) {
        $self->Log && $self->Log->error('[sec/open] missing sec:ratchet header field');
        return;
    }
    my $pn = $self->_find_attr($attrs, 'prev_count') // '0';
    my $n  = $self->_find_attr($attrs, 'msg_index')  // '0';
    my $ad = $self->_ad($attrs);
    my $ct = $self->_trim($data);

    my @args = ('open', '--state', $state, '--dh', $dh,
                '--pn', ($pn || '0'), '--n', ($n || '0'));
    push @args, '--ad', $ad if length $ad;
    my ($rc, $out, $err) = $self->_rctool_run(\@args, $ct);
    if ($rc != 0) {
        $self->Log && $self->Log->error(
            "[sec/open] rctool rc=$rc" . (length $err ? " stderr=$err" : ''));
        return;
    }

    $self->_emit_stream($h, 'sec-open', $out);
    return;
}

1;
