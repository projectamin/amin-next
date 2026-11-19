package Amin::Filter::UI::Guard;

# ui: closed-world guard.
#
# The one-filter-per-kind fleet has no filter for a kind it does not know, so
# on its own an unknown <ui:widget> would ride through untouched.  This guard
# keeps the fail-closed contract: a KNOWN ui: kind is forwarded untouched — so
# a host with no render filters still passes the whole ui: subtree through in
# full — while an UNKNOWN kind is a logged error and its subtree is dropped,
# as the closed-world contract requires.
#
# Always present at `late` (neutral, element-agnostic), independent of the
# render targets, so the contract holds on every host whether or not it renders.

use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';
use Class::Tiny qw(Handler Log Mode Name Element);

our $UI_NS = 'http://projectamin.org/ns/ui/1';

# Closed-world vocabulary — the 36 element LocalNames in the ui: region.
# Stated here (not read from the codec) because a filter is code and must state
# the contract it enforces; the codec's table is the mirror, not the source.
my %KIND = map {; $_ => 1 } qw(
    app scene list row column hstack vstack stack grid section card
    progress alert sheet toolbar searchable item label text markdown badge
    sparkline button navigate image asyncimage swap audio
    form field select option table tr cell style
);

sub start_element ($self, $e) {
    if ($self->{_skip}) { $self->{_skip}++; return }
    if (($e->{NamespaceURI} // '') eq $UI_NS) {
        my $ln = $e->{LocalName} // '';
        unless ($KIND{$ln}) {
            $self->Log && $self->Log->error(
                "[ui/guard] <ui:$ln> is not in the closed-world ui: vocabulary — subtree dropped");
            $self->{_skip} = 1;
            return;
        }
    }
    return $self->SUPER::start_element($e);
}

sub characters ($self, $c) {
    return if $self->{_skip};
    return $self->SUPER::characters($c);
}

sub end_element ($self, $e) {
    if ($self->{_skip}) { $self->{_skip}--; return }
    return $self->SUPER::end_element($e);
}

1;
