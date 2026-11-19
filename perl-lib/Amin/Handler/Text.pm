package Amin::Handler::Text;
use v5.38; use warnings; use utf8;
use parent 'XML::SAX::Base';

use Amin qw(NS);
use Class::Tiny qw(fh autoflush sink), { buf => '' };

# The plain-text serializer (axa-plan §4.1): a route may declare
# type="text/plain", and then the response body IS the character data the chain
# emits — no doctype, no element tags, no escaping.  It is the dumbest possible
# sink, and deliberately so: an ACME HTTP-01 key authorization (or any other
# byte-exact body) is emitted by a filter as characters and must not be
# re-wrapped or entity-escaped on the way out.
#
# Elements are ignored entirely.  Only characters matter, and they pass through
# verbatim — the filter that produced them owns any escaping the body needs.

sub output ($s) { $s->buf }

# Same three sinks, same precedence as Amin::Handler::HTML: sink (streaming),
# then fh + autoflush, then the buffer.
sub _push ($self, $data) {
    if (my $sink = $self->sink) {
        $sink->($data);
        return;
    }
    $self->buf($self->buf . $data);
    if ($self->fh && ($self->autoflush // 1)) {
        print { $self->fh } $data;
        $self->fh->can('flush') && $self->fh->flush;
    }
    return;
}

sub start_document ($self, @) { return }
sub start_element  ($self, $el) { return }
sub end_element    ($self, $el) { return }
sub end_document   ($self, @) { return }

sub characters ($self, $d) {
    my $t = $d->{Data} // '';
    $self->_push($t) if length $t;
    return;
}

1;
