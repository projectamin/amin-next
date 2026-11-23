package Amin::Handler::DOT;
use v5.38; use warnings; use utf8;
use parent 'XML::SAX::Base';

use Class::Tiny { fh => undef, autoflush => 1 }, {
    buf => '',
    in_stream => 0,
};

use constant AMIN_NS => 'http://projectamin.org/ns/2026/';

# Dumb DOT serializer: DOT is not XML, so the map target publishes the complete
# graph text on one <amin:stream channel="map-dot"> element.  Write that text
# raw and drop the profile around it.

sub output ($self) { $self->buf }

sub _push ($self, $data) {
    $self->buf($self->buf . $data);
    if ($self->fh && ($self->autoflush // 1)) {
        print { $self->fh } $data;
        $self->fh->can('flush') && $self->fh->flush;
    }
    return;
}

sub start_element ($self, $el) {
    return unless ($el->{NamespaceURI} // '') eq AMIN_NS
        && ($el->{LocalName} // '') eq 'stream';
    my %a;
    for my $at (values %{ $el->{Attributes} // {} }) {
        $a{ $at->{LocalName} // $at->{Name} // '' } = $at->{Value};
    }
    $self->in_stream(1) if ($a{channel} // '') eq 'map-dot';
    return;
}

sub characters ($self, $d) {
    return unless $self->in_stream;
    my $t = $d->{Data} // '';
    $self->_push($t) if length $t;
    return;
}

sub end_element ($self, $el) {
    return unless ($el->{NamespaceURI} // '') eq AMIN_NS
        && ($el->{LocalName} // '') eq 'stream';
    $self->in_stream(0);
    return;
}

sub start_document ($self, @) { return }
sub end_document   ($self, @) { return }

1;
