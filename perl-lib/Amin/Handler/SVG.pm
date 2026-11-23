package Amin::Handler::SVG;
use v5.38; use warnings; use utf8;
use parent 'Amin::Handler::Writer';

# Dumb SVG serializer: keeps only svg:* events, drops the profile around them.
# The map target already decided what the drawing is and emitted it as events;
# this class only writes XML.  Same division as Amin::Handler::HTML, which keeps
# html:* events and drops everything else.  No indentation: SVG text content is
# geometry-bearing, so padding would change what <text> renders.

use constant SVG_NS => 'http://www.w3.org/2000/svg';

sub start_element ($self, $el) {
    return unless (($el->{NamespaceURI} // '') eq SVG_NS);
    $self->{_svg_depth} = ($self->{_svg_depth} // 0) + 1;
    my $ln = $el->{LocalName} // $el->{Name} // return;
    my @attrs;
    for my $a (values %{ $el->{Attributes} // {} }) {
        my $an = $a->{LocalName} // $a->{Name} // '';
        next unless length $an;
        push @attrs, [ $an, $a->{Value} // '' ];
    }
    my $tag = join '', map { qq( $_->[0]=") . Amin::Handler::Writer::_e($_->[1]) . '"' }
                       sort { $a->[0] cmp $b->[0] } @attrs;
    $self->_push("<$ln$tag>");
    return;
}

sub end_element ($self, $el) {
    return unless (($el->{NamespaceURI} // '') eq SVG_NS);
    my $ln = $el->{LocalName} // $el->{Name} // return;
    $self->_push("</$ln>");
    $self->{_svg_depth} = ($self->{_svg_depth} // 0) - 1;
    return;
}

sub characters ($self, $d) {
    return unless $self->{_svg_depth};
    my $t = $d->{Data} // '';
    $self->_push(Amin::Handler::Writer::_e($t)) if length $t;
    return;
}

1;
