package Amin::Handler::HTML;
use v5.38; use warnings; use utf8;
use parent 'XML::SAX::Base';

use Amin qw(NS);
use Class::Tiny qw(fh autoflush sink), {
    buf   => '',
    stack => sub { [] },
};

# Dumb serializer (plan §4.3/§4.5): void elements self-close so the output
# stays well-formed XHTML, attributes and text are escaped here and nowhere
# else, and every non-`html:` event (amin:status, ui:, stray filter output)
# is dropped.  Debug mode keeping them in a comment is future work.

use constant XHTML => 'http://www.w3.org/1999/xhtml';
use constant VOID  => { map { $_ => 1 }
    qw(area base br col embed hr img input link meta source track wbr) };

sub output ($s) { $s->buf }

# Three sinks, in order of precedence:
#   sink  — coderef, called per chunk.  Streaming: nothing accumulates in
#           buf, so a large page costs O(1) memory instead of O(page).
#   fh    — filehandle + autoflush.  The CLI streaming path (bin/amin).
#   (neither) — buffered; output returns the whole document.
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

sub start_document ($self, @) {
    $self->_push("<!DOCTYPE html>\n");
    return;
}

sub start_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    return unless $ns eq XHTML;
    my $ln = $el->{LocalName} // $el->{Name} // return;
    $self->_push("<$ln");
    # sorted: attribute order in the output must not depend on hash
    # randomization — byte-stable pages, testable assertions (§4.3 dumb serializer)
    my @attrs = sort { ($a->{LocalName} // $a->{Name} // '')
                    cmp ($b->{LocalName} // $b->{Name} // '') }
                values %{ $el->{Attributes} // {} };
    for my $a (@attrs) {
        my $an = $a->{LocalName} // $a->{Name} // next;
        next unless length $an;
        next if $an eq 'xmlns' || ($a->{Prefix} // '') eq 'xmlns';
        my $av = $a->{Value} // '';
        $self->_push(qq( $an=") . _e($av) . '"');
    }
    if (VOID->{$ln}) { $self->_push("/>\n") }
    else             { push @{$self->stack}, $ln; $self->_push(">\n") }
    return;
}

sub end_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    return unless $ns eq XHTML;
    my $ln = pop @{$self->stack};
    return unless defined $ln;
    return if VOID->{$ln};
    $self->_push("</$ln>\n");
    return;
}

sub characters ($self, $d) {
    my $t = $d->{Data} // '';
    return unless length $t;
    return unless @{$self->stack};   # drop text outside any html element
    $self->_push(_e($t));
    return;
}

sub _e ($s) { $s =~ s/([<>&"])/{"<" => "&lt;", ">" => "&gt;", "&" => "&amp;", '"' => "&quot;"}->{$1}/ger }

1;
