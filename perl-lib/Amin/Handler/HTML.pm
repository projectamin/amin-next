package Amin::Handler::HTML;
use v5.38; use warnings; use utf8;
use parent 'XML::SAX::Base';

use Amin qw(NS);
use Class::Tiny qw(fh autoflush sink), {
    buf   => '',
    stack => sub { [] },
    scope => sub { [] },   # 1/0 per open element: is it a kept (XHTML) element?
    raw   => 0,            # inside an HTML raw-text element (script, style)
};

# Dumb serializer (plan §4.3/§4.5): void elements self-close so the output
# stays well-formed XHTML, attributes and text are escaped here and nowhere
# else (script and style content is the raw-text exception), and every non-`html:`
# event (amin:status, ui:, stray filter output) is dropped.  Debug mode
# keeping them in a comment is future work.

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
    my $ln = $el->{LocalName} // $el->{Name} // '';
    my $html = ($ns eq XHTML) ? 1 : 0;
    # A void element is self-contained: it can hold no content, so it neither
    # opens a scope nor waits for a close (end_element skips it symmetrically).
    my $void = ($html && length $ln && VOID->{$ln}) ? 1 : 0;
    push @{ $self->scope }, $html unless $void;
    return unless $html;
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
    # <script> and <style> are raw-text elements in HTML: their content is
    # code, not character data, so it must not be entity-escaped.  An escaped
    # script is dead code, and an escaped selector (`section&gt;h2`) silently
    # matches nothing.  The target emits both; apps cannot.
    $self->raw($self->raw + 1) if $ln eq 'script' || $ln eq 'style';
    return;
}

sub end_element ($self, $el) {
    my $ln = $el->{LocalName} // $el->{Name} // '';
    return if length $ln && VOID->{$ln};     # void: nothing was opened, nothing to close
    return unless pop @{ $self->scope };     # leave a dropped (non-html) scope: nothing to close
    my $top = pop @{$self->stack};
    return unless defined $top;
    $self->_push("</$top>\n");
    $self->raw($self->raw - 1) if ($top eq 'script' || $top eq 'style') && $self->raw > 0;
    return;
}

sub characters ($self, $d) {
    my $sc = $self->scope;
    # emit only text sitting directly inside a kept (XHTML) element — text from a
    # ui:/amin: scope (raw profile content forwarded alongside our fragments) is dropped
    return unless @$sc && $sc->[-1];
    my $t = $d->{Data} // '';
    return unless length $t;
    $self->_push($self->raw ? $t : _e($t));
    return;
}

sub _e ($s) { $s =~ s/([<>&"])/{"<" => "&lt;", ">" => "&gt;", "&" => "&amp;", '"' => "&quot;"}->{$1}/ger }

1;
