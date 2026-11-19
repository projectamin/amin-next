package Amin::Handler::Writer;
use v5.38; use warnings; use utf8;
use parent 'XML::SAX::Base';

# _push calls $fh->flush in stream mode; `flush` is a method IO::Handle installs
# on filehandles, so declare the dependency here rather than inheriting it from
# whichever XML parser happens to be loaded (XML::LibXML::SAX used to pull it in
# by accident, via IO::File).
use IO::Handle ();

use Amin qw(NS);
use Class::Tiny qw(fh autoflush), {
    depth   => 0,
    stack   => sub { [] },
    buf     => '',
    indent  => 2,
};

use constant ESC => { '<' => '&lt;', '>' => '&gt;',
                      '"' => '&quot;', '&' => '&amp;', "'" => '&apos;' };

sub output ($s) { $s->buf }

sub _push ($self, $data) {
    $self->buf($self->buf . $data);
    if ($self->fh && ($self->autoflush // 1)) {
        print { $self->fh } $data;
        $self->fh->can('flush') && $self->fh->flush;
    }
    return;
}

sub start_document ($self, @) {
    $self->_push(qq(<?xml version="1.0" encoding="UTF-8"?>\n));
}

sub start_element ($self, $el) {
    my ($ln, $ns, $pfx) = @{$el}{qw(LocalName NamespaceURI Prefix)};
    my $name = $pfx ? "$pfx:$ln" : $ln;
    push @{$self->stack}, [$name, $ns, $pfx];

    $self->_push(' ' x ($self->depth * $self->indent) . "<$name");
    # Attributes arrive in a plain hash, so `values %*` iterates in Perl's
    # randomised hash order — two runs of the same event stream would not
    # agree byte for byte.  Sort by the rendered qualified name so the
    # serialisation is canonical: identical events always give identical
    # bytes (the determinism the Perl↔Rust decision-profile parity needs).
    my @attrs;
    for my $a (values $el->{Attributes}->%*) {
        my $pf = $a->{Prefix} // '';
        my $an = $a->{LocalName} // $a->{Name} // '';
        next unless length $an;
        $an = "$pf:$an" if length $pf;
        my $av = $a->{Value} // '';
        next unless length $av || defined $a->{Value};
        push @attrs, [ $an, $av ];
    }
    for my $a (sort { $a->[0] cmp $b->[0] } @attrs) {
        $self->_push(qq( $a->[0]=") . _e($a->[1]) . '"');
    }
    $self->_push(">\n");
    $self->depth($self->depth + 1);
}

sub end_element ($self, @) {
    $self->depth($self->depth - 1);
    my $name = (pop @{$self->stack})->[0];
    $self->_push(' ' x ($self->depth * $self->indent) . "</$name>\n");
}

sub characters ($self, $d) {
    my $t = $d->{Data} // '';
    return unless length $t;
    my $top = $self->stack->[-1];
    if ($top && $top->[0] =~ /:stream$/) {
        $self->_push(_e($t));
        return;
    }
    my $pad = ' ' x ($self->depth * $self->indent);
    $self->_push("$pad$_\n") for map _e($_), split /\n/, $t;
}

sub _e ($s) { $s =~ s/([<>"'&])/ESC->{$1}/ger }

1;
