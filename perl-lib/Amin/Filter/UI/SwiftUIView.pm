package Amin::Filter::UI::SwiftUIView;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';

use Class::Tiny qw(Handler Log Mode Name Element), { stack => sub { [] } };

sub _attr ($e, $name) { ($e->{Attributes}{"{}${name}"} // {})->{Value} // '' }

sub start_element ($self, $e) {
    my $ns = $e->{NamespaceURI} // '';
    my $ln = $e->{LocalName}     // '';
    if ($ns eq 'http://projectamin.org/ns/ui/1') {
        push $self->{stack}->@*, $ln;
        my $v = $self->_map_view($ln, $e) // return;
        return $self->Handler && $self->Handler->start_element($v);
    }
    $self->Handler && $self->Handler->start_element($e);
}

sub end_element ($self, $e) {
    my $ns = $e->{NamespaceURI} // '';
    my $ln = $e->{LocalName}     // '';
    if ($ns eq 'http://projectamin.org/ns/ui/1') {
        my $top = pop $self->{stack}->@*;
        if ($self->_map_view($ln, $e)) {
            $self->Handler && $self->Handler->end_element({
                NamespaceURI => 'http://projectamin.org/ns/ui/1',
                LocalName => $ln, Name => "ui:$ln", Prefix => 'ui' });
        }
        return;
    }
    $self->Handler && $self->Handler->end_element($e);
}

sub characters ($self, $c) {
    if (grep { length } $self->{stack}->@*) {
        $self->Handler && $self->Handler->characters($c);
        return;
    }
    $self->Handler && $self->Handler->characters($c);
}

sub _map_view ($self, $ln, $e) {
    state $known = { map {; $_ => 1 } qw(
        app scene list row column stack hstack vstack grid section
        text badge sparkline button navigate image asyncimage picker
        card progress alert sheet toolbar searchable list item label
    )};
    return unless $known->{$ln};
    my %a;
    for my $k (keys $e->{Attributes}->%*) {
        my $local = $e->{Attributes}{$k}{LocalName};
        $a{$local} = $e->{Attributes}{$k}{Value};
    }
    my $attrs = { map {; "{}" . $_ => +{ Name => $_, LocalName => $_,
        Prefix => 'ui', NamespaceURI => 'http://projectamin.org/ns/ui/1',
        Value => $a{$_} } } keys %a };
    +{  NamespaceURI => 'http://projectamin.org/ns/ui/1',
        LocalName => $ln, Name => "ui:$ln", Prefix => 'ui',
        Attributes => $attrs };
}

1;
