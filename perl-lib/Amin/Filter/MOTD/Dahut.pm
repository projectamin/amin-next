package Amin::Filter::MOTD::Dahut;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';

use Class::Tiny qw(Handler Log Mode Name Element inject_on_start), {
    inject_on_start => 0,
    _injected       => 0,
};

use Amin::Util::DahutQuotes;

sub BUILD ($self, @) {
    $self->{inject_on_start} //= 0;
    $self->{_injected} //= 0;
}

sub start_document ($self, $doc = undef) {
    if ($self->inject_on_start && !$self->{_injected}) {
        $self->_inject_motd;
        $self->{_injected} = 1;
    }
    return $self->SUPER::start_document($doc);
}

sub _inject_motd ($self) {
    my $h = $self->Handler or return;
    my $quote = Amin::Util::DahutQuotes->random_quote;
    my $attrs = {};
    # Create amin:motd element
    $h->start_element({
        NamespaceURI => 'http://projectamin.org/ns/amin/1',
        LocalName => 'motd',
        Name => 'amin:motd',
        Prefix => 'amin',
        Attributes => $attrs,
    });
    $h->characters({ Data => $quote });
    $h->end_element({
        NamespaceURI => 'http://projectamin.org/ns/amin/1',
        LocalName => 'motd',
        Name => 'amin:motd',
        Prefix => 'amin',
    });
}

sub start_element ($self, $e) {
    return $self->SUPER::start_element($e);
}

sub end_element ($self, $e) {
    return $self->SUPER::end_element($e);
}

sub characters ($self, $c) {
    return $self->SUPER::characters($c);
}

# Convenience method to get a random quote
sub random_quote ($self = undef) {
    return Amin::Util::DahutQuotes->random_quote;
}

1;
