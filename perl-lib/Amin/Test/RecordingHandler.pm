package Amin::Test::RecordingHandler;

# Amin::Test::RecordingHandler — shared capture of SAX events with
# NAME-sorted attrs + trimmed-whitespace chars normalization, for
# deterministic parity checks between BSAX binary roundtrip path and
# plain Writer/SAX paths.
#
# Direct replacement for the ~50-line duplicated inline RecordingHandler
# class that existed verbatim in t/11-bsax-roundtrip.t and
# t/12-bsax-bitcache-ns.t.
#
# Usage (identical API to the old inline blob, so test body changes are
# s/our @Captured/$r->captured->@*/g only):
#
#   my $r = Amin::Test::RecordingHandler->new;
#   XML::LibXML::SAX->new(Handler => $r)->parse_string($xml);
#   is_deeply scalar($r1->captured), scalar($r2->captured), 'roundtrip parity';
#
use v5.38; use warnings; use utf8; use experimental 'signatures';
use Class::Tiny { captured => sub { [] } };

sub start_document ($self, @) { push $self->captured->@*, 'start_document' }
sub end_document   ($self, @) { push $self->captured->@*, 'end_document' }

sub start_element  ($self, $e) {
    my @attrs;
    for my $a (values %{ $e->{Attributes} // {} }) {
        my $n = $a->{Name} // '';
        next if $n =~ /^xmlns/;
        my $v = $a->{Value} // '';
        next unless length($v) || defined $a->{Value};
        my $ln = $a->{LocalName} // $n;
        $ln =~ s/^[^:]+://;
        push @attrs, { LocalName => $ln, Value => $v };
    }
    @attrs = sort { $a->{LocalName} cmp $b->{LocalName} } @attrs;
    my $eln = $e->{LocalName} // $e->{Name} // '';
    $eln =~ s/^[^:]+://;
    push $self->captured->@*, [start_element => {
        LocalName => $eln,
        NamespaceURI => $e->{NamespaceURI} // '',
        Attributes  => \@attrs,
    }];
}

sub end_element  ($self, $e) {
    my $eln = $e->{LocalName} // $e->{Name} // '';
    $eln =~ s/^[^:]+://;
    push $self->captured->@*, [end_element => {
        LocalName    => $eln,
        NamespaceURI => $e->{NamespaceURI} // '',
    }];
}

sub characters   ($self, $d) {
    my $t = $d->{Data} // '';
    return unless length $t;
    $t =~ s/^\s+|\s+$//g;
    return unless length $t;
    push $self->captured->@*, [characters => $t];
}

1;
