package Amin::AI::Music::Sink;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use parent 'XML::SAX::Base';

# The end of a music dispatch: a SAX handler standing where the XML writer
# stands in `amin render`.  It reads ai:update (progress, handed to on_update as
# it arrives), ai:result and the bc:object the Music filter emits for a take.

use constant AI_NS => 'http://projectamin.org/ns/ai/1';
use constant BC_NS => 'http://projectamin.org/ns/bc/';

sub new ($class, %o) {
    my $self = $class->SUPER::new();
    $self->{on_update} = $o{on_update};
    @$self{qw(in_res res res_text object)} = (0, undef, '', undef);
    return $self;
}

sub _attrs ($el) {
    my %a;
    for my $at (values %{ $el->{Attributes} // {} }) {
        my $n = $at->{LocalName} // $at->{Name} // '';
        $a{$n} = $at->{Value} // '' if length $n;
    }
    return \%a;
}

sub start_element ($self, $el) {
    my ($ns, $ln) = ($el->{NamespaceURI} // '', $el->{LocalName} // '');
    if    ($ns eq AI_NS && $ln eq 'update') { $self->{on_update}->(_attrs($el)) if $self->{on_update} }
    elsif ($ns eq AI_NS && $ln eq 'result') { @$self{qw(in_res res)} = (1, _attrs($el)) }
    elsif ($ln eq 'object' && ($ns eq BC_NS || ($el->{Prefix} // '') eq 'bc')) { $self->{object} //= _attrs($el) }
    return;
}

sub end_element ($self, $el) {
    $self->{in_res} = 0 if ($el->{NamespaceURI} // '') eq AI_NS && ($el->{LocalName} // '') eq 'result';
    return;
}

sub characters ($self, $c) {
    $self->{res_text} .= $c->{Data} // '' if $self->{in_res};
    return;
}

sub output ($self) { '' }
sub result ($self) { +{ res => $self->{res}, res_text => $self->{res_text}, object => $self->{object} } }

1;
