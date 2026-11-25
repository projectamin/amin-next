package Amin::AI::Music::CatalogSink;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use parent 'XML::SAX::Base';

# The end of a discovery dispatch: collects the <ai:catalog> the Models filter
# emits (provider, base, and one <ai:model> per music-capable model) and the
# first ai:result error, if any.  Names only — there is no key in this shape.

use constant AI_NS => 'http://projectamin.org/ns/ai/1';

sub new ($class, %o) {
    my $self = $class->SUPER::new();
    @$self{qw(in_catalog catalog error)} = (0, undef, '');
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
    return unless $ns eq AI_NS;
    if ($ln eq 'catalog') {
        my $a = _attrs($el);
        $self->{catalog} = {
            provider => $a->{provider} // '',
            base     => $a->{base} // '',
            models   => [],
        };
        $self->{in_catalog} = 1;
    }
    elsif ($ln eq 'model' && $self->{in_catalog}) {
        my $a = _attrs($el);
        my $id = $a->{id} // $a->{upstream} // '';
        push $self->{catalog}{models}->@*, {
            id   => $id,
            name => length($a->{name} // '') ? $a->{name} : $id,
        } if length $id;
    }
    elsif ($ln eq 'result') {
        my $a = _attrs($el);
        if (($a->{kind} // '') eq 'error' && !length $self->{error}) {
            $self->{error} = $a->{msg} // 'model discovery failed';
        }
    }
    return;
}

sub end_element ($self, $el) {
    $self->{in_catalog} = 0
        if ($el->{NamespaceURI} // '') eq AI_NS && ($el->{LocalName} // '') eq 'catalog';
    return;
}

sub output ($self) { '' }
sub result ($self) { +{ catalog => $self->{catalog}, error => $self->{error} } }

1;
