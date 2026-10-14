package Amin::AI::Provenance;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';

use Amin::AI qw(AI_NS);
use Class::Tiny qw(Handler Log Mode Name Element), {
    _suppress_depth => 0,
};

my $AI = AI_NS();

sub name    { '' }
sub element { undef }
sub position { 'end' }

sub _is_ai ($e) { ($e->{NamespaceURI} // '') eq $AI }

sub _tier_of ($el) {
    my $attrs = $el->{Attributes} // {};
    for my $k (keys %$attrs) {
        my $a = $attrs->{$k};
        next unless ref $a eq 'HASH';
        if (($a->{LocalName} // '') eq 'provenance.tier') {
            return $a->{Value} // 0;
        }
    }
    return undef;
}

sub start_element ($self, $el) {
    if (($self->{_suppress_depth} //= 0) > 0) {
        $self->{_suppress_depth}++;
        return;
    }
    if (_is_ai($el)) {
        my $mode = $self->Mode // 'render';
        if ($mode eq 'prod') {
            my $tier = _tier_of($el);
            if (defined $tier && $tier < 2) {
                $self->{_suppress_depth} = 1;
                $self->Log && $self->Log->info(
                    "[ai] Tier-$tier event dropped in prod mode; " .
                    "promote with amsinsig sign");
                return;
            }
        }
    }
    return $self->SUPER::start_element($el);
}

sub end_element ($self, $el) {
    if (($self->{_suppress_depth} //= 0) > 0) {
        $self->{_suppress_depth}--;
        return;
    }
    return $self->SUPER::end_element($el);
}

sub characters ($self, $d) {
    return if ($self->{_suppress_depth} //= 0) > 0;
    return $self->SUPER::characters($d);
}

1;
