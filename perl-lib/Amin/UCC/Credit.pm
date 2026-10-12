package Amin::UCC::Credit;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::UCC::Article';

use Amin::UCC qw(UCC_NS);
use Class::Tiny qw(), {
    _lc_stack => sub { [] },
};

my $UCC = UCC_NS();

use constant {
    RC_LC_DISCREPANCY => -5121,
};

sub element { 'lc' }

sub _is_ucc ($e) { ($e->{NamespaceURI} // '') eq $UCC }

sub _parse_lc ($self, $el) {
    my $benef = $self->_attr($el, 'beneficiary') // '';
    my $expiry = $self->_attr($el, 'expiry') // '';
    my $docs   = $self->_attr($el, 'documents') // '';
    my %allow;
    for my $d (split /,/, $docs) {
        my $t = $d;
        $t =~ s/^\s+|\s+$//g;
        $allow{$t} = 1 if length $t;
    }
    return {
        beneficiary => $benef,
        expiry      => $expiry,
        allow       => \%allow,
        has_allow   => (scalar keys %allow) > 0,
    };
}

sub start_element ($self, $el) {
    $self->{_lc_stack} //= [];
    my $ln = $el->{LocalName} // '';
    if (_is_ucc($el) && $ln eq 'lc') {
        my $frame = $self->_parse_lc($el);
        push $self->{_lc_stack}->@*, $frame;
        $self->_emit_event(5, 'lc-opened',
            beneficiary => $frame->{beneficiary},
            expiry      => $frame->{expiry},
            documents   => scalar(keys %{$frame->{allow}}),
        );
    } elsif (_is_ucc($el) && $ln ne 'lc') {
        my $lc = $self->{_lc_stack}[-1];
        if ($lc && $lc->{has_allow} && !$lc->{allow}{$ln}) {
            $self->_emit_event(5, 'lc-discrepancy',
                document    => $ln,
                beneficiary => $lc->{beneficiary},
                reason      => 'not-in-conforming-documents',
            );
        }
    }
    return $self->SUPER::start_element($el);
}

sub end_element ($self, $el) {
    my $ln = $el->{LocalName} // '';
    if (_is_ucc($el) && $ln eq 'lc') {
        pop $self->{_lc_stack}->@*;
    }
    return $self->SUPER::end_element($el);
}

sub on_article_close ($self, $el) { return; }

1;
