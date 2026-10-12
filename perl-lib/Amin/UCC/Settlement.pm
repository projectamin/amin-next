package Amin::UCC::Settlement;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';

use Amin::UCC qw(UCC_NS);
use Class::Tiny qw(Handler Log Mode), {
    _amount_stack => sub { [] },
    _in_ucc_status => 0,
};

my $UCC = UCC_NS();

sub _is_ucc ($e) { ($e->{NamespaceURI} // '') eq $UCC }

sub _attr ($e, $name) {
    return undef unless $e && $e->{Attributes};
    for my $k ("{}" . $name, "{$UCC}$name") {
        return $e->{Attributes}{$k}{Value}
            if exists $e->{Attributes}{$k}
            && defined $e->{Attributes}{$k}{Value};
    }
    return undef;
}

sub _emit_settlement ($self, $amount, $currency, $finality, $kind) {
    my $h = $self->Handler or return;
    my %vals = (
        amount   => $amount   // 0,
        currency => $currency // 'USD',
        finality => $finality // 'irrevocable',
        kind     => $kind     // 'funds-transfer',
    );
    my %attrs;
    for my $k (keys %vals) {
        $attrs{"{}" . $k} = {
            Name         => "ucc:$k",
            LocalName    => $k,
            Prefix       => 'ucc',
            NamespaceURI => $UCC,
            Value        => "$vals{$k}",
        };
    }
    $h->start_element({
        NamespaceURI => $UCC, LocalName => 'settlement',
        Name => 'ucc:settlement', Prefix => 'ucc', Attributes => \%attrs,
    });
    $h->end_element({
        NamespaceURI => $UCC, LocalName => 'settlement',
        Name => 'ucc:settlement', Prefix => 'ucc',
    });
    return;
}

sub start_element ($self, $el) {
    $self->{_amount_stack} //= [];
    if (_is_ucc($el)) {
        my $ln = $el->{LocalName} // '';
        if ($ln eq 'status') {
            $self->{_in_ucc_status} = 1;
        }
        my $amount = _attr($el, 'amount');
        if (defined $amount && length $amount) {
            push $self->{_amount_stack}->@*, {
                amount   => $amount,
                currency => _attr($el, 'currency') // 'USD',
                ln       => $ln,
            };
        }
    }
    return $self->SUPER::start_element($el);
}

sub end_element ($self, $el) {
    $self->{_amount_stack} //= [];
    my $ln = $el->{LocalName} // '';
    if (_is_ucc($el) && $ln eq 'status') {
        $self->{_in_ucc_status} = 0;
        $self->SUPER::end_element($el);
        my $last = $self->{_amount_stack}[-1];
        if ($last) {
            $self->_emit_settlement(
                $last->{amount},
                $last->{currency},
                'irrevocable',
                $last->{ln},
            );
        }
        return;
    }
    if (_is_ucc($el) && @{$self->{_amount_stack}}) {
        my $top = $self->{_amount_stack}[-1];
        if ($top && $top->{ln} eq $ln) {
            pop $self->{_amount_stack}->@*;
        }
    }
    return $self->SUPER::end_element($el);
}

1;
