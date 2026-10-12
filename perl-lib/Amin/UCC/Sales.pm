package Amin::UCC::Sales;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::UCC::Article';

use Amin::Util::Fold qw(_vals _flags);

my %WARRANTY_ALLOW = map { $_ => 1 }
    qw(merchantability fitness title infringement none express);
my %DELIVERY_ALLOW = map { $_ => 1 }
    qw(shipment destination fob-seller fob-buyer ex-ship);

use constant {
    RC_SALE_INVALID => -4224,
};

sub element { 'sale' }

sub on_article_close ($self, $el) {
    my $goods    = $self->_child_vals('goods');
    my $price    = $self->_child_vals('price');
    my $delivery = $self->_child_vals('delivery');
    my $warranty = $self->_child_vals('warranty');

    if (!@$goods || !@$price) {
        $self->_result(
            kind      => 'error',
            rc        => RC_SALE_INVALID,
            exit_kind => 'ucc_sale_form',
            msg       => 'sale requires goods and price',
        );
        return;
    }

    for my $w (@$warranty) {
        unless ($WARRANTY_ALLOW{$w}) {
            $self->_result(
                kind      => 'error',
                rc        => RC_SALE_INVALID,
                exit_kind => 'ucc_sale_term',
                msg       => "unrecognized warranty term: $w",
            );
            return;
        }
    }
    for my $d (@$delivery) {
        unless ($DELIVERY_ALLOW{$d}) {
            $self->_result(
                kind      => 'error',
                rc        => RC_SALE_INVALID,
                exit_kind => 'ucc_sale_term',
                msg       => "unrecognized delivery term: $d",
            );
            return;
        }
    }

    $self->_result(
        kind      => 'accepted',
        rc        => 0,
        exit_kind => 'ok',
    );

    $self->_emit_event(2, 'contract-formed',
        goods    => join(',', @$goods),
        price    => join(',', @$price),
        delivery => join(',', @$delivery) || 'shipment',
    );

    if (@$delivery && $delivery->[0] =~ /destination|fob-buyer/) {
        $self->_emit_event(2, 'risk-of-loss-passed',
            at => 'tender-of-delivery',
        );
    } else {
        $self->_emit_event(2, 'risk-of-loss-passed',
            at => 'shipment',
        );
    }
    return;
}

1;
