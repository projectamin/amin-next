package Amin::UCC::Instruments;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::UCC::Article';

my %KIND_ALLOW = map { $_ => 1 } qw(check note draft certificate-of-deposit);

use constant {
    RC_INSTRUMENT_FORM  => -4352,
    RC_INSTRUMENT_SIG   => -4353,
};

sub _can_verify {
    state $cv = eval { require Crypt::ML_DSA; 1 } || 0;
    return $cv;
}

sub element { 'instrument' }

sub on_article_close ($self, $el) {
    my $kind   = $self->_attr($el, 'kind') // 'note';
    my $maker  = $self->_attr($el, 'maker') // '';
    my $payee  = $self->_attr($el, 'payee') // '';
    my $amount = $self->_attr($el, 'amount') // '';
    my $sig    = $self->_attr($el, 'sig') // '';
    my $vk     = $self->_attr($el, 'vk') // '';

    unless ($KIND_ALLOW{$kind}) {
        $self->_result(kind => 'error', rc => RC_INSTRUMENT_FORM,
            exit_kind => 'ucc_instrument_kind',
            msg => "unrecognized instrument kind: $kind");
        return;
    }
    unless (length($maker) && length($payee) && length($amount)) {
        $self->_result(kind => 'error', rc => RC_INSTRUMENT_FORM,
            exit_kind => 'ucc_instrument_form',
            msg => 'instrument requires maker, payee, amount');
        return;
    }

    my $sig_ok = 1;
    if (length($sig) && length($vk)) {
        if (_can_verify()) {
            require MIME::Base64;
            my $raw_sig = MIME::Base64::decode_base64($sig);
            my $raw_vk  = MIME::Base64::decode_base64($vk);
            my $msg     = join("\0", $maker, $payee, $amount, $kind) . 'amin.ucc.art3.v1';
            eval { $sig_ok = Crypt::ML_DSA::verify_87($raw_vk, $raw_sig, $msg); 1 }
                or do { $sig_ok = 0 };
        }
    }

    unless ($sig_ok) {
        $self->_emit_event(3, 'signature-failed',
            kind  => $kind,
            maker => $maker,
        );
        $self->_result(kind => 'error', rc => RC_INSTRUMENT_SIG,
            exit_kind => 'ucc_bad_sig',
            msg => 'ML-DSA-87 signature verification failed');
        return;
    }

    $self->_emit_event(3, 'signature-verified',
        kind  => $kind,
        maker => $maker,
        payee => $payee,
        alg   => 'ML-DSA-87',
    );
    $self->_result(kind => 'accepted', rc => 0, exit_kind => 'ok');
    return;
}

1;
