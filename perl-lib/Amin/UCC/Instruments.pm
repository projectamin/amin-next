package Amin::UCC::Instruments;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::UCC::Article';

my %KIND_ALLOW = map { $_ => 1 } qw(check note draft certificate-of-deposit);

use constant {
    RC_INSTRUMENT_FORM  => -4352,
    RC_INSTRUMENT_SIG   => -4353,
};

# ── Trusted makers ────────────────────────────────────────────────────────
# A signature checked against a key the instrument itself carries proves
# nothing: anyone can sign with a key of their own choosing.  An instrument is
# accepted only when its VK is one the process already trusts — registered for
# that maker here, or a mesh trust anchor (L<Amin::Auth::ZCap>).
my %MAKER_VK;

sub register_maker ($class, $maker, $vk) {
    return unless defined $maker && length $maker && defined $vk && length $vk;
    $MAKER_VK{$maker} = $vk;
    return;
}
sub clear_makers ($class) { %MAKER_VK = (); return; }

sub _vk_trusted ($maker, $vk) {
    return 1 if defined $MAKER_VK{$maker} && $MAKER_VK{$maker} eq $vk;
    require Amin::Auth::ZCap;
    for my $a (Amin::Auth::ZCap->registered_trust_anchors->@*) {
        return 1 if defined $a && $a eq $vk;
    }
    return 0;
}

# Per-maker high-water mark of accepted instrument seqs (one number per maker).
# Persisted when AMIN_INSTRUMENT_STATE names a file, so a restart cannot reopen
# the replay window; otherwise it lives for the process.
our %LAST;
my $loaded = '';
sub _state_file () { $ENV{AMIN_INSTRUMENT_STATE} }
sub _seq_accept ($maker, $seq) {
    my $f = _state_file();
    if (defined $f && length $f && $loaded ne $f) {
        %LAST = ();
        if (open my $in, '<', $f) {
            while (<$in>) { chomp; my ($m, $s) = split /\t/, $_, 2; $LAST{$m} = $s if defined $s && $s =~ /\A\d+\z/ }
            close $in;
        }
        $loaded = $f;
    }
    return 0 if exists $LAST{$maker} && $seq <= $LAST{$maker};
    if (defined $f && length $f) {
        # append-only; a failed write refuses the instrument (fail closed)
        open my $out, '>>', $f or return 0;
        print {$out} "$maker\t$seq\n" or return 0;
        close $out or return 0;
    }
    $LAST{$maker} = $seq;
    return 1;
}

sub element { 'instrument' }

sub on_article_close ($self, $el) {
    my $kind   = $self->_attr($el, 'kind') // 'note';
    my $maker  = $self->_attr($el, 'maker') // '';
    my $payee  = $self->_attr($el, 'payee') // '';
    my $amount = $self->_attr($el, 'amount') // '';
    my $sig    = $self->_attr($el, 'sig') // '';
    my $vk     = $self->_attr($el, 'vk') // '';
    my $seq    = $self->_attr($el, 'seq') // '';

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

    # Fail closed.  Accepted only if the signature verifies (Rust verifier,
    # bitcache::trust::instrument_verify) under a VK we already trust.  An
    # unsigned instrument, a missing verifier and an untrusted key are all
    # rejections — there is no "structural" accept.
    my $sig_ok = 0;
    my $why    = 'ML-DSA-87 signature verification failed';
    if (!length($sig) || !length($vk)) {
        $why = 'instrument is unsigned';
    } elsif ($seq !~ /\A[0-9]{1,19}\z/) {
        $why = 'instrument has no valid seq';
    } else {
        require MIME::Base64;
        require Amin::Crypto::Verify;
        my $raw_sig = MIME::Base64::decode_base64($sig);
        my $raw_vk  = MIME::Base64::decode_base64($vk);
        if (!_vk_trusted($maker, $raw_vk)) {
            $why = 'instrument key is not trusted for this maker';
        } else {
            my $rc = Amin::Crypto::Verify::instrument_verify(
                $maker, $payee, $amount, $kind, $seq, $raw_vk, $raw_sig);
            $sig_ok = ($rc == Amin::Crypto::Verify::RC_OK()) ? 1 : 0;
            $why = 'verifier unavailable' if $rc == Amin::Crypto::Verify::RC_BAD_ARG();
            # Replay: the seq is signed, so it can be trusted.  Only a seq above
            # everything this maker has had accepted passes; checked after the
            # signature so unsigned junk cannot burn a maker's counter.
            if ($sig_ok && !_seq_accept($maker, $seq)) {
                $sig_ok = 0;
                $why = 'instrument replay: seq not above the last accepted';
            }
        }
    }

    unless ($sig_ok) {
        $self->_emit_event(3, 'signature-failed',
            kind  => $kind,
            maker => $maker,
        );
        $self->_result(kind => 'error', rc => RC_INSTRUMENT_SIG,
            exit_kind => 'ucc_bad_sig',
            msg => $why);
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
