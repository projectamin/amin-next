package Amin::UCC::General;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::UCC::Article';

use Amin::UCC qw(UCC_NS);

my $UCC = UCC_NS();

use constant {
    RC_FORM_MALFORMED => -4096,
};

sub element { 'transaction' }

sub on_article_close ($self, $el) {
    my $parties = $self->_child_vals('party');
    my $subject = $self->_child_vals('subject');
    my $law     = $self->_attr($el, 'governing-law') // 'UCC';

    if (@$parties < 2 || !@$subject) {
        $self->_result(
            kind      => 'error',
            rc        => RC_FORM_MALFORMED,
            exit_kind => 'ucc_form',
            msg       => 'transaction requires >=2 parties and a subject',
        );
        return;
    }

    $self->_emit_event(1, 'transaction-formed',
        governing_law => $law,
        parties       => scalar(@$parties),
        subjects      => scalar(@$subject),
    );
    return;
}

1;
