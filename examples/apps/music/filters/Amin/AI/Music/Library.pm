package Amin::AI::Music::Library;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use parent 'Amin::AI::Music::Element';
use Amin::AXA::UI::Base qw(_short _p);
use Amin::AI::Music::Store;

# <mu:library/> — earlier takes, newest first, each with its player and a
# reuse link that is a GET (the take name is in the URL).
sub render ($self, $a) {
    my $takes = Amin::AI::Music::Store->takes(30);
    $self->_ui_start('section', title => 'takes');
    if (!@$takes) {
        $self->_label('No takes yet.');
    }
    for my $t (@$takes) {
        my $what = _short(join(' · ', grep { length } @$t{qw(style prompt)}), 120)
                 || (length $t->{lyrics} ? 'lyrics' : 'track');
        $self->_ui_start('card');
        $self->_ui_start('hstack');
        $self->_badge('♪');
        $self->_label(_when($t->{time}) . ' · ' . $t->{model});
        $self->_get_form('/', sub { $self->_button('reuse') }, take => $t->{file});
        $self->_ui_end('hstack');
        $self->_text($what);
        $self->_audio('/audio/' . $t->{file}, $what);
        $self->_ui_end('card');
    }
    $self->_ui_end('section');
    return;
}

sub _when ($t) {
    my @l = localtime($t || 0);
    return sprintf('%04d-%02d-%02d %02d:%02d', $l[5] + 1900, $l[4] + 1, @l[3, 2, 1]);
}

1;
