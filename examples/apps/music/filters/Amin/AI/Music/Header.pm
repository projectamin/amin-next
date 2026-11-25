package Amin::AI::Music::Header;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use parent 'Amin::AI::Music::Element';
use Amin::AI::Music::Store;

# <mu:header/> — title, provider, key state and the selected music model.  Only
# whether a key is set is read; the key itself never is.
sub render ($self, $a) {
    my $p = Amin::AI::Music::Store->provider;
    my $cat = Amin::AI::Music::Store->catalog;
    my $n = scalar @{ $cat->{models} // [] };
    $self->_ui_start('toolbar');
    $self->_ui_start('hstack');
    $self->_badge('♪');
    $self->_text('music');
    $self->_ui_end('hstack');
    $self->_ui_start('hstack');
    $self->_get_form('/settings', sub { $self->_button('API') });
    $self->_label(length $p->{id} ? $p->{id} . ($p->{key_set} ? ' · key set' : ' · no key') : 'no provider');
    $self->_label(length $p->{music} ? $p->{music}
        : $n ? ($n == 1 ? '1 model' : "$n models")
        : 'no music model');
    $self->_ui_end('hstack');
    $self->_ui_end('toolbar');
    return;
}

1;
