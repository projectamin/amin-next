package Amin::AI::Music::Settings;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use parent 'Amin::AI::Music::Element';
use Amin::AI::Music::Store;
use Amin::AXA::UI::Base qw(_p);

# <mu:settings provider= csrf=/> — the provider card: pick a known hop, add its
# key.  api/base come from the preset; models come from discovery, so they are
# chosen in the composer, not typed here.  The key is never an input value and
# is never rendered.
sub render ($self, $a) {
    my $p   = Amin::AI::Music::Store->provider;
    my $sel = length($a->{provider} // '') ? $a->{provider} : $p->{id};

    my @choices = map { [ $_->{id}, $_->{label} ] } @{ Amin::AI::Music::Store->presets };
    push @choices, [ $sel, $sel ] if length $sel && !grep { $_->[0] eq $sel } @choices;

    my $cat = Amin::AI::Music::Store->catalog;
    my $n   = scalar @{ $cat->{models} // [] };

    $self->_ui_start('card');
    $self->_ui_start('toolbar');
    $self->_text('API');
    $self->_get_form('/', sub { $self->_button('close') });
    $self->_ui_end('toolbar');
    $self->_form('settings.save', sub {
        $self->_ui_start('vstack');
        $self->_label('Provider');
        $self->_select(_p('provider'), $sel, \@choices);
        $self->_ui_end('vstack');
        $self->_row('Key', _p('key'), '', type => 'secure',
            placeholder => $p->{key_set} ? 'leave blank to keep' : 'API key');
        $self->_ui_start('hstack');
        $self->_field(_p('remove_key'), '1', type => 'toggle');
        $self->_label('delete stored key');
        $self->_button('save');
        $self->_ui_end('hstack');
    });
    $self->_label($p->{key_set}
        ? 'A key is set in ~/.amin-music/provider.xml and is never rendered.'
        : 'No key is set.');
    if (length $p->{music}) {
        $self->_label("Music model: $p->{music}");
    }
    elsif ($n) {
        $self->_label("$n music model" . ($n == 1 ? '' : 's') . ' discovered — pick one in the composer.');
    }
    else {
        $self->_label('No music models discovered yet — save a key to pull them.');
    }
    $self->_ui_end('card');
    return;
}


1;
