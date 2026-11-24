package Amin::AI::Music::Settings;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use parent 'Amin::AI::Music::Element';
use Amin::AI::Music::Store;
use Amin::AXA::UI::Base qw(_p);

# <mu:settings csrf= provider= api= base= music=/> — the provider card.  The
# attributes are the draft the person typed (kept across a failed save) and
# fall back to the saved provider.  The key is never an input here and is never
# rendered.
sub render ($self, $a) {
    my $p = Amin::AI::Music::Store->provider;
    my %d = map { $_ => (length($a->{$_} // '') ? $a->{$_} : $p->{$_}) } qw(api base music);
    $d{provider} = length($a->{provider} // '') ? $a->{provider} : $p->{id};

    $self->_ui_start('card');
    $self->_ui_start('toolbar');
    $self->_text('API');
    $self->_get_form('/', sub { $self->_button('close') });
    $self->_ui_end('toolbar');
    $self->_form('settings.save', sub {
        $self->_row('Provider', _p('provider'), $d{provider}, placeholder => 'provider id');
        $self->_row('API', _p('api'), $d{api}, placeholder => 'openai, deepinfra, zai, stub');
        $self->_row('Base', _p('base'), $d{base}, placeholder => 'https://… (optional for stub)');
        $self->_row('Music model', _p('music'), $d{music}, placeholder => 'upstream music model');
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
    $self->_ui_end('card');
    return;
}


1;
