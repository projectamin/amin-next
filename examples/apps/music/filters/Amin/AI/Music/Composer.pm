package Amin::AI::Music::Composer;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use parent 'Amin::AI::Music::Element';
use Amin::AXA::UI::Base qw(_p);

# <mu:composer style= prompt= lyrics= duration= instrumental= csrf=/> — the
# one form.  Style is the genre/mood line, the description is the brief, lyrics
# are optional multi-line text with [verse]/[chorus] markers.  The attributes
# are a draft (a reused take, or what was typed before a refusal).
sub render ($self, $a) {
    $self->_ui_start('card');
    $self->_form('music.make', sub {
        $self->_row('Style', _p('style'), $a->{style},
            placeholder => 'lo-fi, warm tape hiss, 78 bpm, female vocal');
        $self->_row('Description', _p('prompt'), $a->{prompt},
            placeholder => 'rain on a tin roof, late at night');
        $self->_row('Lyrics', _p('lyrics'), $a->{lyrics}, type => 'multiline', lines => 10,
            placeholder => "[verse]\n…\n[chorus]\n…");
        $self->_ui_start('hstack');
        $self->_label('Seconds');
        $self->_field(_p('duration'), $a->{duration}, type => 'number', min => 5, max => 600,
            placeholder => 'auto');
        $self->_field(_p('instrumental'), '1', type => 'toggle');
        $self->_label('instrumental');
        $self->_button('make');
        $self->_ui_end('hstack');
    });
    $self->_ui_end('card');
    return;
}


1;
