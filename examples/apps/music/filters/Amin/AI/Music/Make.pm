package Amin::AI::Music::Make;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use parent 'Amin::AI::Music::Element';
use Amin::AXA::UI::Base qw(_short _p);
use Amin::AI::Music::Run;

# <mu:make style= prompt= lyrics= duration= instrumental= csrf=/> — one take,
# painted while it runs.  The page places this inside the live lane: the
# request card and a waiting card go out first, each progress update is a
# ui:swap on the waiting card, and the finished take replaces it with a
# player.  The hop is a separate concrete profile dispatched in this process.

sub render ($self, $a) {
    my %a = %$a;
    my $summary = _short(join(' · ', grep { length } @a{qw(style prompt)}), 160)
                || (length($a{lyrics} // '') ? 'lyrics' : 'track');
    my $mode = ($a{instrumental} // '') =~ /\A(?:1|on|true|yes)\z/i ? 'instrumental' : (length($a{lyrics} // '') ? 'with lyrics' : 'song');

    $self->_swap('append', 'live-lane', sub {
        $self->_ui_start('card', id => 'live-card');
        $self->_ui_start('hstack');
        $self->_badge('♪');
        $self->_label($mode);
        $self->_ui_end('hstack');
        $self->_text($summary);
        $self->_ui_start('text', id => 'live-status');
        $self->_ui_text('waiting for the model');
        $self->_ui_end('text');
        $self->_ui_end('card');
    });

    my $t0   = time;
    my $last = '';
    my $res = eval {
        Amin::AI::Music::Run->make(%a, on_update => sub {
            my $line = Amin::AI::Music::Run->progress_line($_[0], time - $t0);
            return if $line eq $last;
            $last = $line;
            $self->_swap('text', 'live-status', sub { $self->_text($line) });
        });
    };
    if (!$res) { (my $why = $@ // 'unknown error') =~ s/\s+\z//; $res = { err => $why } }

    $self->_swap('replace', 'live-card', sub {
        if ($res->{err}) { $self->_alert($res->{err}); return }
        $self->_ui_start('card');
        $self->_ui_start('hstack');
        $self->_badge('♪');
        $self->_label($res->{model} // 'music');
        $self->_ui_end('hstack');
        $self->_text($summary);
        $self->_player($res->{audio}, $summary);
        $self->_ui_end('card');
    });
    return;
}

1;
