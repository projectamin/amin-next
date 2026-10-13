package Amin::Util::DahutQuotes;
use v5.38; use warnings; use utf8; use experimental 'signatures';

use Class::Tiny;

my @QUOTES = (
    'Dahut dwells in the mountain!',
    'Dahut stirs in the deep...',
    'The ancient one rises from the darkness!',
    'Beware the wrath of Dahut!',
    'Dahut calls to the worthy!',
    'From the depths, Dahut watches...',
    'Dahut has awakened!',
    'The mountain trembles at Dahut\'s name!',
    'Dahut sees all from beneath the stone!',
    'None shall escape the grasp of Dahut!',
    'Dahut hungers for the unwary!',
    'In the halls of stone, Dahut reigns supreme!',
    'The legend of Dahut grows stronger!',
    'Dahut demands tribute!',
    'Heed the call of Dahut!',
    'The depths whisper the name of Dahut!',
    'Dahut claims this realm!',
    'Long live the glory of Dahut!',
    'Dahut lurks beneath the adamantine!',
    'The shadows belong to Dahut!',
);

sub random_quote ($self = undef) {
    my $idx = int(rand(scalar @QUOTES));
    return $QUOTES[$idx];
}

sub all_quotes ($self = undef) {
    return @QUOTES;
}

sub quote_count ($self = undef) {
    return scalar @QUOTES;
}

1;
