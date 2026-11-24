package Amin::AI::Music::Effect;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use parent 'Amin::AXA::UI::Effect';

sub app_ns     ($self) { 'urn:projectamin:app:music' }
sub app_prefix ($self) { 'mu' }

1;
