package Amin::Filter::UI::Element::Player;

# ui:player — one projection filter per ui: kind (axa-plan §4.3).  A neutral
# container: the profile carries the transport and equalizer as children, and
# each target decides how to draw them (a web runtime, a native player view).
# The shared streaming behaviour lives in Amin::Filter::UI::Element::Base.

use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Filter::UI::Element::Base';

sub kind ($self) { 'player' }

1;
