package Amin::Filter::UI::Element::Sparkline;

# ui:sparkline — one projection filter per ui: kind (axa-plan §4.3).  The
# shared streaming behaviour lives in Amin::Filter::UI::Element::Base.

use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Filter::UI::Element::Base';

sub kind ($self) { 'sparkline' }

1;
