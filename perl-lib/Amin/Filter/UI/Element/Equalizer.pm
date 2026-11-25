package Amin::Filter::UI::Element::Equalizer;

# ui:equalizer — a neutral meter child of ui:player (bars=N mode=bars|wave).
# The target owns the implementation: HTML draws it on a canvas from a Web
# Audio AnalyserNode, the native targets emit their own bar view.  The shared
# streaming behaviour lives in Amin::Filter::UI::Element::Base.

use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Filter::UI::Element::Base';

sub kind ($self) { 'equalizer' }

1;
