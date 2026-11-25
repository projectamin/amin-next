package Amin::Filter::UI::Element::Visualizer;

# ui:visualizer — a curated animated field (mode=plasma|ripple|vortex).
# The target owns the implementation: HTML runs one pooled WebGL program,
# the native targets emit their own field view.  The shared streaming
# behaviour lives in Amin::Filter::UI::Element::Base.

use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Filter::UI::Element::Base';

sub kind ($self) { 'visualizer' }

1;
