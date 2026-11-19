package Amin::Filter::UI::Element::Swap;

# ui:swap — a streaming update fragment: its own subtree is a complete ui:
# fragment addressed at another element (for="ID") and applied with a mode
# (replace default, append, prepend, text, text-append).  The element carries
# no identity of its own; each target decides how to apply it — HTML renders
# the subtree inside an inert <template> and lets the page's swap runtime
# apply it to the target element, while source targets simply render the
# subtree inline.  The shared streaming behaviour lives in
# Amin::Filter::UI::Element::Base.

use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Filter::UI::Element::Base';

sub kind ($self) { 'swap' }

1;
