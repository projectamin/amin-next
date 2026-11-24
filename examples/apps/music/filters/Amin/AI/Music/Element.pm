package Amin::AI::Music::Element;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use parent 'Amin::AXA::UI::Element';

use constant MU_NS => 'urn:projectamin:app:music';
sub app_ns     ($self) { MU_NS }
sub app_prefix ($self) { 'mu' }

1;
