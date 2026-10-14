package Amin::AI;
use v5.38; use warnings; use utf8; use parent 'Exporter';

use constant AI_NS => 'http://projectamin.org/ns/ai/1';

our @EXPORT_OK = qw(AI_NS);
our %EXPORT_TAGS = (all => \@EXPORT_OK);

1;
