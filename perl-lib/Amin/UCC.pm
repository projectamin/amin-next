package Amin::UCC;
use v5.38; use warnings; use utf8; use parent 'Exporter';

use constant UCC_NS => 'http://projectamin.org/ns/ucc/1';

our @EXPORT_OK   = qw(UCC_NS);
our %EXPORT_TAGS = (all => \@EXPORT_OK);

1;
