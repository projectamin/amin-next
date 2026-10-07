# ═══════════════════════════════════════════════════════════════════════════
# Amin 3.0 CPAN runtime requirements  (DSL parsed by Carton/Module::CPANfile)
# ═══════════════════════════════════════════════════════════════════════════
#
# Managed by mise: `[tools.perl]` ships the cpanm and prove SHIMS; PERL5LIB is
# pre-set by [env] line to $PWD/local/lib/perl5.  To install: `mise run bootstrap`
# (uses cpanm --cpanfile ./cpanfile --installdeps . for reproducibility).
#
# Format (DSL):   requires "Module::Name",  "VERSION";
#                 on develop => sub { requires "Dev::Only", "VERSION" };
# Forward-declared for `perl -c` linting (actual subs from Module::CPANfile):
use strict;
use warnings;
use v5.38;
sub requires; sub on; sub recommends; sub suggests; sub conflicts; sub feature;

# ═════ runtime (hard required for bin/amin + perl-lib/ Amin:: namespace) ══
requires 'Class::Tiny',           '1.008';
requires 'IPC::Run',              '20231003.0';
requires 'XML::SAX',              '1.02';
requires 'XML::SAX::Base',        '1.09';
requires 'XML::NamespaceSupport', '1.12';
requires 'XML::LibXML',           '2.0210';
requires 'XML::LibXML::SAX',      '2.0210';
requires 'XML::Filter::XInclude', '1.19';
requires 'Safe',                  '2.44';
requires 'Opcode',                '1.66';
requires 'HTTP::Tiny',            '0.088';
requires 'Getopt::Long',          '2.54';

# ═════ develop/test only (needed for `mise run test` / prove) ═════════════
on 'develop' => sub {
    requires 'Test2::Suite',        '0.000159';
    requires 'Test2::V0',           '0.000159';
    requires 'Perl::Tidy',          '20240903';
    requires 'Path::Tiny',          '0.144';
    requires 'Try::Tiny',           '0.31';
    requires 'Devel::Cover',        '1.40';
    requires 'Carton',              'v1.0.35';
};
