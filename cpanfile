# ═══════════════════════════════════════════════════════════════════════════
# Amin 3.0 CPAN runtime requirements  (DSL parsed by Carton/Module::CPANfile)
# ═══════════════════════════════════════════════════════════════════════════
#
# No version pins — latest stable from CPAN is pulled at bootstrap time.
# To reproduce a known-good install later, `carton install` writes
# cpanfile.snapshot during `mise run bootstrap`; commit that snapshot and
# use `carton install --deployment` to replay it exactly.
#
# Install:
#     mise run bootstrap
# Auto-triggered after `mise install` via [hooks.post_install] in .mise.toml.
#
# Format (DSL):   requires "Module::Name";           # latest, no pin
#                 on develop => sub { requires … };
# Forward-declared for `perl -c` linting (actual subs from Module::CPANfile):
use strict;
use warnings;
use v5.38;
sub requires; sub on; sub recommends; sub suggests; sub conflicts; sub feature;

# ═════ runtime (hard required for bin/amin + perl-lib/ Amin:: namespace) ══
requires 'Class::Tiny';
requires 'IPC::Run';
requires 'XML::SAX';
requires 'XML::SAX::Base';
requires 'XML::NamespaceSupport';
requires 'XML::LibXML';
requires 'XML::LibXML::SAX';
requires 'XML::Filter::XInclude';
requires 'Safe';
requires 'HTTP::Tiny';
requires 'MIME::Base64';
requires 'Digest::BLAKE3';
requires 'Crypt::ML-DSA';

# ═════ develop/test only (needed for `mise run test` / prove) ═════════════
on 'develop' => sub {
    requires 'Test2::Suite';
    requires 'Test2::V0';
    requires 'Perl::Tidy';
    requires 'Path::Tiny';
    requires 'Try::Tiny';
    requires 'Devel::Cover';
    requires 'Carton';
};
