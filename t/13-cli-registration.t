# t/13-cli-registration.t — CLI --with-* filter hooks (DI-2 extensibility: third-party
# filters installed via command line, without Amin source fork, without modifying
# the profile XML).
#
# Three assertion groups:
#   1. --with-begin loads a fictional Corp filter package from a tempdir via --inc.
#      The filter writes a marker file on every start_element.  After amin render
#      we verify >0 markers present + first is 'profile' start_element.
#   2. --with-begin + --with-middle: order of first 2 trace events for the same
#      LocalName is begin-then-middle (register() push ordering contract, DI-2).
#   3. Fail-closed: non-existent --with-end filter class exits non-zero with a
#      clear "Cannot load --with-end filter ..." error.
use v5.38; use warnings; use utf8;
use Test2::V0;
use Path::Tiny qw(path);
use File::Basename qw(dirname);
use File::Temp;
use File::Spec;

my $ROOT = path(dirname(__FILE__))->parent->absolute;
my $amin = "$ROOT/bin/amin";

# ── Tempdir setup (cleaned automatically on scope exit)
my $tmpdir = File::Temp->newdir(CLEANUP => 1, TMPDIR => 1);
my $T = path("$tmpdir");
$T->child('lib/CorpX/Policy')->mkpath;
my $trace = $T->child('trace.txt')->stringify;

# Three fictional filter packages, all inheriting XML::SAX::Base + Class::Tiny
# (matches t/05 in-test CorpExt::Policy::Dummy filter shape exactly — so the
# CLI filter install path is API-compatible with the public register() API).
for my $pos (qw(Begin Middle End)) {
    $T->child("lib/CorpX/Policy/${pos}Seen.pm")->spew_utf8(<<"PKG");
package CorpX::Policy::${pos}Seen;
use v5.38; use warnings;
use parent 'XML::SAX::Base';
use Class::Tiny qw(Handler Log Mode Name Element);
my \$TRACE_FILE = '$trace';
sub _append_trace {
    my \$line = shift;
    open(my \$fh, ">>", \$TRACE_FILE) or die "open \$TRACE_FILE: \$!";
    print {\$fh} lc('$pos') . "|" . (\$line // '') . "\\n";
    close \$fh;
}
sub start_document { my \$s = shift; \$s->SUPER::start_document(\@_) }
sub start_element  {
    my (\$s, \$e) = \@_;
    _append_trace(\$e->{LocalName} // '');
    \$s->SUPER::start_element(\$e);
}
sub end_element     { my (\$s, \$e) = \@_; \$s->SUPER::end_element(\$e) }
sub characters  { my (\$s, \$d) = \@_; \$s->SUPER::characters(\$d) }
sub end_document { my \$s = shift; \$s->SUPER::end_document(\@_) }
1;
PKG
}

my $profile = $T->child('profile.xml');
$profile->spew_utf8(<<'XML');
<?xml version="1.0" encoding="UTF-8"?>
<amin:profile xmlns:amin="http://projectamin.org/ns/2026/"
              xmlns:map="http://projectamin.org/ns/map/1">
  <amin:rc kind="machine" id="m0"/>
  <map:host hostname="db0"/>
</amin:profile>
XML

sub amin_run {
    my @args = @_;
    my @cmd = ($^X, "-I", "$ROOT/perl-lib", "-I", "$T/lib",
               $amin, @args, 'render', "$profile", '--no-stream');
    my $out = qx/@cmd 2>&1/;
    return ($? >> 8, $out // '');
}

# ── 1. --with-begin loads corp filter → it actually saw SAX events
{
    unlink $trace if -f $trace;
    my ($exit, $out) = amin_run(
        '--inc' => "$T/lib",
        '--with-begin' => 'CorpX::Policy::BeginSeen',
    );
    is($exit, 0, "CLI --with-begin exits 0")
        or diag "exit=$exit; stderr tail: " . substr($out, -500);
    my @lines = -f $trace ? split /\n/, path($trace)->slurp : ();
    ok(scalar @lines >= 2, '--with-begin: corp filter saw SAX events (lines=' .
       scalar(@lines) . ')');
    like(join("\n", @lines), qr/^begin\|profile/m,
         '--with-begin: trace begins with "begin|profile" (profile start_element)');
}

# ── 2. --with-begin + --with-middle → ordering begin BEFORE middle for the
#      same LocalName (register() push semantics).
{
    unlink $trace if -f $trace;
    my ($exit, $out) = amin_run(
        '--inc' => "$T/lib",
        '--with-begin'  => 'CorpX::Policy::BeginSeen',
        '--with-middle' => 'CorpX::Policy::MiddleSeen',
    );
    is($exit, 0, "CLI --with-begin + --with-middle exits 0")
        or diag "exit=$exit; stderr tail: " . substr($out, -500);
    my @lines = -f $trace ? split /\n/, path($trace)->slurp : ();
    # Walk pairs: find first two lines sharing same local name suffix, compare
    # their position prefixes.
    my %first_pos_for_label;
    my ($first_label, @two_positions);
    for my $l (@lines) {
        my ($pos, $label) = split /\|/, $l, 2;
        next unless defined $label && length $label;
        if (!defined $first_label) {
            $first_label = $label;
            @two_positions = ($pos);
        } elsif ($label eq $first_label) {
            push @two_positions, $pos;
            last;
        } else {
            $first_label = $label;
            @two_positions = ($pos);
        }
    }
    is($two_positions[0], 'begin',  'ordering: first position fires begin');
    is($two_positions[1], 'middle', 'ordering: second position fires middle (push contract)');
}

# ── 3. Fail-closed: non-existent class must NOT proceed silently to parse.
{
    my ($exit, $out) = amin_run(
        '--inc' => "$T/lib",
        '--with-end' => 'CorpX::Policy::NoSuchFilterClassXYZ99',
    );
    isnt($exit, 0, 'non-existent --with-end class exits NON-ZERO (fail-closed)');
    like($out, qr/Cannot load --with-end filter/i,
         'error message names the position + failed class clearly');
}

done_testing();
