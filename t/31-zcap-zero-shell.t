use v5.38; use warnings; use strict; use utf8;
use Test2::V0;

use lib 'perl-lib';

# ── AC-Z6 Rubric: Zero-shell for ZCap.pm (same algorithm as t/26 NetFabric AC-8) ──
# Comment-aware grep across ZCap.pm for executable shell patterns:
#   - system(  ... perl core system()
#   - /bin/sh ... literal shell interpreter
#   - qx(      ... perl core qx// backtick operator
#   - `...`    ... literal backtick pairs (count pairs)
# Strip comments before matching so "never use system(...)" docs don't match.
#
# Pass threshold: hits ≤ 3 (Score ≥ 4/5 perfect).  PERFECT score 5/5 = exactly 0 hits.

sub strip_perl_comments ($src) {
    my @lines = split /\n/, $src;
    my @stripped;
    for my $line (@lines) {
        # Strip Rust/Python-style # line comments; but preserve Perl PACKAGE attrs
        # like use constant etc (those have # in code; but # line comment = line starts with or whitespace then #)
        # Actually for Perl: line comments are any # not inside string.
        # Simplification for Rubric: if line matches ^\s*# → entire line strip;
        # otherwise strip trailing # that isn't inside a "..." balanced string.
        if ($line =~ /^\s*#/) { push @stripped, ''; next; }
        # Conservative: remove trailing # comments when no unclosed quotes.
        my $in_sq = 0; my $in_dq = 0; my $cut_at = undef;
        my @chars = split //, $line;
        for my $i (0..$#chars) {
            my $ch = $chars[$i];
            if ($ch eq "'" && !$in_dq) { $in_sq = !$in_sq; next; }
            if ($ch eq '"' && !$in_sq) { $in_dq = !$in_dq; next; }
            if ($ch eq '#' && !$in_sq && !$in_dq) { $cut_at = $i; last; }
        }
        if (defined $cut_at) { $line = substr($line, 0, $cut_at); }
        push @stripped, $line;
    }
    return join("\n", @stripped);
}

# Read ZCap.pm source
{
    my $zcap_path = __FILE__;
    $zcap_path =~ s{t/[^/]+$}{perl-lib/Amin/Auth/ZCap.pm};
    ok(-f $zcap_path, "t31: ZCap.pm exists at $zcap_path");
    open(my $fh, '<', $zcap_path) or die "open $zcap_path: $!";
    local $/; my $src = <$fh>; close $fh;

    my $stripped = strip_perl_comments($src);
    my @hits;
    # Pattern 1: perl system( call
    while ($stripped =~ /\bsystem\s*\(/g) { push @hits, "system() at pos $-[0]"; }
    # Pattern 2: literal /bin/sh
    while ($stripped =~ m{/bin/sh\b}g) { push @hits, "/bin/sh at pos $-[0]"; }
    # Pattern 3: perl qx( operator
    while ($stripped =~ /\bqx\s*\(/g) { push @hits, "qx() at pos $-[0]"; }
    # Pattern 4: backtick pairs (count balanced backtick delimiters / 2 non-overlapping)
    my $bt_count = () = $stripped =~ /`/g;
    if ($bt_count >= 2) { push @hits, "backtick pair x " . int($bt_count/2); }

    my $total_hits = scalar @hits;
    # Score: 0 hits = 5/5 perfect; 1 = 4/5 pass; 2 = 3/5 fail; ≥3 FAIL big
    my $score = ($total_hits == 0) ? 5
              : ($total_hits == 1) ? 4
              : ($total_hits == 2) ? 3
              : ($total_hits == 3) ? 2
              : 1;
    diag("t31 AC-Z6 Zero-shell: hits=$total_hits score=$score/5 threshold≥4");
    for my $h (@hits) { diag("  HIT: $h"); }

    # PASS criterion
    ok($total_hits == 0,
        "t31 AC-Z6: PERFECT 5/5 zero shell; total executable shell grep hits=$total_hits (Profile-as-Contract closed-world: no shell expansion \$PATH \${VAR} globs tilde literal-only profile)");
    cmp_ok($score, '>=', 4,
        "t31 AC-Z6: score=$score/5 ≥ 4/5 minimum pass threshold for Rubric zero-shell");
    is($bt_count, 0,
        "t31 AC-Z6: backtick count=0 (no shell command capture via `` operator; zero leak of signed zcap scope to shell via \$()/``)");
}

done_testing;
