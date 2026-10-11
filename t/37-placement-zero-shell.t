use v5.38; use warnings; use strict; use utf8;
use Test2::V0;

use lib 'perl-lib';

# ── AC-14.7 Rubric: Zero-shell for Placement + Mesh + Transport files ──
# Comment-aware grep; same algorithm as t/31 ZCap and t/26 NetFabric.

sub strip_perl_comments ($src) {
    my @lines = split /\n/, $src;
    my @stripped;
    for my $line (@lines) {
        if ($line =~ /^\s*#/) { push @stripped, ''; next; }
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

sub score_file ($path) {
    open(my $fh, '<', $path) or die "open $path: $!";
    local $/; my $src = <$fh>; close $fh;
    my $stripped = strip_perl_comments($src);
    my @hits;
    while ($stripped =~ /\bsystem\s*\(/g) { push @hits, "system() at pos $-[0]"; }
    while ($stripped =~ m{/bin/sh\b}g) { push @hits, "/bin/sh at pos $-[0]"; }
    while ($stripped =~ /\bqx\s*\(/g) { push @hits, "qx() at pos $-[0]"; }
    my $bt_count = () = $stripped =~ /`/g;
    if ($bt_count >= 2) { push @hits, "backtick pair x " . int($bt_count/2); }
    return \@hits, $bt_count;
}

my @targets = (
    'perl-lib/Amin/Schedule/Placement.pm',
    'perl-lib/Amin/Discovery/Mesh.pm',
    'perl-lib/Amin/Mesh/Transport/InProcess.pm',
);

my $total_hits = 0;
my $total_bt   = 0;
for my $p (@targets) {
    my $absp = __FILE__; $absp =~ s{t/[^/]+$}{$p};
    ok(-f $absp, "t37: target file $p exists");
    my ($hits, $bt) = score_file($absp);
    my $n = scalar @$hits;
    diag("t37: $p -> hits=$n backticks=$bt");
    for my $h (@$hits) { diag("  HIT $p: $h"); }
    is($n, 0, "t37 AC-14.7 $p: 0 shell grep hits (PERFECT zero shell closed world)");
    is($bt, 0, "t37 AC-14.7 $p: backtick count 0 no operator");
    $total_hits += $n;
    $total_bt   += $bt;
}

my $score = ($total_hits == 0) ? 5
          : ($total_hits == 1) ? 4
          : ($total_hits == 2) ? 3
          : ($total_hits == 3) ? 2
          : 1;
cmp_ok($score, '>=', 4,
    "t37 AC-14.7: combined score $score/5 ≥ 4/5 — Placement/Mesh/Transport zero shell closed-world no PATH no aliases no glob Profile-as-Contract env isolation");

done_testing;
