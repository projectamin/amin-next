#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';
use Path::Tiny qw(path);

my $ROOT = path(dirname(__FILE__))->parent->absolute;
my $amin = "$ROOT/bin/amin";
chmod 0755, $amin unless -x $amin;

# Run the CLI under THIS interpreter — the shebang resolves via PATH and can
# pick up the system perl (older than the module's v5.38 floor).
my $CLI = "$^X -I\"$ROOT/perl-lib\" -I\"$ROOT/local/lib/perl5\" $amin";
sub run ($cmd) { scalar `$cmd 2>/dev/null` }
sub rc  ($cmd) { system($cmd . ' 2>/dev/null >/dev/null'); $? >> 8 }

my @libs;
$ROOT->child('perl-lib')->visit(sub {
    my ($p) = @_;
    push @libs, "$p" if $p =~ /\.pm$/ && $p->is_file;
}, { recurse => 1 });

for my $f (sort @libs) {
    my $out = `$^X -I ${\$ROOT->child('perl-lib')} -I /tmp/amin-local/lib/perl5 -c "$f" 2>&1`;
    like($out, qr/syntax OK/, "compile cleanly: $f");
}my $usage = `$^X -I "$ROOT/perl-lib" -I "$ROOT/local/lib/perl5" $amin 2>&1 || true`;
like($usage, qr/(?:Usage|render|dryrun|app|run)/s, 'CLI shows modes');

my $app = "$ROOT/examples/apps/shop-ui";
ok(rc("$CLI app $app") == 0, 'amin app shop-ui → exit 0');
my $render = run("$CLI app $app" );
like($render, qr/\Q<amin:profile\E/,                     'output has profile root');
like($render, qr/\Q<amin:command name="mkdir"\E/,         'output has mkdir element');
like($render, qr/\Q<amin:command name="echo"\E/,          'output has echo element');

ok(rc("$CLI dryrun $app/profile.xml") == 0, 'amin dryrun shop-ui → exit 0');
my $dry = run("$CLI dryrun $app/profile.xml");
like($dry,  qr/kind="dryrun"/,  'dryrun result has kind=dryrun');
like($dry,  qr/\Q<amin:stream\E[^>]*channel="argv"/,  'dryrun emits argv stream event');

if ($^O eq 'linux') {
    like($render, qr/\Qname="remove"\E/,  'linux branch runs on linux host');
}

done_testing;
