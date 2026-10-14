#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';
use Path::Tiny qw(path);

my $ROOT = path(dirname(__FILE__))->parent->absolute;
my $amin = "$ROOT/bin/amin";
chmod 0755, $amin unless -x $amin;

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
}

my $usage = `$amin 2>&1 || true`;
like($usage, qr/(?:Usage|render|dryrun|app|run)/s, 'CLI shows modes');

my $app = "$ROOT/examples/apps/shop-ui";
ok(rc("$amin app $app") == 0, 'amin app shop-ui → exit 0');
my $render = run("$amin app $app");
like($render, qr/\Q<amin:profile\E/,                     'output has profile root');
like($render, qr/\Q<amin:command name="mkdir"\E/,         'output has mkdir element');
like($render, qr/\Q<amin:command name="echo"\E/,          'output has echo element');

ok(rc("$amin dryrun $app/profile.xml") == 0, 'amin dryrun shop-ui → exit 0');
my $dry = run("$amin dryrun $app/profile.xml");
like($dry,  qr/kind="dryrun"/,  'dryrun result has kind=dryrun');
like($dry,  qr/\Q<amin:stream\E[^>]*channel="argv"/,  'dryrun emits argv stream event');

if ($^O eq 'linux') {
    like($render, qr/\Qname="remove"\E/,  'linux branch runs on linux host');
}

done_testing;
