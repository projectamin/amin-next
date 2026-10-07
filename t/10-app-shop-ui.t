#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use Path::Tiny qw(path);
use lib dirname(__FILE__) . '/../perl-lib';

my $APP  = path(dirname(__FILE__))->parent->child('examples/apps/shop-ui');
my $TOML = "$APP/app.toml";
my $XML  = "$APP/profile.xml";
my $ROOT = path(dirname(__FILE__))->parent->absolute;
my $amin = "$ROOT/bin/amin";

$ENV{PERL5LIB} = join ':', "$ROOT/perl-lib", "/tmp/amin-local/lib/perl5";

ok(-f $XML,  'shop-ui profile.xml exists');
ok(-f $TOML, 'shop-ui app.toml exists');
ok(-d $APP,  'shop-ui is a bundle directory');

sub run_bin {
    open(my $p, '-|', @_) or die "popen: $!";
    local $/; my $o = <$p>; close $p;
    ($o, $? >> 8);
}
my ($out, $rc) = run_bin($amin, 'render', $XML);
is($rc, 0, 'amin render shop-ui → exit 0');
ok(length($out) > 1000, 'rendered output substantial (not stub)');

use XML::LibXML;
my $dom = eval { XML::LibXML->load_xml(string => $out) };
is($@, '', 'rendered output is well-formed XML (parseable without errors)');
is(ref($dom), 'XML::LibXML::Document', 'rendered output produced XML::LibXML::Document DOM');

my $nr_remove = () = $out =~ /<amin:command[^>]*name="remove"/g;
my $nr_mkdir  = () = $out =~ /<amin:command[^>]*name="mkdir"/g;
my $nr_echo   = () = $out =~ /<amin:command[^>]*name="echo"/g;
cmp_ok($nr_remove, '>=', 1, 'at least 1 <amin:command name=remove> in rendered output');
cmp_ok($nr_mkdir,  '>=', 1, 'at least 1 <amin:command name=mkdir>  in rendered output');
cmp_ok($nr_echo,   '>=', 3, 'at least 3 <amin:command name=echo>   in rendered output');

my $nr_results =()= $out =~ /<amin:result/g;
my $nr_status  =()= $out =~ /<amin:status/g;
cmp_ok($nr_results, '>=', 5, 'each bundled command emitted a result block');
is($nr_results, $nr_status, 'each <result> has exactly 1 matching <status> child pair count-wise');

my @status_blocks = ($out =~ m{<amin:status\b([^>]*)>(.*?)</amin:status>}gs);
my $sc = 0;
for my $i (0..$#status_blocks) {
    next unless $i % 2 == 1;
    my $content = $status_blocks[$i];
    $content =~ s/\s+//g;
    is($content, '', "status block #" . (++$sc) . ": textContent empty (metadata-only)");
}
cmp_ok($sc, '>=', 5, 'found >= 5 status blocks to validate (one per command)');

my ($root) = $dom->documentElement;
is($root->namespaceURI, 'http://projectamin.org/ns/2026/', 'root NS correct');
is($root->localName,      'profile',                         'root localName correct');

my $toml = path($TOML)->slurp_utf8;
like($toml, qr/id\s*=\s*"io\.projectamin\.apps\.shop-ui"/, 'app.toml id field present');
like($toml, qr/version\s*=\s*"0\.1\.0[^"]*"/,              'app.toml version field present (0.1.0 + build suffix)');
like($toml, qr/\[schedule\]/,                                'app.toml has [schedule] table');
like($toml, qr/\[storage\]/,                                 'app.toml has [storage] table');
like($toml, qr/^tier\s*=/m,                                  'app.toml has a top-level tier = "…" declaration');

done_testing;
