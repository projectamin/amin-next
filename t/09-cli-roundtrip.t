#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use Path::Tiny qw(path);
use lib dirname(__FILE__) . '/../perl-lib';

my $ROOT = path(dirname(__FILE__))->parent->absolute;
my $amin = "$ROOT/bin/amin";
chmod 0755, $amin unless -x $amin;
$ENV{PERL5LIB} = join ':', "$ROOT/perl-lib",
    (grep length, map "$_/lib/perl5", grep defined, $ENV{LOCAL_LIBDIR} // ());

sub run_amin (@cmd) {
    open(my $p, '-|', @cmd) or die "popen $cmd[0]: $!";
    local $/; my $out = <$p>; close $p;
    (rc => $? >> 8, out => $out // '');
}

my %r;
%r = do { my $out = `$amin 2>&1`; (rc => $? >> 8, out => $out // '') };
isnt($r{rc}, 0, 'no args → non-zero exit');
like($r{out} // '', qr/Usage:/, 'no args → prints Usage message (combined stream)');

%r = run_amin($amin, 'render', '/this/path/does/not/exist.xml');
isnt($r{rc}, 0, 'missing path → non-zero exit');

%r = run_amin($amin, 'bogus-mode', __FILE__);
isnt($r{rc}, 0, 'unknown mode → non-zero exit');

my $tmpd = Path::Tiny->tempdir(CLEANUP => 1);
%r = run_amin($amin, 'app', "$tmpd");
isnt($r{rc}, 0, 'app dir without profile.xml → non-zero exit');
$tmpd->child('profile.xml')->spew_utf8(<<'XML');
<?xml version="1.0" encoding="UTF-8"?>
<amin:profile xmlns:amin="http://projectamin.org/ns/2026/">
  <amin:command name="echo"><amin:param name="text">ok</amin:param></amin:command>
</amin:profile>
XML
%r = run_amin($amin, 'app', "$tmpd");
is($r{rc}, 0, 'app dir with profile.xml → exit 0');
like($r{out}, qr{<amin:profile\b}, 'app mode renders profile root');
like($r{out}, qr{kind="dryrun"},  'app mode defaults internally to render/dryrun kind');

my $xml = "$tmpd/p.xml"; path($xml)->spew_utf8(<<'XML');
<?xml version="1.0" encoding="UTF-8"?><amin:profile xmlns:amin="http://projectamin.org/ns/2026/" />
XML
%r = run_amin($amin, 'render', $xml);
is($r{rc}, 0, 'render → exit 0');
like($r{out}, qr/^<\?xml/s, 'render stdout begins with XML prolog');

%r = run_amin($amin, 'dryrun', $tmpd->child('profile.xml').'');
is($r{rc}, 0, 'dryrun → exit 0');
like($r{out}, qr{<amin:stream amin:channel="argv">}, 'dryrun has argv stream');

%r = do {
    my $out = `$amin run "$tmpd/profile.xml" 2>&1`;
    (rc => $? >> 8, out => $out);
};
is($r{rc}, 0, 'run (streaming default) → exit 0');
like($r{out}, qr{<amin:status\b[^>]*amin:kind="success"},
     'run produces final success status element (default streaming)');
my $prologs =()= $r{out} =~ /^<\?xml /gms;
cmp_ok($prologs, '>=', 1, 'streaming default emits XML (at least one prolog)');

done_testing;
