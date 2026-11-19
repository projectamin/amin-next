#!/usr/bin/env perl
# t/77-axa-file-route.t — `file=` routes answer with bytes, not a page.
#
# A route that declares `file=` is a byte route: the template expands from the
# environment, captured segments fill `:name` (one name-safe segment each), the
# resolved path must stay inside the template's directory, and the response is
# the file with Content-Type plus byte-range support so a browser can stream
# and seek it.  This is what lets an app hand a browser an artifact (audio,
# image) without a second server.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::AXA::App;
use Amin::AXA::HTTP;

my $dir = path(tempdir(CLEANUP => 1));
my $media = $dir->child('media');
$media->mkpath;
$media->child('take.mp3')->spew_raw('ABCDEFGHIJ');
$media->child('take.bin')->spew_raw('bin-bytes');
mkdir $dir->child('inside');
symlink "$dir/inside", "$media/escape" or die "symlink: $!";

$ENV{T77_MEDIA} = "$media";
$dir->child('axa.xml')->spew_utf8(<<'XML');
<axa:app xmlns:axa="http://projectamin.org/ns/axa/1" id="io.projectamin.test.file">
  <axa:route path="/media/:name" method="GET" file="$T77_MEDIA/:name" type="audio/mpeg"/>
  <axa:route path="/plain" method="GET" type="text/plain"><text>x</text></axa:route>
</axa:app>
XML

my $app = Amin::AXA::App->load("$dir");
my ($route) = grep { $_->{path} eq '/media/:name' } @{ $app->{routes} };
ok($route, 'the file route loads');
is($route->{file}, '$T77_MEDIA/:name', 'the file template is kept as declared');

sub get ($name, $hdr = {}) {
    my ($r, $params) = $app->get_route("/media/$name");
    return undef unless $r;
    return Amin::AXA::HTTP->serve_file($r, $params, { header => $hdr, method => 'GET' });
}

my $res = get('take.mp3');
is($res->[0], 200, 'a captured file is served 200');
is($res->[2], 'ABCDEFGHIJ', 'the body is the file bytes');
my %h = @{ $res->[1] };
is($h{'Content-Type'}, 'audio/mpeg', 'route type covers an unknown-but-declared type');
is($h{'Content-Length'} // length($res->[2]), 10, 'the full byte count is sent');
is($h{'Accept-Ranges'}, 'bytes', 'the response advertises ranges');

$res = get('take.bin');
%h = @{ $res->[1] };
is($h{'Content-Type'}, 'audio/mpeg', 'an unmapped extension falls back to the route type');

$res = get('take.mp3', { range => 'bytes=2-5' });
is($res->[0], 206, 'a byte range answers 206');
is($res->[2], 'CDEF', 'the range slice is exact');
%h = @{ $res->[1] };
is($h{'Content-Range'}, 'bytes 2-5/10', 'Content-Range names the slice');

$res = get('take.mp3', { range => 'bytes=-4' });
is($res->[2], 'GHIJ', 'a suffix range reads from the end');

$res = get('take.mp3', { range => 'bytes=20-30' });
is($res->[0], 416, 'an unsatisfiable range answers 416');

for my $bad (qw(.. .hidden take.mp3.bak), 'a/b') {
    my $r = eval { get($bad) };
    if (!$r) { pass("no route match for $bad"); next }
    is($r->[0], 404, "traversal/odd name is refused ($bad)");
}

$res = get('escape');
is($res->[0], 404, 'a symlink that leaves the directory is refused');

delete $ENV{T77_MEDIA};
$res = get('take.mp3');
is($res->[0], 404, 'an unresolved environment placeholder is refused');

done_testing;
