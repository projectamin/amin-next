#!/usr/bin/env perl
# t/62-ui-html.t — `--os=html`: the ui: IR projected to XHTML (axa-plan §4.5, §6 M0).
#
#   <ui:*>  ──html host──▶  real html:* XHTML events, handed to
#                            Amin::Handler::HTML, which serialises + escapes them
#                            and drops every non-html event.  The raw ui: subtree
#                            rides along additively but never reaches the page, and
#                            no markup is ever built from a string (§4.5).
#
# One IR, one more dialect: the same 25-element filter fleet + one Target::HTML.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use Path::Tiny qw(path);
use lib dirname(__FILE__) . '/../perl-lib';

my $ROOT = path(dirname(__FILE__))->parent->absolute;
my $amin = "$ROOT/bin/amin";
my $SHOP = "$ROOT/examples/apps/shop-ui/map+ui.xml";

# Prepend (never replace) PERL5LIB: mise may already provide the real local-lib.
$ENV{PERL5LIB} = join ':', "$ROOT/perl-lib",
    (grep { -d } "$ROOT/local/lib/perl5"),
    (grep length, $ENV{PERL5LIB} // '');

sub run_bin {
    open(my $p, '-|', $^X, '-I', "$ROOT/perl-lib", '-I', "$ROOT/local/lib/perl5", @_)
        or die "popen: $!";
    local $/; my $o = <$p>; close $p;
    ($o, $? >> 8);
}

# ═══════════════════════════════════════════════════════════════════════════
# 1. shop-ui → a real HTML5 document, well-formed, with no ui: leakage.
# ═══════════════════════════════════════════════════════════════════════════
my ($html, $rc) = run_bin($amin, 'ui', $SHOP, '--os=html');
is($rc, 0, 'amin ui --os=html exits 0');
like($html, qr/^<!DOCTYPE html>/, 'emits <!DOCTYPE html>');
is(scalar(() = $html =~ /<html\b[^>]*\blang\s*=/g), 1, 'exactly one <html lang=...>');
unlike($html, qr/<ui:/, 'no ui: element reaches the page');
is(scalar(() = $html =~ /\{\.\/\@flavor\}/g), 1,
    'the ui:text binding appears exactly once (the additive ui: copy is dropped)');

like($html, qr{<main>.*?</main>}s,                     'ui:scene → <main>');
like($html, qr{<ul>.*?<li>.*?</li>.*?</ul>}s,          'ui:list / ui:row → <ul> / <li>');
like($html, qr{<span class="badge">},                  'ui:badge → <span class="badge">');
like($html, qr{<p>\s*\{\.\/\@flavor\}</p>},            'ui:text body reaches <p>, exactly once');
like($html, qr{<canvas class="sparkline">},            'ui:sparkline → <canvas class="sparkline">');
like($html, qr{<a href="server-detail-\{\@id\}">},     'ui:navigate → <a href=…>');
like($html, qr{<article>.*?<img alt="" src="bundle://out/map\.svg"/>\s*</article>}s,
    'ui:card / ui:asyncimage → <article> / a void <img …/>');

use XML::LibXML;
my $doc = eval { XML::LibXML->load_xml(string => $html) };
is($@, '', 'html output is well-formed XML/XHTML (parses without error)');
is(ref($doc), 'XML::LibXML::Document', 'parsed to an XML::LibXML::Document');
if (ref $doc) {
    my $root = $doc->documentElement;
    is($root->localName, 'html', 'document root is <html>');
    is($root->getAttribute('lang'), 'en', '<html lang="en">');
}

# ═══════════════════════════════════════════════════════════════════════════
# 2. A single <ui:text> carrying markup renders escaped (never raw).
# ═══════════════════════════════════════════════════════════════════════════
my $tmp = Path::Tiny->tempfile(SUFFIX => '.xml');
$tmp->spew_utf8(<<'XML');
<?xml version="1.0" encoding="UTF-8"?>
<amin:profile xmlns:amin="http://projectamin.org/ns/2026/"
              xmlns:ui="http://projectamin.org/ns/ui/1"
              amin:id="io.projectamin.test.escape" amin:version="0.1.0">
  <ui:app title="Escape">
    <ui:text kind="headline">&lt;script&gt;alert(1)&lt;/script&gt;</ui:text>
  </ui:app>
</amin:profile>
XML

my ($esc, $rc2) = run_bin($amin, 'ui', "$tmp", '--os=html');
is($rc2, 0, 'escape fixture renders');
like($esc, qr{<p>\s*&lt;script&gt;alert\(1\)&lt;/script&gt;</p>},
    '<ui:text> content is HTML-escaped, not emitted raw');
unlike($esc, qr{<script>}, 'no unescaped <script> element reaches the page');
is(scalar(() = $esc =~ /alert\(1\)/g), 1, 'the payload appears exactly once (no ui: duplicate)');

# ═══════════════════════════════════════════════════════════════════════════
# 3. --os=tty is the untouched pass-through stream: not a page, ui: intact.
# ═══════════════════════════════════════════════════════════════════════════
my ($tty, $rc3) = run_bin($amin, 'ui', $SHOP, '--os=tty');
is($rc3, 0, 'amin ui --os=tty exits 0');
unlike($tty, qr/<!DOCTYPE/, 'tty output is the pass-through profile, not a page');
like($tty, qr/<ui:app\b/, 'tty re-emits the whole ui: subtree (for a later render host)');
is(length($tty), 5920, '--os=tty byte-stable baseline (5920 bytes)');

done_testing;
