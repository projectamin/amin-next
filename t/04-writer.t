#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Handler::Writer;
use Amin qw(NS);

sub el ($ln, $pfx='amin', $ns=NS(), $attrs={}) {
    +{ Name => "$pfx:$ln", LocalName => $ln, Prefix => $pfx, NamespaceURI => $ns,
       Attributes => { map {; "{}" . $_ => +{ Name => $_, LocalName => $_,
           Prefix => $pfx, NamespaceURI => $ns, Value => $attrs->{$_} } } keys %$attrs } }
}

my $w = Amin::Handler::Writer->new(indent => 1);
$w->start_document;
$w->start_element(el('profile', 'amin', NS(), { id => 't1' }));
$w->start_element(el('command', 'amin', NS(), { name => 'echo' }));
$w->start_element(el('param', 'amin', NS(), { name => 'text' }));
$w->characters({ Data => "Hello & <'\"'> world" });
$w->end_element(el('param'));
$w->end_element(el('command'));
$w->end_element(el('profile'));
$w->end_document;

my $out = $w->output;
like($out, qr/^<\?xml version="1\.0" encoding="UTF-8"\?>/, 'prolog first');
like($out, qr/<amin:profile amin:id="t1">/, 'element + attr render with prefix');
like($out, qr{Hello &amp; &lt;&apos;&quot;&apos;&gt; world},
     'XML esc table: & < > " \' all converted to their entity refs');
like($out, qr{</amin:param>\s+</amin:command>\s+</amin:profile>},
     'closing tags in correct LIFO order');
unlike($out, qr/=""/, 'empty-valued sentinel attrs are NOT rendered');

is($w->output, $out, 'output() idempotent string');

open(my $fh, '>:encoding(UTF-8)', \my $live) or die;
my $sw = Amin::Handler::Writer->new(indent => 1, fh => $fh, autoflush => 1);
$sw->start_document;
$sw->start_element(el('x'));
like($live, qr{<amin:x>}, 'stream mode: writes arrive BEFORE end_document/autoflush');
$sw->end_element(el('x'));
close $fh;
like($sw->output, qr{</amin:x>}, 'buffer also has everything for downstream consumers');

done_testing;
