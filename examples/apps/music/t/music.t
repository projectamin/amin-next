#!/usr/bin/env perl
# The music app on its own: store, run, and each element's output.
use v5.38;
use warnings;
use utf8;
use Test::More;
use File::Temp qw(tempdir);
use FindBin;
use lib "$FindBin::Bin/../filters";

my $home = tempdir(CLEANUP => 1);
$ENV{HOME} = $home;

require Amin::AI::Music::Store;
require Amin::AI::Music::Run;
require Amin::AI::Music::Page;
require Amin::AI::Music::SettingsSave;
for my $c (qw(Header Composer Settings Library Make)) { require "Amin/AI/Music/$c.pm" }
my $Store = 'Amin::AI::Music::Store';
my $MU = 'urn:projectamin:app:music';
my $AI = 'http://projectamin.org/ns/ai/1';
my $BC = 'http://projectamin.org/ns/bc/';

{
    package Rec;
    sub new { bless { ev => [] }, shift }
    sub start_element { my ($s, $e) = @_; push @{ $s->{ev} }, [ start => $e->{LocalName}, { map { ($_->{LocalName} => $_->{Value}) } values %{ $e->{Attributes} // {} } } ] }
    sub end_element   { my ($s, $e) = @_; push @{ $s->{ev} }, [ end => $e->{LocalName} ] }
    sub characters    { my ($s, $c) = @_; push @{ $s->{ev} }, [ text => $c->{Data} ] }
    sub starts { my ($s, $n) = @_; grep { $_->[0] eq 'start' && $_->[1] eq $n } @{ $s->{ev} } }
    sub all    { join "\n", map { join ' ', map { ref $_ ? join(',', %$_) : $_ } @$_ } @{ $_[0]{ev} } }
}
sub ev { my ($ns, $ln, %at) = @_; +{ NamespaceURI => $ns, LocalName => $ln, Name => $ln, Attributes => {
    map { ("{}$_" => { LocalName => $_, Name => $_, Value => $at{$_} }) } keys %at } } }
sub run { my ($class, $name, %at) = @_;
    my $rec = Rec->new; my $f = $class->new(Handler => $rec, Element => $name);
    $f->start_element(ev($MU, $name, %at)); $f->end_element(ev($MU, $name)); return $rec }

# ── settings: validation, key kept apart ──
like $Store->save_provider(provider => 'dx', api => 'deepinfra', music => '')->{err}, qr/Music model/, 'a music model is required';
like $Store->save_provider(provider => 'dx', api => 'deepinfra', music => 'm', base => 'ftp://x')->{err}, qr/http/, 'base must be http(s)';
ok $Store->save_provider(provider => 'dx', api => 'deepinfra', base => 'https://api.example/v1', music => 'ace', key => 'sk-SECRET')->{ok}, 'provider saves';
my $p = $Store->provider;
is_deeply [ @$p{qw(id api music key_set)} ], [ 'dx', 'deepinfra', 'ace', 1 ], 'provider reads back';
ok !exists $p->{key}, 'provider() never returns the key';
is((stat "$home/.amin-music/provider.xml")[2] & 07777, 0600, 'provider.xml is private');
ok $Store->save_provider(provider => 'dx', api => 'deepinfra', music => 'ace2')->{ok}, 'a blank key keeps the stored one';
is $Store->key, 'sk-SECRET', '... and it is still there';
$Store->save_provider(provider => 'dx', api => 'deepinfra', music => 'ace2', remove_key => '1');
is $Store->key, '', 'remove_key deletes it';
$Store->save_provider(provider => 'dx', api => 'deepinfra', base => 'https://api.example/v1', music => 'ace', key => 'sk-SECRET');

# ── elements never render the key ──
for my $pair ([Header => 'header'], [Composer => 'composer'], [Settings => 'settings'], [Library => 'library']) {
    my $rec = run("Amin::AI::Music::$pair->[0]", $pair->[1], csrf => 'tok');
    unlike $rec->all, qr/sk-SECRET/, "mu:$pair->[1] never renders the provider key";
}
like run('Amin::AI::Music::Header', 'header')->all, qr/dx · key set/, 'header says a key is set';

# ── composer: multi-line lyrics field, csrf, draft ──
my $c = run('Amin::AI::Music::Composer', 'composer', csrf => 'tok', style => 'lo-fi', lyrics => "a\nb");
my %f = map { ($_->[2]{name} // '') => $_->[2] } $c->starts('field');
is $f{'axa.csrf'}{value}, 'tok', 'the form carries the csrf';
is $f{'axa.action'}{value}, 'music.make', '... and posts music.make';
is $f{'axa.param.lyrics'}{type}, 'multiline', 'lyrics is a multi-line field';
is $f{'axa.param.lyrics'}{value}, "a\nb", '... and keeps line breaks';
is $f{'axa.param.style'}{value}, 'lo-fi', 'a draft fills the form';
ok exists $f{'axa.param.instrumental'} && exists $f{'axa.param.duration'}, 'instrumental and duration are offered';

# ── making a take ──
my ($seen_mode, $seen_xml);
my $take = "$home/.amin-music/takes/seed.bin";
sub fake_audio {
    my ($upd) = @_;
    return sub {
        my ($mode, $xml, $h) = @_;
        ($seen_mode, $seen_xml) = ($mode, $xml);
        my ($out) = $xml =~ /ai:out="([^"]+)"/;
        open my $o, '>:raw', $out or die $!; print {$o} 'RIFF....'; close $o;
        if ($upd) {
            $h->start_element(ev($AI, 'update', kind => 'progress', phase => 'stream', state => 'running', bytes => '262144'));
            $h->end_element(ev($AI, 'update'));
        }
        $h->start_element(ev($BC, 'object', path => $out, mime => 'audio/wav', size => '8'));
        $h->end_element(ev($BC, 'object'));
    };
}
like(Amin::AI::Music::Run->make()->{err}, qr/style, a description or lyrics/, 'an empty brief is refused');
like(Amin::AI::Music::Run->make(prompt => 'x', duration => '3')->{err}, qr/Duration/, 'a silly duration is refused');
like(Amin::AI::Music::Run->make(lyrics => 'x' x 20000)->{err}, qr/limited to/, 'lyrics are bounded');

my @u;
{
    local $Amin::AI::Music::Run::DISPATCH = fake_audio(1);
    my $r = Amin::AI::Music::Run->make(style => 'lo-fi', prompt => 'rain & "tin"', lyrics => "[verse]\nline <1>",
        duration => '45', instrumental => '', on_update => sub { push @u, $_[0] });
    ok $r->{ok}, 'a take is made';
    is $seen_mode, 'run', 'in run mode, so the file is written';
    like $r->{audio}, qr{\A/audio/[\w.-]+\.wav\z}, 'named by its real format, served from /audio';
    like $seen_xml, qr{<ai:style>lo-fi</ai:style>}, 'style travels as ai:style';
    like $seen_xml, qr{<ai:prompt>rain &amp; &quot;tin&quot;</ai:prompt>}, 'the description is escaped';
    like $seen_xml, qr{<ai:lyrics>\[verse\]\nline &lt;1&gt;</ai:lyrics>}, 'lyrics keep their line breaks';
    like $seen_xml, qr{duration="45"}, 'duration is passed';
    unlike $seen_xml, qr/instrumental/, 'instrumental is off unless asked';
    like $seen_xml, qr{key="sk-SECRET"}, 'the key is in the hop profile only';
    is $u[0]{bytes}, 262144, 'progress reaches the caller as it arrives';
}
{
    local $Amin::AI::Music::Run::DISPATCH = fake_audio(0);
    Amin::AI::Music::Run->make(prompt => 'a tune', instrumental => 'on');
    like $seen_xml, qr{instrumental="true"}, 'instrumental is passed';
    unlike $seen_xml, qr/<ai:lyrics>/, 'no lyrics element when there are none';
}
{
    local $Amin::AI::Music::Run::DISPATCH = sub {
        my ($m, $x, $h) = @_;
        $h->start_element(ev($AI, 'result', kind => 'error', msg => 'bad key sk-SECRET'));
        $h->end_element(ev($AI, 'result'));
    };
    my $e = Amin::AI::Music::Run->make(prompt => 'a tune')->{err};
    like $e, qr/bad key/, 'a refusal says why';
    unlike $e, qr/sk-SECRET/, '... without the key';
}
{
    local $Amin::AI::Music::Run::DISPATCH = sub { die "boom\n" };
    like(Amin::AI::Music::Run->make(prompt => 'a tune')->{err}, qr/boom/, 'a dispatch failure is reported, not thrown');
}

# ── the library and reuse ──
my $takes = $Store->takes;
is scalar(@$takes), 2, 'two takes recorded';
is $takes->[0]{prompt}, 'a tune', 'newest first';
my ($old) = grep { $_->{style} eq 'lo-fi' } @$takes;
is $old->{lyrics}, "[verse]\nline <1>", 'lyrics round-trip with line breaks';
is $old->{prompt}, 'rain & "tin"', 'the description round-trips';
ok !defined $Store->take('../etc/passwd'), 'take() refuses a path';
my $lib = run('Amin::AI::Music::Library', 'library');
is scalar($lib->starts('audio')), 2, 'every take has a player';
like $lib->all, qr{src,/audio/}, '... served from /audio';
like $lib->all, qr/reuse/, '... and a reuse link';

# ── Make paints into the lane ──
{
    local $Amin::AI::Music::Run::DISPATCH = fake_audio(1);
    my $m = run('Amin::AI::Music::Make', 'make', prompt => 'again', style => 'jazz', csrf => 'tok');
    my @swaps = map { $_->[2]{for} . ':' . $_->[2]{mode} } $m->starts('swap');
    is_deeply \@swaps, ['live-lane:append', 'live-status:text', 'live-card:replace'], 'lane, progress, then the finished card';
    like $m->all, qr/receiving audio · 256 KB/, 'progress is painted while the take is made';
    is scalar($m->starts('audio')), 1, 'the finished take has a player';
}
{
    local $Amin::AI::Music::Run::DISPATCH = sub { die "no route\n" };
    my $m = run('Amin::AI::Music::Make', 'make', prompt => 'again');
    like $m->all, qr/no route/, 'a failed take reports inside its own card';
}

# ── Page: request, result, action ──
{
    my $rec = Rec->new; my $pg = Amin::AI::Music::Page->new(Handler => $rec);
    $pg->start_element(ev($MU, 'result', ok => 0, err => 'Provider id is required.', panel => 'settings'));
    $pg->end_element(ev($MU, 'result'));
    $pg->start_element(ev($MU, 'request', provider => 'typed', csrf => 'tok'));
    $pg->end_element(ev($MU, 'request'));
    like $rec->all, qr/Provider id is required/, 'a failed effect is shown';
    my %s = map { ($_->[1] => $_->[2]) } $rec->starts('settings');
    my ($s) = $rec->starts('settings');
    is $s->[2]{provider}, 'typed', 'the settings card is reopened with the draft';
    ok !scalar($rec->starts('result')), 'mu:result is consumed';
}
{
    my $rec = Rec->new; my $pg = Amin::AI::Music::Page->new(Handler => $rec);
    my ($t) = grep { $_->{style} eq 'lo-fi' } @{ $Store->takes };
    $pg->start_element(ev($MU, 'request', take => $t->{file}, csrf => 'tok'));
    $pg->end_element(ev($MU, 'request'));
    my ($c) = $rec->starts('composer');
    is $c->[2]{style}, 'lo-fi', 'reuse puts a take back in the form';
    is $c->[2]{lyrics}, "[verse]\nline <1>", '... lyrics included';
}
{
    my $rec = Rec->new; my $pg = Amin::AI::Music::Page->new(Handler => $rec);
    $pg->start_element(ev($MU, 'action', op => 'music.make', prompt => 'go', csrf => 'tok'));
    $pg->end_element(ev($MU, 'action'));
    my ($m) = $rec->starts('make');
    is $m->[2]{prompt}, 'go', 'a make action places mu:make in the live lane';
    unlike $rec->all, qr/sk-SECRET/, 'the page stream never carries the key';
}

# ── the spec is the whole filter surface ──
{
    open my $fh, '<', "$FindBin::Bin/../machine_spec.xml" or die $!;
    my $spec = do { local $/; <$fh> };
    my %decl = $spec =~ /<filter class="([\w:]+)"[^>]*?(?:element="([\w-]+)")?/g;
    ok $spec !~ /permanent/, 'nothing is permanent';
    for my $c (qw(Header Composer Settings Library Make SettingsSave Page)) {
        like $spec, qr/class="Amin::AI::Music::$c"/, "$c is declared";
    }
    is scalar(() = $spec =~ /<filter /g), 7, 'seven filters, no more';
}

done_testing;
