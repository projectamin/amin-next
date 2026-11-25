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
require Amin::AI::Music::Catalog;
for my $c (qw(Header Composer Settings Library Make)) { require "Amin/AI/Music/$c.pm" }
my $Store = 'Amin::AI::Music::Store';
my $MU = 'urn:projectamin:app:music';
my $AI = 'http://projectamin.org/ns/ai/1';
my $BC = 'http://projectamin.org/ns/bc/';

sub slurp { open my $fh, '<:raw', shift or return ''; local $/; my $s = <$fh>; $s // '' }

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

# ── settings: a provider preset and a key, nothing else ──
is $Store->save_provider(provider => '')->{err}, 'Choose a provider.', 'a provider is required';
like $Store->save_provider(provider => 'nope')->{err}, qr/Unknown provider/, 'an unknown provider is refused';
ok $Store->save_provider(provider => 'deepinfra', key => 'sk-SECRET')->{ok}, 'provider saves';
my $p = $Store->provider;
is_deeply [ @$p{qw(id api base music key_set)} ],
    [ 'deepinfra', 'deepinfra', 'https://api.deepinfra.com', '', 1 ],
    'the preset supplies api and base';
ok !exists $p->{key}, 'provider() never returns the key';
is((stat "$home/.amin-music/provider.xml")[2] & 07777, 0600, 'provider.xml is private');
ok $Store->save_provider(provider => 'deepinfra')->{ok}, 'a blank key keeps the stored one';
is $Store->key, 'sk-SECRET', '... and it is still there';
$Store->save_provider(provider => 'deepinfra', remove_key => '1');
is $Store->key, '', 'remove_key deletes it';
$Store->save_provider(provider => 'deepinfra', key => 'sk-SECRET');

# ── the catalog comes from discovery, and is names only ──
ok $Store->save_catalog({ provider => 'deepinfra', base => 'https://api.deepinfra.com',
    models => [ { id => 'ace-step', name => 'ACE-Step' }, { id => 'lyria', name => 'Lyria' } ] })->{ok},
    'a discovered catalog caches';
my $cat = $Store->catalog;
is scalar @{ $cat->{models} }, 2, 'both music models are read back';
is $cat->{models}[0]{id}, 'ace-step', '... in order';
like slurp("$home/.amin-music/catalog.xml"), qr/<ai:catalog[^>]*count="2"/, 'the cache records the count';
unlike slurp("$home/.amin-music/catalog.xml"), qr/sk-SECRET/, '... and never the key';

# ── elements never render the key ──
for my $pair ([Header => 'header'], [Composer => 'composer'], [Settings => 'settings'], [Library => 'library']) {
    my $rec = run("Amin::AI::Music::$pair->[0]", $pair->[1], csrf => 'tok');
    unlike $rec->all, qr/sk-SECRET/, "mu:$pair->[1] never renders the provider key";
}
like run('Amin::AI::Music::Header', 'header')->all, qr/deepinfra · key set/, 'header says a key is set';

# ── settings offers presets, never asks for api/base/model ──
{
    my $set = run('Amin::AI::Music::Settings', 'settings', csrf => 'tok');
    my ($ps) = $set->starts('select');
    is $ps->[2]{name}, 'axa.param.provider', 'the provider is a picker';
    is_deeply [ map { $_->[2]{value} } $set->starts('option') ],
        [qw(deepinfra openai openrouter stub)], 'the known providers are offered';
    my ($sel) = grep { $_->[2]{selected} } $set->starts('option');
    is $sel->[2]{value}, 'deepinfra', 'the saved provider is selected';
    my %sf = map { ($_->[2]{name} // '') => $_->[2] } $set->starts('field');
    ok exists $sf{'axa.param.key'}, 'the key is a field';
    ok !exists $sf{'axa.param.api'} && !exists $sf{'axa.param.base'} && !exists $sf{'axa.param.music'},
        'api, base and the model are not typed here';
    like $set->all, qr/2 music models discovered/, 'the card reports the discovered catalog';
}

# ── composer: model picker, multi-line lyrics, csrf, draft ──
my $c = run('Amin::AI::Music::Composer', 'composer', csrf => 'tok', style => 'lo-fi', lyrics => "a\nb", model => 'lyria');
my %f = map { ($_->[2]{name} // '') => $_->[2] } $c->starts('field');
is $f{'axa.csrf'}{value}, 'tok', 'the form carries the csrf';
is $f{'axa.action'}{value}, 'music.make', '... and posts music.make';
is $f{'axa.param.lyrics'}{type}, 'multiline', 'lyrics is a multi-line field';
is $f{'axa.param.lyrics'}{value}, "a\nb", '... and keeps line breaks';
is $f{'axa.param.style'}{value}, 'lo-fi', 'a draft fills the form';
ok exists $f{'axa.param.instrumental'} && exists $f{'axa.param.duration'}, 'instrumental and duration are offered';
{
    my ($vis) = $c->starts('visualizer');
    is $vis->[2]{mode}, 'plasma', 'the composer carries an ambient visualizer';
}
{
    my ($ms) = $c->starts('select');
    is $ms->[2]{name}, 'axa.param.model', 'the model picker posts axa.param.model';
    is_deeply [ map { $_->[2]{value} } $c->starts('option') ], [qw(ace-step lyria)],
        'the catalog fills the picker';
    my ($sel) = grep { $_->[2]{selected} } $c->starts('option');
    is $sel->[2]{value}, 'lyria', 'the draft model is selected';
}
{
    $Store->drop_catalog;
    my $none = run('Amin::AI::Music::Composer', 'composer', csrf => 'tok');
    is scalar($none->starts('select')), 0, 'no picker until discovery has found models';
    $Store->save_catalog({ provider => 'deepinfra', base => 'https://api.deepinfra.com',
        models => [ { id => 'ace-step', name => 'ACE-Step' }, { id => 'lyria', name => 'Lyria' } ] });
}

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
like(Amin::AI::Music::Run->make(prompt => 'x')->{err}, qr/Choose a music model/, 'a model is required');
like(Amin::AI::Music::Run->make(prompt => 'x', model => 'gpt-4o-mini')->{err},
    qr/not in the discovered catalog/, 'a model outside the catalog is refused before the hop');

my @u;
{
    local $Amin::AI::Music::Run::DISPATCH = fake_audio(1);
    my $r = Amin::AI::Music::Run->make(style => 'lo-fi', prompt => 'rain & "tin"', lyrics => "[verse]\nline <1>",
        duration => '45', instrumental => '', model => 'ace-step', on_update => sub { push @u, $_[0] });
    ok $r->{ok}, 'a take is made';
    is $r->{model}, 'ace-step', 'the take names the chosen model';
    is $seen_mode, 'run', 'in run mode, so the file is written';
    like $r->{audio}, qr{\A/audio/[\w.-]+\.wav\z}, 'named by its real format, served from /audio';
    like $seen_xml, qr{upstream="ace-step"}, 'the chosen model becomes ai:model upstream';
    like $seen_xml, qr{<ai:style>lo-fi</ai:style>}, 'style travels as ai:style';
    like $seen_xml, qr{<ai:prompt>rain &amp; &quot;tin&quot;</ai:prompt>}, 'the description is escaped';
    like $seen_xml, qr{<ai:lyrics>\[verse\]\nline &lt;1&gt;</ai:lyrics>}, 'lyrics keep their line breaks';
    like $seen_xml, qr{duration="45"}, 'duration is passed';
    unlike $seen_xml, qr/instrumental/, 'instrumental is off unless asked';
    like $seen_xml, qr{key="sk-SECRET"}, 'the key is in the hop profile only';
    is $u[0]{bytes}, 262144, 'progress reaches the caller as it arrives';
    is $Store->provider->{music}, 'ace-step', 'the used model is remembered';
}
{
    local $Amin::AI::Music::Run::DISPATCH = fake_audio(0);
    Amin::AI::Music::Run->make(prompt => 'a tune', instrumental => 'on');
    like $seen_xml, qr{instrumental="true"}, 'instrumental is passed';
    like $seen_xml, qr{upstream="ace-step"}, 'with no model posted, the remembered one is used';
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
is $old->{model}, 'ace-step', 'the take records the model that made it';
ok !defined $Store->take('../etc/passwd'), 'take() refuses a path';
my $lib = run('Amin::AI::Music::Library', 'library');
is scalar($lib->starts('audio')), 2, 'every take has a player';
is scalar($lib->starts('player')), 2, '... the neutral player construct';
is scalar($lib->starts('equalizer')), 2, '... with its equalizer';
is scalar($lib->starts('visualizer')), 2, '... and an audio-reactive field';
is_deeply [ map { $_->[2]{mode} } $lib->starts('visualizer') ], ['ripple', 'ripple'],
    'every library player asks for the ripple mode';
like $lib->all, qr{src,/audio/}, '... served from /audio';
like $lib->all, qr/reuse/, '... and a reuse link';

# ── Make paints into the lane ──
{
    local $Amin::AI::Music::Run::DISPATCH = fake_audio(1);
    my $m = run('Amin::AI::Music::Make', 'make', prompt => 'again', style => 'jazz',
        model => 'lyria', csrf => 'tok');
    my @swaps = map { $_->[2]{for} . ':' . $_->[2]{mode} } $m->starts('swap');
    is_deeply \@swaps, ['live-lane:append', 'live-status:text', 'live-card:replace'], 'lane, progress, then the finished card';
    like $m->all, qr/receiving audio · 256 KB/, 'progress is painted while the take is made';
    like $seen_xml, qr/upstream="lyria"/, 'the card takes the model chosen in the composer';
    like $m->all, qr/lyria/, '... and labels the finished take with it';
    is scalar($m->starts('audio')), 1, 'the finished take has a player';
    is scalar($m->starts('player')), 1, '... wrapped in the neutral player construct';
    is scalar($m->starts('equalizer')), 1, '... with its equalizer';
    is_deeply [ map { $_->[2]{mode} } $m->starts('visualizer') ], ['vortex', 'ripple'],
        'the waiting lane swirls, then the finished take ripples';
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
    $pg->start_element(ev($MU, 'action', op => 'music.make', prompt => 'go', model => 'lyria', csrf => 'tok'));
    $pg->end_element(ev($MU, 'action'));
    my ($m) = $rec->starts('make');
    is $m->[2]{prompt}, 'go', 'a make action places mu:make in the live lane';
    is $m->[2]{model}, 'lyria', '... with the model the composer chose';
    unlike $rec->all, qr/sk-SECRET/, 'the page stream never carries the key';
}

# ── saving settings discovers models through the machine ──
{
    my ($seen_mode, $seen_xml);
    local $Amin::AI::Music::Catalog::DISPATCH = sub {
        my ($mode, $xml, $h) = @_;
        ($seen_mode, $seen_xml) = ($mode, $xml);
        $h->start_element(ev($AI, 'catalog', provider => 'openai',
            base => 'https://api.openai.com/v1', count => '1'));
        $h->start_element(ev($AI, 'model', id => 'lyria', name => 'Lyria',
            upstream => 'lyria', kind => 'music'));
        $h->end_element(ev($AI, 'model'));
        $h->end_element(ev($AI, 'catalog'));
    };
    my $rec = run('Amin::AI::Music::SettingsSave', 'settings-save',
        provider => 'openai', key => 'sk-NEW');
    is $seen_mode, 'render', 'discovery is read-only, so render mode';
    like $seen_xml, qr/key="sk-NEW"/, 'the key rides only in the discovery profile';
    like $seen_xml, qr{<ai:models/>}, 'the profile asks the machine for models';
    my ($res) = $rec->starts('result');
    is $res->[2]{ok}, 1, 'the save reports ok';
    like $res->[2]{notice}, qr/Found 1 music model/, '... and how many were found';
    my $cat = $Store->catalog;
    is $cat->{provider}, 'openai', 'the catalog records the provider';
    is $cat->{models}[0]{id}, 'lyria', '... and the discovered model';
    unlike slurp("$home/.amin-music/catalog.xml"), qr/sk-NEW/, 'the cache never carries the key';
    unlike $rec->all, qr/sk-NEW/, 'the result never carries the key';
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
