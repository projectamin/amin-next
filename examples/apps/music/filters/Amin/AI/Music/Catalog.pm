package Amin::AI::Music::Catalog;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use Amin::AI::Music::Store;
use Amin::AI::Music::CatalogSink;

# Discovery, as a profile to the Amin machine: the saved provider (with the key
# in memory only) wraps an empty <ai:models/>; the machine's Amin::AI::Models
# filter pulls the provider catalog, keeps the music-capable entities, and
# emits an <ai:catalog>.  What lands is cached in ~/.amin-music/catalog.xml —
# ids and names, never the key.  Like a take, the discovery profile is a string
# that never reaches the page stream or disk.

use constant AMIN_NS => 'http://projectamin.org/ns/2026/';
use constant AI_NS   => 'http://projectamin.org/ns/ai/1';
use constant TIMEOUT => 30;

our $DISPATCH;   # test hook: ($mode, $xml, $handler)

sub refresh ($class, $p) {
    my $id = $p->{id} // '';
    return { err => 'Choose a provider first.' } unless length $id;
    my $pre = Amin::AI::Music::Store->preset($id);
    return { err => 'Unknown provider.' } unless $pre;

    my $key = Amin::AI::Music::Store->key;
    return { err => 'Add a key before discovering models.' }
        if !length $key && ($pre->{api} // '') ne 'stub';

    my $xml = _xml({ %$p, api => $pre->{api}, base => $pre->{base} }, $key);
    my $run = _dispatch($xml);
    return { err => $run->{error} } if $run->{error};

    my $sink = $run->{sink};
    return { err => $sink->{error} } if length($sink->{error} // '');
    my $cat = $sink->{catalog} // { models => [] };

    $cat->{provider} = $id;
    $cat->{base}     = $pre->{base};
    my $saved = Amin::AI::Music::Store->save_catalog($cat);
    return $saved if $saved->{err};
    return { ok => 1, count => scalar @{ $cat->{models} } };
}

sub _esc ($s) {
    $s //= '';
    $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g;
    return $s;
}

sub _xml ($p, $key) {
    my $pa = join ' ', map {
        my $v = $p->{$_} // '';
        length $v ? qq{$_="} . _esc($v) . '"' : ()
    } qw(id api base);
    $pa .= ' key="' . _esc($key) . '"' if length $key;
    return qq{<?xml version="1.0" encoding="UTF-8"?>\n}
        . '<amin:profile xmlns:amin="' . AMIN_NS . '" xmlns:ai="' . AI_NS . qq{">\n}
        . "  <ai:provider $pa>\n"
        . qq{    <ai:model id="amin-models" kind="models">\n}
        . "      <ai:models/>\n"
        . "    </ai:model>\n  </ai:provider>\n</amin:profile>\n";
}

sub _dispatch ($xml) {
    my $sink = Amin::AI::Music::CatalogSink->new;
    my $timeout = 0;
    my $ok = eval {
        local $SIG{ALRM} = sub { $timeout = 1; die "timeout\n" };
        alarm TIMEOUT;
        if ($DISPATCH) { $DISPATCH->('render', $xml, $sink) }
        else {
            require Amin::Machine::Dispatcher;
            # render: discovery is read-only, nothing is written but the cache.
            Amin::Machine::Dispatcher->run(
                mode => 'render', source_xml => $xml, Handler => $sink,
                late_filters_enable => { map => 0, ui => 0 },
            );
        }
        alarm 0;
        1;
    };
    alarm 0;
    return { error => 'model discovery timed out after ' . TIMEOUT . 's' } if $timeout;
    if (!$ok) {
        (my $why = $@ || 'unknown error') =~ s/\s+\z//;
        return { error => "model discovery failed: $why" };
    }
    return { sink => $sink->result };
}

1;
