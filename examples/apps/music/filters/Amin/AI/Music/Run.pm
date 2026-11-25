package Amin::AI::Music::Run;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use File::Path qw(make_path);
use File::Basename qw(basename);
use Amin::AI::Music::Store;
use Amin::AI::Music::Sink;

# One music take: build a concrete ai:music profile from the form and the saved
# provider, run it through the machine in this process (the same
# Dispatcher->run `bin/amin render` makes), and record the take.  The profile is
# a string that carries the provider key; it is never written anywhere and
# never reaches the page stream.

use constant AMIN_NS => 'http://projectamin.org/ns/2026/';
use constant AI_NS   => 'http://projectamin.org/ns/ai/1';
use constant TIMEOUT => 600;
use constant LIMIT   => { style => 1024, prompt => 4096, lyrics => 16384 };

our $DISPATCH;   # test hook: ($mode, $xml, $handler)

my %EXT = (
    'audio/mpeg' => 'mp3', 'audio/mp3' => 'mp3', 'audio/wav' => 'wav', 'audio/x-wav' => 'wav',
    'audio/flac' => 'flac', 'audio/ogg' => 'ogg', 'audio/opus' => 'opus',
    'audio/mp4' => 'm4a', 'audio/aac' => 'aac',
);

sub _esc ($s) {
    $s //= '';
    $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/>/&gt;/g; $s =~ s/"/&quot;/g;
    return $s;
}

sub _norm ($s) {
    $s //= '';
    $s =~ s/\r\n?/\n/g;
    $s =~ s/[\x00-\x08\x0B\x0C\x0E-\x1F]//g;
    $s =~ s/\A\s+|\s+\z//g;
    return $s;
}

sub make ($class, %f) {
    return { err => 'HOME is not set; nowhere to keep takes.' } unless Amin::AI::Music::Store->ready;
    my %v = map { $_ => _norm($f{$_}) } qw(style prompt lyrics);
    return { err => 'Give the track a style, a description or lyrics.' }
        unless length($v{style}) || length($v{prompt}) || length($v{lyrics});
    for my $k (sort keys %{ +LIMIT }) {
        return { err => ucfirst($k) . ' is limited to ' . LIMIT->{$k} . ' bytes.' }
            if length($v{$k}) > LIMIT->{$k};
    }
    my $dur = _norm($f{duration});
    return { err => 'Duration is seconds, 5 to 600.' }
        if length $dur && ($dur !~ /\A\d{1,3}\z/ || $dur < 5 || $dur > 600);
    my $instr = ($f{instrumental} // '') =~ /\A(?:1|on|true|yes)\z/i ? 1 : 0;

    my $p = Amin::AI::Music::Store->provider;
    return { err => 'Set a provider in API first.' } unless length $p->{id};
    my $key = Amin::AI::Music::Store->key;
    return { err => 'Add a key in API first.' }
        if !length $key && ($p->{api} // '') ne 'stub';

    # The posted model must be one discovery found for this provider; if the
    # composer posted none, fall back to the saved selection.
    my $cat = Amin::AI::Music::Store->catalog;
    my @known = map { $_->{id} } @{ $cat->{models} // [] };
    my $model = _norm($f{model});
    $model = $p->{music} // '' unless length $model;
    return { err => 'Choose a music model.' } unless length $model;
    if (@known && !grep { $_ eq $model } @known) {
        return { err => 'That model is not in the discovered catalog; pick one in the composer.' };
    }

    my $dir = Amin::AI::Music::Store->takes_dir;
    make_path($dir) unless -d $dir;
    my $out = "$dir/" . time . '.bin';
    $out = "$dir/" . time . "-$$.bin" if -e $out;

    my $xml = _xml(%v, model => $model, p => $p, key => $key, out => $out, duration => $dur, instrumental => $instr);
    my $run = _dispatch($xml, $f{on_update});
    my $res = $run->{error} ? { error => $run->{error} } : _result($run->{sink});
    # a refusal can echo what it was sent; the key never leaves this sub
    return { err => _redact($res->{error}, $key) } if $res->{error};

    if (my $ext = $EXT{ lc($res->{mime} // '') }) {
        (my $named = $res->{path}) =~ s/\.bin\z/.$ext/;
        $res->{path} = $named if $named ne $res->{path} && !-e $named && rename $res->{path}, $named;
    }
    my $file = basename($res->{path});
    Amin::AI::Music::Store->add_take(file => $file, mime => $res->{mime}, model => $model, %v);
    Amin::AI::Music::Store->remember_model($model);
    return { ok => 1, file => $file, audio => "/audio/$file", mime => $res->{mime}, model => $model };
}

sub _xml (%v) {
    my $p = $v{p};
    my $pa = join ' ', map { my $x = $p->{$_} // ''; $_ eq 'key' ? () : length $x ? qq{$_="} . _esc($x) . '"' : () } qw(id api base);
    $pa .= ' key="' . _esc($v{key}) . '"' if length $v{key};
    my $ma = 'ai:out="' . _esc($v{out}) . '"';
    $ma .= ' duration="' . _esc($v{duration}) . '"' if length $v{duration};
    $ma .= ' instrumental="true"' if $v{instrumental};
    my $kids = join '', map { length $v{$_} ? "        <ai:$_>" . _esc($v{$_}) . "</ai:$_>\n" : '' } qw(style prompt lyrics);
    return qq{<?xml version="1.0" encoding="UTF-8"?>\n}
        . '<amin:profile xmlns:amin="' . AMIN_NS . '" xmlns:ai="' . AI_NS . qq{">\n}
        . "  <ai:provider $pa>\n"
        . '    <ai:model id="amin-music" upstream="' . _esc($v{model}) . qq{" kind="music">\n}
        . "      <ai:music $ma>\n$kids      </ai:music>\n"
        . "    </ai:model>\n  </ai:provider>\n</amin:profile>\n";
}

sub _dispatch ($xml, $on_update) {
    my $sink = Amin::AI::Music::Sink->new(on_update => $on_update);
    my $timeout = 0;
    my $ok = eval {
        local $SIG{ALRM} = sub { $timeout = 1; die "timeout\n" };
        alarm TIMEOUT;
        if ($DISPATCH) { $DISPATCH->('run', $xml, $sink) }
        else {
            require Amin::Machine::Dispatcher;
            # `run`, not `render`: the music filter must write the file.
            Amin::Machine::Dispatcher->run(
                mode => 'run', source_xml => $xml, Handler => $sink,
                late_filters_enable => { map => 0, ui => 0 },
            );
        }
        alarm 0;
        1;
    };
    alarm 0;
    return { error => 'music turn timed out after ' . TIMEOUT . 's' } if $timeout;
    if (!$ok) { (my $why = $@ || 'unknown error') =~ s/\s+\z//; return { error => "music turn failed: $why" } }
    return { sink => $sink->result };
}

sub _result ($r) {
    my $res = $r->{res};
    if ($res && ($res->{kind} // '') eq 'error') {
        my $m = $res->{msg} // '';
        return { error => length $m ? $m : 'music turn refused' };
    }
    my $o = $r->{object} or return { error => 'music turn produced no audio' };
    my ($path, $mime) = ($o->{path} // '', $o->{mime} // '');
    return { error => 'music turn produced no audio file' }
        unless length $path && -f $path && (-s $path // 0) > 0;
    return { path => $path, mime => $mime || 'audio' };
}

sub _redact ($s, $key) {
    $s //= '';
    $s =~ s/\Q$key\E/[key]/g if length $key;
    $s =~ s/\s+/ /g;
    return $s;
}

# one line for a progress update: what the hop is doing, how much has arrived
sub progress_line ($class, $u, $secs) {
    my @bits;
    if (($u->{phase} // '') eq 'stream' && ($u->{bytes} // 0) > 0) {
        my $b = $u->{bytes};
        push @bits, 'receiving audio',
            $b >= 1048576 ? sprintf('%.1f MB', $b / 1048576) : sprintf('%d KB', ($b + 1023) / 1024);
    }
    else {
        my $s = $u->{state} // 'running';
        push @bits, $s eq 'running' ? 'composing' : $s;
        my $p = $u->{progress} // 0;
        push @bits, sprintf('%d%%', $p <= 1 ? $p * 100 : $p) if $p > 0;
    }
    push @bits, $secs . 's';
    return join ' · ', @bits;
}

1;
