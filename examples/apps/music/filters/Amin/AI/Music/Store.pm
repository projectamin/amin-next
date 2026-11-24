package Amin::AI::Music::Store;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use XML::LibXML;
use File::Path qw(make_path);
use File::Basename qw(basename);
use Encode qw(encode_utf8);

# Everything the music app keeps lives in ~/.amin-music:
#   provider.xml  the provider (same shape the other Amin AI apps use); 0600
#   takes/        finished audio, served by the /audio/:name file route
#   takes.tsv     one line per take: time, file, mime, model, style, prompt, lyrics
# The key is read only by key(); provider() reports whether one is set.

use constant AMIN_NS => 'http://projectamin.org/ns/2026/';
use constant AI_NS   => 'http://projectamin.org/ns/ai/1';

sub home      ($c) { ($ENV{HOME} // '') . '/.amin-music' }
sub takes_dir ($c) { $c->home . '/takes' }
sub _ppath    ($c) { $c->home . '/provider.xml' }
sub _tpath    ($c) { $c->home . '/takes.tsv' }

sub ready ($c) { length($ENV{HOME} // '') ? 1 : 0 }

sub _load ($path) { return eval { XML::LibXML->load_xml(location => $path, no_blanks => 1) } }

sub provider ($c) {
    my %out = ( id => '', api => '', base => '', music => '', key_set => 0 );
    my $doc = -f $c->_ppath ? _load($c->_ppath) : undef;
    return \%out unless $doc;
    my ($p) = $doc->findnodes('//*[local-name()="provider"]') or return \%out;
    for my $k (qw(id api base music)) {
        my $v = eval { $p->getAttribute($k) };
        $out{$k} = $v if defined $v;
    }
    my $key = eval { $p->getAttribute('key') };
    $out{key_set} = defined $key && length $key ? 1 : 0;
    return \%out;
}

sub key ($c) {
    my $doc = -f $c->_ppath ? _load($c->_ppath) : undef;
    return '' unless $doc;
    my ($p) = $doc->findnodes('//*[local-name()="provider"]') or return '';
    return eval { $p->getAttribute('key') } // '';
}

sub _clean ($s) {
    $s //= '';
    $s =~ s/[\x00-\x1F\x7F]//g;
    $s =~ s/\A\s+|\s+\z//g;
    return $s;
}

sub save_provider ($c, %f) {
    return { err => 'HOME is not set; nowhere to keep settings.' } unless $c->ready;
    my ($id, $api, $base, $music) = map { _clean($f{$_}) } qw(provider api base music);
    return { err => 'Provider id is required.' }       unless length $id;
    return { err => 'API is required.' }               unless length $api;
    return { err => 'Music model is required.' }       unless length $music;
    return { err => 'Base must be an http(s) URL.' }   if length $base && $base !~ m{\Ahttps?://\S+\z};

    my $new  = _clean($f{key});
    my $drop = ($f{remove_key} // '') =~ /\A(?:1|on|true|yes)\z/i;
    my $key  = $drop ? '' : (length $new ? $new : $c->key);

    my $doc = XML::LibXML->load_xml(string =>
        '<amin:profile xmlns:amin="' . AMIN_NS . '" xmlns:ai="' . AI_NS . '">'
      . '<ai:provider/></amin:profile>');
    my ($p) = $doc->findnodes('//*[local-name()="provider"]');
    my %v = (id => $id, api => $api, base => $base, music => $music, key => $key);
    for my $k (sort keys %v) {
        length $v{$k} ? $p->setAttribute($k, $v{$k}) : $p->removeAttribute($k);
    }
    my $xml = $doc->toString(1);
    $xml .= "\n" unless $xml =~ /\n\z/;
    make_path($c->home) unless -d $c->home;
    return { err => 'Could not write ' . $c->_ppath . '.' } unless _write($c->_ppath, encode_utf8($xml), 0600);
    return { ok => 1, notice => 'Saved provider.xml.' };
}

# ── takes ─────────────────────────────────────────────────────────────
sub _esc ($s) { $s //= ''; $s =~ s/\\/\\\\/g; $s =~ s/\t/\\t/g; $s =~ s/\r/\\r/g; $s =~ s/\n/\\n/g; $s }
sub _unesc ($s) {
    $s =~ s/\\(.)/ $1 eq 't' ? "\t" : $1 eq 'n' ? "\n" : $1 eq 'r' ? "\r" : $1 /ge;
    return $s;
}

sub add_take ($c, %t) {
    make_path($c->home) unless -d $c->home;
    open my $fh, '>>:raw', $c->_tpath or return 0;
    print {$fh} join("\t", map { _esc(encode_utf8($_ // '')) } time, @t{qw(file mime model style prompt lyrics)}), "\n";
    close $fh;
    return 1;
}

my @COLS = qw(time file mime model style prompt lyrics);

sub _read_takes ($c) {
    open my $fh, '<:raw', $c->_tpath or return ();
    my @out;
    while (my $l = <$fh>) {
        chomp $l;
        my @f = map { my $v = _unesc($_); utf8::decode($v); $v } split /\t/, $l, -1;
        next unless @f == @COLS;
        my %t; @t{@COLS} = @f;
        push @out, \%t if -f $c->takes_dir . '/' . $t{file};
    }
    return @out;
}

# newest first
sub takes ($c, $limit = 30) {
    my @all = reverse $c->_read_takes;
    return \@all if @all <= $limit;
    return [ @all[0 .. $limit - 1] ];
}

sub take ($c, $file) {
    return undef unless defined $file && $file =~ /\A[A-Za-z0-9][A-Za-z0-9._-]{0,127}\z/;
    my ($t) = grep { $_->{file} eq $file } $c->_read_takes;
    return $t;
}

sub _write ($path, $data, $mode = 0644) {
    my $tmp = "$path.$$.tmp";
    open my $fh, '>:raw', $tmp or return 0;
    print {$fh} $data;
    close $fh or return 0;
    chmod $mode, $tmp;
    return rename $tmp, $path;
}

1;
