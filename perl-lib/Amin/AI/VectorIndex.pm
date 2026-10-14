package Amin::AI::VectorIndex;
use v5.38; use warnings; use utf8; use experimental 'signatures';

use JSON::PP;
use File::Basename qw(dirname);
use File::Path qw(make_path);

my $EMBED_DIM = 384;

sub new ($class, %o) {
    my $tenant = $o{tenant_id} // 'default';
    my $model  = $o{model_id}  // 'amin-embed-384';
    my $dir    = $o{index_dir} // $ENV{AMIN_AI_INDEX_DIR} // do {
        require File::Temp;
        File::Temp::tempdir(CLEANUP => 0) . '/amin-vector-index';
    };
    make_path($dir) unless -d $dir;
    my $file = "$dir/${tenant}__${model}.json";
    bless {
        tenant_id => $tenant,
        model_id  => $model,
        file      => $file,
        entries   => [],
        loaded    => 0,
    }, $class;
}

sub _load ($self) {
    return if $self->{loaded};
    $self->{loaded} = 1;
    return unless -f $self->{file};
    open(my $fh, '<:encoding(UTF-8)', $self->{file}) or return;
    local $/;
    my $raw = <$fh>;
    close $fh;
    return unless defined $raw && length $raw;
    eval { $self->{entries} = decode_json($raw) };
    $self->{entries} //= [];
}

sub _save ($self) {
    open(my $fh, '>:encoding(UTF-8)', $self->{file}) or return;
    print $fh encode_json($self->{entries});
    close $fh;
    return 1;
}

sub embed_dim { $EMBED_DIM }

sub pseudo_embed ($class_or_self, $text) {
    my @vec = (0.0) x $EMBED_DIM;
    return \@vec unless defined $text && length $text;
    require Digest::SHA;
    my $t = lc($text);
    my $len = length($t);
    for my $i (0 .. $len - 3) {
        my $ng = substr($t, $i, 3);
        my $h = Digest::SHA::sha256($ng);
        my $idx = unpack('V', substr($h, 0, 4)) % $EMBED_DIM;
        $vec[$idx] += 1.0;
    }
    my $norm = 0.0;
    $norm += $_ * $_ for @vec;
    $norm = sqrt($norm);
    if ($norm > 0) {
        @vec = map { $_ / $norm } @vec;
    }
    return \@vec;
}

sub cosine ($a, $b) {
    my $dot = 0.0;
    my $na  = 0.0;
    my $nb  = 0.0;
    for my $i (0 .. $#$a) {
        $dot += $a->[$i] * $b->[$i];
        $na  += $a->[$i] * $a->[$i];
        $nb  += $b->[$i] * $b->[$i];
    }
    return 0 unless $na > 0 && $nb > 0;
    return $dot / (sqrt($na) * sqrt($nb));
}

sub add ($self, %entry) {
    $self->_load;
    push $self->{entries}->@*, {
        doc_hash  => $entry{doc_hash}  // '',
        emb_hash  => $entry{emb_hash}  // '',
        vector    => $entry{vector}    // [],
        preview   => $entry{preview}   // '',
        model_id  => $entry{model_id}  // $self->{model_id},
    };
    $self->_save;
    return $self->{entries}->[-1];
}

sub search ($self, $query_vec, $k = 3) {
    $self->_load;
    return [] unless @{$self->{entries}};
    my @scored;
    for my $e ($self->{entries}->@*) {
        my $sim = cosine($query_vec, $e->{vector});
        push @scored, { entry => $e, score => $sim };
    }
    @scored = sort { $b->{score} <=> $a->{score} } @scored;
    $k = scalar @scored if $k > scalar @scored;
    return [ map { $_->{entry} } @scored[0 .. $k - 1] ];
}

1;
