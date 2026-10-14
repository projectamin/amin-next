package Amin::AI::Embed;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI';

use Amin::AI qw(AI_NS);
use Amin::AI::ModelRegistry;
use Amin::AI::VectorIndex;

use IPC::Run qw(harness start finish);

sub name     { '' }
sub element  { 'embed' }
sub position { 'middle' }

sub _bctool {
    require Amin::ToolPaths;
    my $t = Amin::ToolPaths::tool_bctool();
    return length $t ? $t : 'bctool';
}

sub _slab {
    state $default = do {
        require File::Temp;
        File::Temp::tempdir(CLEANUP => 1) . '/default.slab';
    };
    return $default;
}

sub _bctool_put ($self, $dataref) {
    my $bctool = _bctool();
    # bctool absent → hash in-process with BLAKE3 and skip slab streaming.
    # The bitcache bin must exist for real pushes; without it we still emit
    # content-addressed refs so the pipeline stays auditable.
    return _blake3_put($dataref)
        unless defined $bctool && length $bctool && _cmd_exists($bctool);
    my $slab   = _slab();
    my ($out, $err) = ('', '');
    my $in = $$dataref;
    my $h = harness [$bctool, 'put', '--slab', $slab],
        \$in, \$out, \$err, debug => 0;
    eval { start $h; finish $h };
    my $rc = $? >> 8;
    return _blake3_put($dataref) if $@ || $rc != 0;
    my (%kv, $line);
    for my $ln (split /\n/, $out) {
        ($line = $ln) =~ s/\r?\n?$//;
        my ($k, $v) = split /\t/, $line, 2;
        $kv{$k} = $v if defined $v;
    }
    return unless exists $kv{hash} && length($kv{hash}) == 64;
    return ($kv{hash}, $kv{size} // length($$dataref));
}

sub _blake3_put ($dataref) {
    require Digest::BLAKE3;
    my $hasher = Digest::BLAKE3::->new();
    $hasher->add($$dataref);
    return ($hasher->hexdigest(), length($$dataref));
}

sub _cmd_exists ($cmd) {
    return 1 if -x $cmd;
    return 1 if $cmd =~ m{/};
    for my $d (split /:/, $ENV{PATH} // '/usr/bin:/bin') {
        return 1 if -x "$d/$cmd";
    }
    return 0;
}

sub on_article_close ($self, $el) {
    my $model = $self->_attr($el, 'model') // 'amin-embed-384';
    return unless Amin::AI::ModelRegistry->is_allowed($model);

    my $docs = $self->_child_vals('document');
    return unless @$docs;

    my $h = $self->Handler or return;
    my $AI = AI_NS();
    my $BC = 'http://projectamin.org/ns/bc/';

    my $tenant = 'default';
    eval {
        require Amin::Auth::ZCap;
        my $scope = Amin::Auth::ZCap->current_scope_attrs;
        $tenant = $scope->{tenant_id} if $scope && $scope->{tenant_id};
    };

    my $idx = Amin::AI::VectorIndex->new(tenant_id => $tenant, model_id => $model);

    for my $doc (@$docs) {
        my $vec = Amin::AI::VectorIndex->pseudo_embed($doc);
        my $vec_bytes = join(',', @$vec);

        my ($doc_hash, $doc_size) = $self->_bctool_put(\$doc);
        my ($emb_hash, $emb_size) = $self->_bctool_put(\$vec_bytes);

        next unless defined $doc_hash && defined $emb_hash;

        $idx->add(
            doc_hash => $doc_hash,
            emb_hash => $emb_hash,
            vector   => $vec,
            preview  => substr($doc, 0, 120),
            model_id => $model,
        );

        my %doc_attrs = (
            '{}hash' => { Name => 'bc:hash', LocalName => 'hash', Prefix => 'bc', NamespaceURI => $BC, Value => $doc_hash },
            '{}size' => { Name => 'bc:size', LocalName => 'size', Prefix => 'bc', NamespaceURI => $BC, Value => $doc_size },
            '{}kind' => { Name => 'bc:kind', LocalName => 'kind', Prefix => 'bc', NamespaceURI => $BC, Value => 'document' },
        );
        $h->start_element({ NamespaceURI => $BC, LocalName => 'object', Name => 'bc:object', Prefix => 'bc', Attributes => \%doc_attrs });
        $h->end_element({ NamespaceURI => $BC, LocalName => 'object', Name => 'bc:object', Prefix => 'bc' });

        my %emb_attrs = (
            '{}hash'        => { Name => 'bc:hash', LocalName => 'hash', Prefix => 'bc', NamespaceURI => $BC, Value => $emb_hash },
            '{}size'        => { Name => 'bc:size', LocalName => 'size', Prefix => 'bc', NamespaceURI => $BC, Value => $emb_size },
            '{}kind'        => { Name => 'bc:kind', LocalName => 'kind', Prefix => 'bc', NamespaceURI => $BC, Value => 'embedding' },
            '{}model'       => { Name => 'bc:model', LocalName => 'model', Prefix => 'bc', NamespaceURI => $BC, Value => $model },
            '{}dim'         => { Name => 'bc:dim', LocalName => 'dim', Prefix => 'bc', NamespaceURI => $BC, Value => Amin::AI::VectorIndex->embed_dim },
            '{}source_hash' => { Name => 'bc:source_hash', LocalName => 'source_hash', Prefix => 'bc', NamespaceURI => $BC, Value => $doc_hash },
        );
        $h->start_element({ NamespaceURI => $BC, LocalName => 'object', Name => 'bc:object', Prefix => 'bc', Attributes => \%emb_attrs });
        $h->end_element({ NamespaceURI => $BC, LocalName => 'object', Name => 'bc:object', Prefix => 'bc' });
    }

    return;
}

1;
