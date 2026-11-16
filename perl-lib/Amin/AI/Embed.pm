package Amin::AI::Embed;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI';

use Amin::AI qw(AI_NS);
use Amin::AI::ModelRegistry;
use Amin::AI::VectorIndex;

sub name     { '' }
sub element  { 'embed' }
sub position { 'middle' }

sub on_article_close ($self, $el) {
    # The binding is lexical: the model comes from the enclosing ai:model.
    my $denied = eval { require Amin::AI::Model; Amin::AI::Model->current_denied } || 0;
    return if $denied;
    my $bind  = eval { require Amin::AI::Model; Amin::AI::Model->current_binding } // {};
    my $model = $bind->{model} // 'amin-embed-384';
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

        my ($doc_hash, $doc_size) = $self->_bc_put(\$doc);
        my ($emb_hash, $emb_size) = $self->_bc_put(\$vec_bytes);

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
