package Amin::AI::Memory;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI::Article';

use Amin::AI qw(AI_NS);
use Amin::AI::ModelRegistry;
use Amin::AI::VectorIndex;

sub name     { '' }
sub element  { 'query' }
sub position { 'middle' }

sub on_article_close ($self, $el) {
    my $model = $self->_attr($el, 'model') // 'amin-embed-384';
    return unless Amin::AI::ModelRegistry->is_allowed($model);

    my $queries = $self->_child_vals('prompt');
    push @$queries, @{ $self->_child_vals('text') };
    return unless @$queries;

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

    my $k = $self->_attr($el, 'top-k') // 3;
    $k = 3 unless $k =~ /^\d+$/ && $k > 0;

    for my $q (@$queries) {
        my $qvec = Amin::AI::VectorIndex->pseudo_embed($q);
        my $results = $idx->search($qvec, $k);

        my %ctx_attrs = ($self->_provenance_attrs(tier => 0, model_id => $model), $self->_xmlns_ai_attr);
        $ctx_attrs{'{}query'} = {
            Name => 'ai:query', LocalName => 'query', Prefix => 'ai',
            NamespaceURI => $AI, Value => substr($q, 0, 200),
        };
        $ctx_attrs{'{}model'} = {
            Name => 'ai:model', LocalName => 'model', Prefix => 'ai',
            NamespaceURI => $AI, Value => $model,
        };
        $ctx_attrs{'{}count'} = {
            Name => 'ai:count', LocalName => 'count', Prefix => 'ai',
            NamespaceURI => $AI, Value => scalar @$results,
        };

        $h->start_element({
            NamespaceURI => $AI, LocalName => 'context',
            Name => 'ai:context', Prefix => 'ai', Attributes => \%ctx_attrs,
        });

        for my $r (@$results) {
            my %ref_attrs = (
                '{}hash' => { Name => 'bc:hash', LocalName => 'hash', Prefix => 'bc', NamespaceURI => $BC, Value => $r->{doc_hash} },
                '{}kind' => { Name => 'bc:kind', LocalName => 'kind', Prefix => 'bc', NamespaceURI => $BC, Value => 'document' },
            );
            $h->start_element({ NamespaceURI => $BC, LocalName => 'object', Name => 'bc:object', Prefix => 'bc', Attributes => \%ref_attrs });
            $h->end_element({ NamespaceURI => $BC, LocalName => 'object', Name => 'bc:object', Prefix => 'bc' });
        }

        $h->end_element({
            NamespaceURI => $AI, LocalName => 'context',
            Name => 'ai:context', Prefix => 'ai',
        });
    }

    return;
}

1;
