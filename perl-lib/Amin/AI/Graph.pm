package Amin::AI::Graph;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI::Article';

use Amin::AI qw(AI_NS);

my @ACCEL_NAMES = qw(none cuda rocm neural-engine tpu);
my @AI_TIER_NAMES = qw(none ai-cpu ai-gpu ai-embed);

sub name     { '' }
sub element  { undef }
sub position { 'late' }

sub start_document ($self, $doc = {}) {
    $self->SUPER::start_document($doc);
    return;
}

sub start_element ($self, $el) {
    my $ret = $self->SUPER::start_element($el);
    unless ($self->{_emitted}) {
        $self->{_emitted} = 1;
        $self->_emit_graph;
    }
    return $ret;
}

sub _emit_graph ($self) {
    my $h = $self->Handler or return;
    my $AI = AI_NS();

    my @peers;
    eval {
        require Amin::Discovery::Mesh;
        my $mesh = Amin::Discovery::Mesh->new;
        @peers = $mesh->peers;
    };

    my %graph_attrs = ($self->_provenance_attrs(tier => 0, model_id => 'mesh-graph'), $self->_xmlns_ai_attr);
    $graph_attrs{'{}node_count'} = {
        Name => 'ai:node_count', LocalName => 'node_count', Prefix => 'ai',
        NamespaceURI => $AI, Value => scalar(@peers),
    };

    $h->start_element({
        NamespaceURI => $AI, LocalName => 'graph',
        Name => 'ai:graph', Prefix => 'ai', Attributes => \%graph_attrs,
    });

    for my $p (@peers) {
        my $nid = $p->{node_id};
        $nid = unpack('H*', $nid) if defined $nid && length($nid) == 32;
        my $accel = $ACCEL_NAMES[$p->{accelerator} // 0] // 'none';
        my $aitier = $AI_TIER_NAMES[$p->{ai_tier} // 0] // 'none';
        my %attrs = (
            '{}id' => { Name => 'ai:id', LocalName => 'id', Prefix => 'ai',
                NamespaceURI => $AI, Value => $nid // '' },
            '{}tier' => { Name => 'ai:tier', LocalName => 'tier', Prefix => 'ai',
                NamespaceURI => $AI, Value => $p->{tier} // '' },
            '{}zone' => { Name => 'ai:zone', LocalName => 'zone', Prefix => 'ai',
                NamespaceURI => $AI, Value => $p->{zone} // '' },
            '{}load' => { Name => 'ai:load', LocalName => 'load', Prefix => 'ai',
                NamespaceURI => $AI, Value => $p->{load_pct} // 0 },
            '{}free_mem_mb' => { Name => 'ai:free_mem_mb', LocalName => 'free_mem_mb',
                Prefix => 'ai', NamespaceURI => $AI, Value => $p->{free_mem_MB} // 0 },
            '{}free_vram_mb' => { Name => 'ai:free_vram_mb', LocalName => 'free_vram_mb',
                Prefix => 'ai', NamespaceURI => $AI, Value => $p->{free_vram_MB} // 0 },
            '{}accelerator' => { Name => 'ai:accelerator', LocalName => 'accelerator',
                Prefix => 'ai', NamespaceURI => $AI, Value => $accel },
            '{}ai_tier' => { Name => 'ai:ai_tier', LocalName => 'ai_tier',
                Prefix => 'ai', NamespaceURI => $AI, Value => $aitier },
        );
        $h->start_element({
            NamespaceURI => $AI, LocalName => 'node',
            Name => 'ai:node', Prefix => 'ai', Attributes => \%attrs,
        });
        $h->end_element({
            NamespaceURI => $AI, LocalName => 'node',
            Name => 'ai:node', Prefix => 'ai',
        });
    }

    $h->end_element({
        NamespaceURI => $AI, LocalName => 'graph',
        Name => 'ai:graph', Prefix => 'ai',
    });

    return;
}

1;
