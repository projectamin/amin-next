package Amin::AI::ModelRegistry;
use v5.38; use warnings; use utf8; use experimental 'signatures';

use constant {
    RC_AI_MODEL_DENIED  => -6145,
    RC_AI_SCOPE_DENIED  => -6146,
    RC_AI_MODEL_INJECT  => -6148,
    TIER_STUB           => 0,
    TIER_HUMAN_SIGNED   => 2,
};

my %MODEL_ALLOW = (
    'amin-embed-384' => {
        tier           => TIER_STUB,
        max_context    => 8192,
        kind           => 'embedding',
        provider       => 'stub',
        upstream       => undef,
        allowed_scopes => undef,
    },
    'amin-chat-7b' => {
        tier           => TIER_STUB,
        max_context    => 32768,
        kind           => 'chat',
        provider       => 'stub',
        upstream       => undef,
        allowed_scopes => undef,
    },
);

# Catalog file entries (and tests) land here so reset_extras can
# drop them without losing the two stock ids.
my %MODEL_EXTRA;

sub list_models ($pkg_or_self) {
    return keys %MODEL_ALLOW, keys %MODEL_EXTRA;
}

sub is_allowed ($pkg_or_self, $model_id) {
    return 0 unless defined $model_id && length $model_id;
    return exists $MODEL_EXTRA{$model_id} || exists $MODEL_ALLOW{$model_id};
}

sub model_meta ($pkg_or_self, $model_id) {
    return undef unless defined $model_id && length $model_id;
    return $MODEL_EXTRA{$model_id} if exists $MODEL_EXTRA{$model_id};
    return $MODEL_ALLOW{$model_id};
}

sub reset_extras ($pkg_or_self) { %MODEL_EXTRA = (); return; }

sub scope_allows ($pkg_or_self, $model_id, $scope_attrs = {}) {
    my $meta = $pkg_or_self->model_meta($model_id) or return 0;
    my $allowed = $meta->{allowed_scopes};
    return 1 unless defined $allowed && @$allowed;
    my $tier = $scope_attrs->{tiers} // [];
    for my $t (@$tier) {
        return 1 if grep { $_ eq $t } @$allowed;
    }
    return 0;
}

sub register_model ($pkg_or_self, $model_id, %meta) {
    return unless defined $model_id && length $model_id;
    $MODEL_EXTRA{$model_id} = {
        tier           => $meta{tier}           // TIER_STUB,
        max_context    => $meta{max_context}    // 4096,
        kind           => $meta{kind}           // 'chat',
        provider       => $meta{provider}       // 'stub',
        upstream       => $meta{upstream},
        allowed_scopes => $meta{allowed_scopes} // undef,
    };
    return;
}

# File catalog only. Document <ai:catalog> is not a source — that would
# let a turn inject provider/upstream. base/key/url attributes are ignored.
sub load_catalog_file ($pkg_or_self, $path) {
    return 0 unless defined $path && length $path && -f $path;
    require XML::LibXML;
    my $doc = eval { XML::LibXML->load_xml(location => $path) };
    return 0 unless $doc;
    my $AI = 'http://projectamin.org/ns/ai/1';
    my $n = 0;
    for my $node ($doc->findnodes('//*[local-name()="model"]')) {
        my $id = $node->getAttributeNS($AI, 'id');
        $id = $node->getAttribute('id') unless defined $id && length $id;
        next unless defined $id && length $id;
        my $provider = $node->getAttributeNS($AI, 'provider');
        $provider = $node->getAttribute('provider')
            unless defined $provider && length $provider;
        my $upstream = $node->getAttributeNS($AI, 'upstream');
        $upstream = $node->getAttribute('upstream')
            unless defined $upstream && length $upstream;
        my $kind = $node->getAttributeNS($AI, 'kind');
        $kind = $node->getAttribute('kind') unless defined $kind && length $kind;
        $pkg_or_self->register_model($id,
            provider => $provider || 'stub',
            upstream => (defined $upstream && length $upstream) ? $upstream : undef,
            kind     => $kind || 'chat',
        );
        $n++;
    }
    return $n;
}

1;
