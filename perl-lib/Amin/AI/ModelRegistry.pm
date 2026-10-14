package Amin::AI::ModelRegistry;
use v5.38; use warnings; use utf8; use experimental 'signatures';

use constant {
    RC_AI_MODEL_DENIED  => -6145,
    RC_AI_SCOPE_DENIED  => -6146,
    TIER_STUB           => 0,
    TIER_HUMAN_SIGNED   => 2,
};

my %MODEL_ALLOW = (
    'amin-embed-384' => {
        tier           => TIER_STUB,
        max_context    => 8192,
        kind           => 'embedding',
        allowed_scopes => undef,
    },
    'amin-chat-7b' => {
        tier           => TIER_STUB,
        max_context    => 32768,
        kind           => 'chat',
        allowed_scopes => undef,
    },
);

sub list_models ($pkg_or_self) { keys %MODEL_ALLOW }

sub is_allowed ($pkg_or_self, $model_id) {
    return 0 unless defined $model_id && length $model_id;
    return exists $MODEL_ALLOW{$model_id};
}

sub model_meta ($pkg_or_self, $model_id) {
    return undef unless defined $model_id && length $model_id;
    return $MODEL_ALLOW{$model_id};
}

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
    $MODEL_ALLOW{$model_id} = {
        tier           => $meta{tier}           // TIER_STUB,
        max_context    => $meta{max_context}    // 4096,
        kind           => $meta{kind}           // 'chat',
        allowed_scopes => $meta{allowed_scopes} // undef,
    };
    return;
}

1;
