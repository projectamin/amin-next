package Amin::AI::Gate;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI';

use Amin::AI qw(AI_NS);
use Amin::AI::ModelRegistry;

use constant {
    RC_AI_MODEL_DENIED => Amin::AI::ModelRegistry::RC_AI_MODEL_DENIED,
    RC_AI_SCOPE_DENIED => Amin::AI::ModelRegistry::RC_AI_SCOPE_DENIED,
};

sub name    { '' }
sub element { 'request' }
sub position { 'begin' }

sub on_article_close ($self, $el) {
    # The binding is lexical: the model comes from the enclosing ai:model.
    # Model already flagged an inject/denial for this request — skip it.
    my $denied = eval { require Amin::AI::Model; Amin::AI::Model->current_denied } || 0;
    return if $denied;

    my $bind  = eval { require Amin::AI::Model; Amin::AI::Model->current_binding } // {};
    my $model = $bind->{model} // '';
    unless (length $model) {
        $self->_emit_ai('result',
            kind      => 'error',
            rc        => RC_AI_MODEL_DENIED,
            exit_kind => 'ai_model_denied',
            msg       => 'ai:request has no enclosing ai:model',
        );
        return;
    }

    unless (Amin::AI::ModelRegistry->is_allowed($model)) {
        $self->_emit_ai('result',
            kind      => 'error',
            rc        => RC_AI_MODEL_DENIED,
            exit_kind => 'ai_model_denied',
            msg       => "model not in allowlist: $model",
        );
        return;
    }

    my $scope;
    eval {
        require Amin::Auth::ZCap;
        $scope = Amin::Auth::ZCap->current_scope_attrs;
    };
    if (defined $scope && !Amin::AI::ModelRegistry->scope_allows($model, $scope)) {
        $self->_emit_ai('result',
            kind      => 'error',
            rc        => RC_AI_SCOPE_DENIED,
            exit_kind => 'ai_scope_denied',
            msg       => "model $model not permitted by ZCap scope",
        );
        return;
    }

    return;
}

1;
