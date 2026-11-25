package Amin::AI::Model;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI';

use Amin::AI qw(AI_NS);
use Amin::AI::ModelRegistry;

# ═══════════════════════════════════════════════════════════════════════════
# Amin::AI::Model — the profile's AI binding, captured by LEXICAL NESTING.
#
# amin-legacy convention: the container names the thing, its children are its
# parts (mount.xml: <amin:command name="mount"><amin:flag>…).  Here the
# provider is the outer container, the model nests inside it, and the action
# nests inside the model — the whole chain is inherited by position, with no
# back-reference:
#
#   <ai:provider id="openai" api="openai" base="https://…" key="…">
#     <ai:model id="amin-chat-cloud" upstream="gpt-4o-mini">
#       <ai:request><ai:prompt>…</ai:prompt></ai:request>
#     </ai:model>
#   </ai:provider>
#
# This filter owns the scope stack: it pushes on ai:provider / ai:model
# start_element and pops on the matching end_element, so current_binding()
# returns the innermost scope.  The action filters (Gate / Inference / Music /
# Models / Embed / Memory) simply read it — they never look for a model
# attribute on their own element.
#
# The profile is the definition; this filter does not rewrite it.  A request
# that carries base/key/upstream is refused (an ai:result kind=error is added)
# — the element itself is still forwarded unchanged.
# ═══════════════════════════════════════════════════════════════════════════

use constant RC_AI_MODEL_INJECT => Amin::AI::ModelRegistry::RC_AI_MODEL_INJECT;

# Attributes that may never appear on an action element: the hop is owned by
# ai:provider and the model by ai:model, so an action carrying them is an
# injection attempt.
my %REQUEST_INJECT = map { $_ => 1 }
    qw(base key url href host endpoint authorization token secret
       authorization_header api_key apikey upstream);
# Attributes that may never appear on ai:model: the hop lives on ai:provider.
# (upstream/kind are allowed here — they are the model's own parts.)
my %HOP_ON_MODEL = map { $_ => 1 }
    qw(key token secret authorization authorization_header api_key apikey
       base url href host endpoint);

# Action elements: the leaves that consume a binding.  Each start clears the
# per-action inject latch so a denied sibling never poisons the next action.
my %ACTION = map { $_ => 1 } qw(request embed music models query);

{
    my @STACK;          # lexical scopes: { kind, binding, denied, reason }
    my $REQ_DENIED = 0; # per-action inject latch (reset on each action start)

    # Innermost scope's binding, or undef when no ai:provider/ai:model encloses.
    sub current_binding ($pkg_or_self) {
        return @STACK ? $STACK[-1]{binding} : undef;
    }

    # Fail-closed: a denied declaration or an inject action taints the scope.
    sub current_denied ($pkg_or_self) {
        return 1 if $REQ_DENIED;
        for my $e (@STACK) { return 1 if $e->{denied} }
        return 0;
    }

    sub _reset_for_tests ($pkg_or_self) {
        @STACK = ();
        $REQ_DENIED = 0;
        Amin::AI::ModelRegistry->reset_extras;
    }

    sub _clear_current {
        @STACK = ();
        $REQ_DENIED = 0;
        Amin::AI::ModelRegistry->reset_extras;
        return;
    }

    sub _push_scope ($kind, $binding) {
        my $e = { kind => $kind, binding => $binding, denied => 0 };
        push @STACK, $e;
        return $e;
    }

    sub _pop_scope ($kind) {
        pop @STACK if @STACK && $STACK[-1]{kind} eq $kind;
        return;
    }

    sub _begin_action { $REQ_DENIED = 0; return; }
    sub _deny_action  { $REQ_DENIED = 1; return; }
}

sub name     { '' }
sub element  { '' }
sub position { 'begin' }

sub start_document ($self, $doc = {}) {
    _clear_current();
    return $self->SUPER::start_document($doc);
}

sub _has_attr ($self, $el, $set) {
    my $attrs = $el->{Attributes} // {};
    for my $a (values %$attrs) {
        next unless ref $a eq 'HASH';
        my $ln = lc($a->{LocalName} // '');
        return 1 if $set->{$ln};
    }
    return 0;
}

# Fill a model scope from the enclosing scope (provider + hop) plus the model's
# own parts (upstream / kind).  No provider= back-reference: the provider is
# the lexical parent.
sub _capture_model ($self, $el, $id, $entry) {
    my $b        = $entry->{binding};
    my $provider = $b->{provider} // '';
    my $upstream = $self->_attr($el, 'upstream') // ($b->{upstream} // '');
    my $kind     = $self->_attr($el, 'kind')     // ($b->{kind} // '');
    $provider = 'stub' unless length $provider;
    $kind     = 'chat' unless length $kind;
    $b->{model}    = $id;
    $b->{provider} = $provider;
    $b->{upstream} = $upstream if length $upstream;
    $b->{kind}     = $kind;
    Amin::AI::ModelRegistry->register_model($id,
        provider => $provider,
        upstream => length $upstream ? $upstream : undef,
        kind     => $kind,
    );
    return;
}

sub start_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    if ($ns eq AI_NS()) {
        if ($ln eq 'provider') {
            my $id   = $self->_attr($el, 'id') // $self->_attr($el, 'name') // '';
            my $base = $self->_attr($el, 'base') // '';
            my $key  = $self->_attr($el, 'key')  // '';
            my $up   = $self->_attr($el, 'upstream') // '';
            my $timeout = $self->_attr($el, 'timeout') // '';
            my $api  = $self->_attr($el, 'api') // '';
            my $parent = current_binding(__PACKAGE__) // {};
            my %b = %$parent;
            $b{provider} = length $id ? $id : ($parent->{provider} // '');
            $b{base}     = $base;
            $b{key}      = $key;
            $b{upstream} = $up      if length $up;
            $b{timeout}  = $timeout if length $timeout;
            $b{api}      = $api     if length $api;
            _push_scope('provider', \%b);
        }
        elsif ($ln eq 'model') {
            my $id = $self->_attr($el, 'id') // $self->_attr($el, 'model') // '';
            my $entry = _push_scope('model', { %{ current_binding(__PACKAGE__) // {} } });
            if (!length $id) {
                $entry->{denied} = 1;
                $entry->{reason} = 'model missing id';
                $self->_emit_ai('result',
                    kind      => 'error',
                    rc        => Amin::AI::ModelRegistry::RC_AI_MODEL_DENIED,
                    exit_kind => 'ai_model_denied',
                    msg       => 'ai:model missing id',
                );
            }
            elsif ($self->_has_attr($el, \%HOP_ON_MODEL)) {
                $entry->{denied} = 1;
                $entry->{reason} = 'inject';
                $self->_emit_ai('result',
                    kind      => 'error',
                    rc        => RC_AI_MODEL_INJECT,
                    exit_kind => 'ai_model_inject',
                    msg       => 'ai:model names the model; ai:provider carries the hop',
                    model     => $id,
                );
            }
            else {
                $self->_capture_model($el, $id, $entry);
            }
        }
        elsif ($ACTION{$ln}) {
            _begin_action();
            $self->_check_action($el) if $ln eq 'request';
        }
    }
    return $self->SUPER::start_element($el);
}

sub end_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    _pop_scope($ln) if $ns eq AI_NS() && ($ln eq 'provider' || $ln eq 'model');
    return $self->SUPER::end_element($el);
}

# An action that names base/key/upstream is an injection; an action that names
# a model disagreeing with its enclosing scope is a tamper signal.  Both are
# fail-closed: the action filters skip the element via current_denied().
sub _check_action ($self, $el) {
    my $cur   = current_binding(__PACKAGE__);
    my $model = $self->_attr($el, 'model') // '';
    if ($self->_has_attr($el, \%REQUEST_INJECT)) {
        _deny_action();
        $self->_emit_ai('result',
            kind      => 'error',
            rc        => RC_AI_MODEL_INJECT,
            exit_kind => 'ai_model_inject',
            msg       => 'ai:request must not set base/key/upstream',
            model     => length $model ? $model : ($cur->{model} // ''),
        );
    }
    elsif (length $model && $cur && length($cur->{model} // '')
           && $cur->{model} ne $model) {
        _deny_action();
        $self->_emit_ai('result',
            kind      => 'error',
            rc        => RC_AI_MODEL_INJECT,
            exit_kind => 'ai_model_inject',
            msg       => "ai:request model $model != enclosing $cur->{model}",
            model     => $model,
        );
    }
    return;
}

1;
