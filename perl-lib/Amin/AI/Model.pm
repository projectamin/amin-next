package Amin::AI::Model;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI';

use Amin::AI qw(AI_NS);
use Amin::AI::ModelRegistry;

# The profile is the definition. This filter does not rewrite it.
# UI (or a signed transform outside this pipeline) writes:
#   <ai:provider id="openai" base="https://…" key="…"/>
#   <ai:model id="amin-chat-cloud" provider="openai" upstream="gpt-4o-mini"/>
#   <ai:request model="amin-chat-cloud"/>
# We capture those elements as written. Inference hops from that
# capture. A request that carries base/key/upstream is refused
# (add ai:result kind=error) — the request element is still forwarded
# unchanged. Transforms belong outside: write a new profile, sign,
# re-execute.

use constant RC_AI_MODEL_INJECT => Amin::AI::ModelRegistry::RC_AI_MODEL_INJECT;

my %REQUEST_INJECT = map { $_ => 1 }
    qw(base key url href host endpoint authorization token secret
       authorization_header api_key apikey upstream);
my %HOP_ON_MODEL = map { $_ => 1 }
    qw(key token secret authorization authorization_header api_key apikey
       base url href host endpoint);

{
    my $CURRENT;

    sub current_binding ($pkg_or_self) { $CURRENT }
    sub current_denied  ($pkg_or_self) { $CURRENT && $CURRENT->{denied} ? 1 : 0 }

    sub _reset_for_tests ($pkg_or_self) {
        $CURRENT = undef;
        Amin::AI::ModelRegistry->reset_extras;
    }

    sub _clear_current {
        $CURRENT = undef;
        Amin::AI::ModelRegistry->reset_extras;
        return;
    }

    sub _merge ($patch) {
        $CURRENT = { %{ $CURRENT // {} }, %$patch, denied => 0 };
        delete $CURRENT->{reason};
        return $CURRENT;
    }

    sub _deny ($model, $reason) {
        $CURRENT = {
            %{ $CURRENT // {} },
            model    => $model // ($CURRENT->{model} // ''),
            denied   => 1,
            reason   => $reason // 'denied',
        };
        return $CURRENT;
    }
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

sub _capture_model ($self, $el, $id) {
    my $provider = $self->_attr($el, 'provider') // '';
    my $upstream = $self->_attr($el, 'upstream') // '';
    my $kind     = $self->_attr($el, 'kind')     // '';
    my $cur      = current_binding(__PACKAGE__) // {};
    $provider = $cur->{provider} // 'stub' unless length $provider;
    $upstream = $cur->{upstream} // ''     unless length $upstream;
    $kind     = $cur->{kind}     // 'chat' unless length $kind;
    Amin::AI::ModelRegistry->register_model($id,
        provider => $provider,
        upstream => length $upstream ? $upstream : undef,
        kind     => $kind,
    );
    _merge({
        model    => $id,
        provider => $provider,
        upstream => length $upstream ? $upstream : undef,
        kind     => $kind,
    });
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
            my $cur  = current_binding(__PACKAGE__) // {};
            _merge({
                provider => length $id ? $id : ($cur->{provider} // ''),
                base     => $base,
                key      => $key,
                (length $up      ? (upstream => $up)      : ()),
                (length $timeout ? (timeout  => $timeout) : ()),
                (length $api     ? (api      => $api)     : ()),
            });
        }
        elsif ($ln eq 'model') {
            my $id = $self->_attr($el, 'id') // $self->_attr($el, 'model') // '';
            if (!length $id) {
                _deny('', 'model missing id');
                $self->_emit_ai('result',
                    kind      => 'error',
                    rc        => Amin::AI::ModelRegistry::RC_AI_MODEL_DENIED,
                    exit_kind => 'ai_model_denied',
                    msg       => 'ai:model missing id',
                );
            }
            elsif ($self->_has_attr($el, \%HOP_ON_MODEL)) {
                _deny($id, 'inject');
                $self->_emit_ai('result',
                    kind      => 'error',
                    rc        => RC_AI_MODEL_INJECT,
                    exit_kind => 'ai_model_inject',
                    msg       => 'ai:model names the id; ai:provider carries the hop',
                    model     => $id,
                );
            }
            else {
                $self->_capture_model($el, $id);
            }
        }
        elsif ($ln eq 'request') {
            my $model = $self->_attr($el, 'model') // '';
            my $cur   = current_binding(__PACKAGE__);
            if ($self->_has_attr($el, \%REQUEST_INJECT)) {
                _deny($model, 'inject');
                $self->_emit_ai('result',
                    kind      => 'error',
                    rc        => RC_AI_MODEL_INJECT,
                    exit_kind => 'ai_model_inject',
                    msg       => 'ai:request must not set base/key/upstream',
                    model     => $model,
                );
            }
            elsif (length $model && $cur && $cur->{model}
                   && !$cur->{denied} && $cur->{model} ne $model) {
                my $have = $cur->{model};
                _deny($model, 'mismatch');
                $self->_emit_ai('result',
                    kind      => 'error',
                    rc        => RC_AI_MODEL_INJECT,
                    exit_kind => 'ai_model_inject',
                    msg       => "request model $model != current $have",
                    model     => $model,
                );
            }
            elsif (length $model && (!$cur || !$cur->{model})
                   && Amin::AI::ModelRegistry->is_allowed($model)) {
                $self->_capture_model($el, $model);
            }
        }
    }
    return $self->SUPER::start_element($el);
}

1;
