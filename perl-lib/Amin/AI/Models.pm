package Amin::AI::Models;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI';

use Amin::AI qw(AI_NS);
use Amin::AI::ModelRegistry;
use Amin::AI::Provider::Registry;

use constant RC_AI_PROVIDER_ERROR => -6147;

# ═══════════════════════════════════════════════════════════════════════════
# Amin::AI::Models — discovery: the provider's catalog, filtered to the models
# that can make music.
#
#   <ai:provider id="openai" api="openai" base="https://…" key="…">
#     <ai:model id="amin-models" kind="models">
#       <ai:models/>
#     </ai:model>
#   </ai:provider>
#
# The lexically enclosing provider is the whole input; the element is empty.
# The adapter's list_models() does the hop, this filter keeps the music-capable
# entities and emits them as an <ai:catalog> (id/name/upstream/kind), then
# registers each one so a later turn can name it.  The key rides only in the
# dispatched profile and in the provider object, never in the catalog or an
# error (the provider already redacts it).
# ═══════════════════════════════════════════════════════════════════════════

# Adapters default to the OpenAI list shape; the filter tolerates {data:[…]},
# {models:[…]} and a bare array.
#
# Each hint is word-anchored: `udio` (the brand) must not match the `audio`
# inside every audio-*input* model's modality string.
my @MUSIC_HINT = (
    'suno', 'udio', 'music', 'song', 'lyria', 'mureka',
    'ace[-\s]?step', 'acestep', 'riff(?:usion)?',
    'stable[-\s]?audio', 'audioldm', 'musicgen',
);

sub name     { '' }
sub element  { 'models' }
sub position { 'middle' }

sub on_article_close ($self, $el) {
    my $denied = eval { require Amin::AI::Model; Amin::AI::Model->current_denied } || 0;
    return if $denied;

    my $bind = eval { require Amin::AI::Model; Amin::AI::Model->current_binding } // {};

    my $provider = eval {
        Amin::AI::Provider::Registry->for_binding({
            id       => $bind->{provider} // '',
            api      => $bind->{api}      // '',
            provider => $bind->{provider} // '',
            base     => $bind->{base}     // '',
            key      => $bind->{key}      // '',
            kind     => $bind->{kind}     // '',
            timeout  => $bind->{timeout}  // 120,
        });
    };
    if (!$provider) {
        $self->_error('no provider adapter for this binding');
        return;
    }
    if (!$provider->has_hop) {
        $self->_error('ai:provider needs both base and key');
        return;
    }

    my $res = eval { $provider->list_models };
    $res = { ok => 0, msg => $@ } if $@;
    if (ref($res) ne 'HASH' || !$res->{ok}) {
        $self->_error((ref($res) eq 'HASH' ? ($res->{msg} // '') : '')
            || 'model discovery failed');
        return;
    }

    my $pid    = $bind->{provider} // '';
    my $models = _music_models($res->{obj});
    $self->_emit_catalog($pid, $bind->{base} // '', $models);

    for my $m (@$models) {
        Amin::AI::ModelRegistry->register_model($m->{id},
            kind     => 'music',
            provider => length $pid ? $pid : 'stub',
            upstream => $m->{id},
        );
    }
    return;
}

sub _error ($self, $msg) {
    $self->_emit_ai('result',
        kind      => 'error',
        rc        => RC_AI_PROVIDER_ERROR,
        exit_kind => 'ai_provider_error',
        msg       => $msg,
    );
    return;
}

# ── catalog shape ───────────────────────────────────────────────────────
sub _entries ($obj) {
    my $list = ref $obj eq 'ARRAY'                ? $obj
             : ref($obj) eq 'HASH'
               && ref $obj->{data}   eq 'ARRAY'   ? $obj->{data}
             : ref($obj) eq 'HASH'
               && ref $obj->{models} eq 'ARRAY'   ? $obj->{models}
             : return [];
    my @out;
    for my $e (@$list) {
        if (!ref $e) {
            next unless defined $e && length $e;
            push @out, { id => "$e" };
            next;
        }
        next unless ref $e eq 'HASH';
        my $id = $e->{id} // $e->{model} // $e->{name};
        next unless defined $id && !ref $id && length $id;
        my $name = $e->{name} // $e->{display_name} // $e->{title} // '';
        $name = '' if ref $name;
        push @out, { id => "$id", name => "$name", entry => $e };
    }
    return \@out;
}

sub _music_models ($obj) {
    my @out;
    for my $m (@{ _entries($obj) }) {
        next unless _is_music($m);
        push @out, { id => $m->{id}, name => $m->{name} };
    }
    return \@out;
}

# Capability metadata first; identity keywords only when the catalog is silent.
#
# An audio *input* is not an audio output.  OpenRouter lists audio-input
# models with `architecture.modality: "text+audio+…->text"`; matching the word
# "audio" anywhere admitted Gemini/Qwen Omni/Voxtral as music models, and the
# hop then failed with "no endpoints support text, audio".  So the declared
# output is authoritative when present, and a music identity is still needed:
# a conversational audio model (GPT Audio) emits audio but makes no music.
sub _is_music ($m) {
    my $e    = $m->{entry} // {};

    # Capability text only — an id/name/description is identity, not a claim
    # about what the model emits.
    my $caps = lc join ' ',
        _flat($e->{capabilities}), _flat($e->{kind}), _flat($e->{type}),
        _flat($e->{tags}), _flat($e->{category});
    my $declared_music = $caps =~ /\bmusic\b/
        || $caps =~ /\baudio[_\s-]?(?:generation|gen|synthesis)\b/;

    # Hard exclusions: these cannot make music.  An explicit music capability
    # tag wins over a neighbouring word (e.g. a "speech" tag on a song model).
    if (!$declared_music && $caps =~ /\b(?:embeddings?|embed|tts|text[-\s]to[-\s]speech|
            speech|transcri\w*|whisper|rerank\w*|image[_\s-]?gen\w*)\b/x) {
        return 0;
    }

    # What the catalog says the model emits.  OpenRouter carries this in
    # architecture.{output_modalities,modality}; compat catalogs are silent.
    my ($declares_output, $emits_audio) = (0, 0);
    my $out = lc _flat($e->{output_modalities});
    if (length $out) {
        $declares_output = 1;
        $emits_audio = 1 if $out =~ /\baudio\b/;
    }
    my $arch = $e->{architecture};
    if (ref $arch eq 'HASH') {
        if (defined $arch->{output_modalities}) {
            $declares_output = 1;
            $emits_audio = 1 if lc(_flat($arch->{output_modalities})) =~ /\baudio\b/;
        }
        # `modality` is "inputs->outputs"; only the right-hand side counts.
        if (defined $arch->{modality} && !ref $arch->{modality}
                && $arch->{modality} =~ /->\s*(.+)\z/) {
            $declares_output = 1;
            $emits_audio = 1 if lc($1) =~ /\baudio\b/;
        }
    }

    # Identity: a music name/brand, or a description that calls it music.
    my $identity = lc join ' ',
        (defined $m->{id} ? $m->{id} : ''),
        (defined $m->{name} ? $m->{name} : ''),
        _flat($e->{description}), $caps;
    my $hint = join '|', map { "\\b(?:$_)\\b" } @MUSIC_HINT;
    my $named_music = ($declared_music || $identity =~ /(?:$hint)/) ? 1 : 0;

    # A catalog that declares outputs is authoritative: music must actually
    # emit audio.  A silent catalog leaves the name as the only evidence.
    return 0 if $declares_output && !$emits_audio;
    return 0 unless $named_music;
    return 1;
}

# Flatten an arbitrary JSON value to lower-case text, keeping object keys: a
# capability can be a string, an array, or {output_modalities:["audio"]}.
sub _flat ($v) {
    return '' unless defined $v;
    return "$v" unless ref $v;
    return join ' ', map { _flat($_) } @$v if ref $v eq 'ARRAY';
    return join ' ', map { $_, _flat($v->{$_}) } sort keys %$v if ref $v eq 'HASH';
    return '';
}

sub _emit_catalog ($self, $provider, $base, $models) {
    my $h = $self->Handler or return;
    my $AI = AI_NS();
    my %at = (
        _ai_attr('provider', $provider),
        _ai_attr('base',     $base),
        _ai_attr('count',    scalar @$models),
    );
    $h->start_element({
        NamespaceURI => $AI, LocalName => 'catalog',
        Name => 'ai:catalog', Prefix => 'ai', Attributes => \%at,
    });
    for my $m (@$models) {
        my %ma = (
            _ai_attr('id',       $m->{id}),
            _ai_attr('name',     $m->{name} // ''),
            _ai_attr('upstream', $m->{id}),
            _ai_attr('kind',     'music'),
            _ai_attr('provider', $provider),
        );
        $h->start_element({
            NamespaceURI => $AI, LocalName => 'model',
            Name => 'ai:model', Prefix => 'ai', Attributes => \%ma,
        });
        $h->end_element({
            NamespaceURI => $AI, LocalName => 'model',
            Name => 'ai:model', Prefix => 'ai',
        });
    }
    $h->end_element({
        NamespaceURI => $AI, LocalName => 'catalog',
        Name => 'ai:catalog', Prefix => 'ai',
    });
    return;
}

sub _ai_attr ($ln, $v) {
    my $AI = AI_NS();
    return ('{}' . $ln => {
        Name => "ai:$ln", LocalName => $ln, Prefix => 'ai',
        NamespaceURI => $AI, Value => defined $v ? "$v" : '',
    });
}

1;
