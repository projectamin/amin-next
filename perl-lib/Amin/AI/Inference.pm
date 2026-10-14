package Amin::AI::Inference;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI::Article';

use Amin::AI qw(AI_NS);
use Amin::AI::ModelRegistry;

sub name    { '' }
sub element { 'request' }
sub position { 'middle' }

sub on_article_close ($self, $el) {
    my $model  = $self->_attr($el, 'model') // '';
    return unless length $model;
    return unless Amin::AI::ModelRegistry->is_allowed($model);

    my $prompt_parts = $self->_child_vals('prompt');
    my $prompt = join("\n", @$prompt_parts);
    my $tokens_in  = length($prompt);
    my $response = $self->_stub_inference($model, $prompt);
    my $tokens_out = length($response);

    my $h = $self->Handler or return;
    my $AI = AI_NS();
    my %attrs = (
        model      => $model,
        tokens_in  => $tokens_in,
        tokens_out => $tokens_out,
        latency_ms => 0,
    );
    my %sax_attrs = ($self->_provenance_attrs(tier => 0, model_id => $model), $self->_xmlns_ai_attr);
    for my $k (keys %attrs) {
        $sax_attrs{"{}" . $k} = {
            Name         => "ai:$k",
            LocalName    => $k,
            Prefix       => 'ai',
            NamespaceURI => $AI,
            Value        => "$attrs{$k}",
        };
    }
    $h->start_element({
        NamespaceURI => $AI, LocalName => 'result',
        Name => 'ai:result', Prefix => 'ai', Attributes => \%sax_attrs,
    });
    $h->start_element({
        NamespaceURI => $AI, LocalName => 'stream',
        Name => 'ai:stream', Prefix => 'ai',
        Attributes => {
            '{}channel' => {
                Name => 'ai:channel', LocalName => 'channel',
                Prefix => 'ai', NamespaceURI => $AI, Value => 'response',
            },
        },
    });
    $h->characters({ Data => $response });
    $h->end_element({
        NamespaceURI => $AI, LocalName => 'stream',
        Name => 'ai:stream', Prefix => 'ai',
    });
    $h->end_element({
        NamespaceURI => $AI, LocalName => 'result',
        Name => 'ai:result', Prefix => 'ai',
    });
    return;
}

sub _stub_inference ($self, $model, $prompt) {
    return "[stub:$model] " . substr($prompt, 0, 200);
}

1;
