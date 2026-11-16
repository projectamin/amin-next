package Amin::AI::Provider::OpenRouter;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI::Provider::OpenAICompat';

# ═══════════════════════════════════════════════════════════════════════════
# OpenRouter serves music on its chat endpoint via the audio modality.
# This adapter only sets the defaults; the hop itself is the compat path.
# ═══════════════════════════════════════════════════════════════════════════

sub submit ($self, $req) {
    my %r = %$req;
    $r{modalities} = [ 'text', 'audio' ] unless ref $r{modalities} eq 'ARRAY' && @{ $r{modalities} };
    my %audio = ref $r{audio} eq 'HASH' ? %{ $r{audio} } : ();
    $audio{format} = $r{format} if length($r{format} // '');
    $r{audio} = \%audio if %audio;
    return $self->SUPER::submit(\%r);
}

1;
