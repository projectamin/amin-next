package Amin::AI::Provider::OpenAICompat;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI::Provider::Base';

use JSON::PP;

# ═══════════════════════════════════════════════════════════════════════════
# Chat-completions hop that can return an artifact.  OpenRouter's music
# models ride this shape: POST /chat/completions with modalities => [text,
# audio].  Text-only replies come back as one JSON body; an audio reply
# requires stream:true and arrives as SSE frames with the audio base64-split
# across choices[].delta.audio.data, so the hop switches to post_sse().
# ═══════════════════════════════════════════════════════════════════════════

sub submit ($self, $req) {
    return { state => 'error', msg => 'provider needs base and key' } unless $self->has_hop;

    my $url = $self->join_url($self->{base}, 'chat/completions');
    my @msgs;
    push @msgs, { role => 'system', content => $req->{style} } if length($req->{style} // '');
    push @msgs, { role => 'user',   content => $self->_user_text($req) };

    my %body = (
        model    => ($self->{upstream} || $req->{model} || ''),
        messages => \@msgs,
    );
    my $mods = $req->{modalities};
    my $wants_audio = 0;
    if (ref $mods eq 'ARRAY') {
        $body{modalities} = $mods if @$mods;
        $wants_audio = 1 if grep { $_ eq 'audio' } @$mods;
    }
    if (ref $req->{audio} eq 'HASH' && %{ $req->{audio} }) {
        $body{audio} = $req->{audio};
        $wants_audio = 1;
    }

    # audio output requires stream:true; the artifact rides the SSE frames.
    my $r;
    if ($wants_audio || $req->{stream}) {
        $body{stream} = JSON::PP::true;
        $r = $self->post_sse($url, \%body, { on_progress => $req->{on_progress} });
    }
    else {
        $r = $self->post_json($url, \%body);
    }
    return { state => 'error', msg => $r->{msg} // 'provider request failed' } unless $r->{ok};

    my ($bytes, $mime) = $self->extract_audio($r->{obj});
    return { state => 'error', msg => 'provider returned no audio' } unless length($bytes // '');
    return {
        state    => 'done',
        audio    => $bytes,
        mime     => $mime // 'audio/mpeg',
        model    => $body{model},
        progress => 100,
    };
}

sub _user_text ($self, $req) {
    my @p;
    push @p, $req->{prompt} if length($req->{prompt} // '');
    push @p, "Lyrics:\n$req->{lyrics}" if length($req->{lyrics} // '');
    return join("\n\n", @p);
}

1;
