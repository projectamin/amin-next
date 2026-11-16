package Amin::AI::Provider::OpenAICompat;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI::Provider::Base';

# ═══════════════════════════════════════════════════════════════════════════
# Sync chat-completions hop that can return an artifact.  OpenRouter's music
# models ride this shape: POST /chat/completions with modalities => [text,
# audio], then the audio comes back base64 in the message.
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
    $body{modalities} = $mods if ref $mods eq 'ARRAY' && @$mods;
    $body{audio} = $req->{audio} if ref $req->{audio} eq 'HASH' && %{ $req->{audio} };

    my $r = $self->post_json($url, \%body);
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
