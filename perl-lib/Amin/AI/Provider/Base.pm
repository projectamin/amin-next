package Amin::AI::Provider::Base;
use v5.38; use warnings; use utf8; use experimental 'signatures';

use JSON::PP;

# ═══════════════════════════════════════════════════════════════════════════
# Amin::AI::Provider::Base — the provider plugin interface.
#
# A provider adapter turns an ai: request into artifact bytes.  Two shapes:
#
#   sync  — submit() does the whole hop and returns a job already terminal
#           ({ state => 'done', audio => $bytes, mime => .. }).
#   async — submit() starts a remote task and returns a non-terminal job
#           ({ state => 'running', handle => .., poll_url => .., progress => n });
#           poll() advances it one step until terminal($job) is true.
#
# The filter that drives a provider never branches on which shape it is: it
# calls submit() then poll() until terminal(), emitting an ai:update per
# step.  A new provider is a new subclass registered by api id — no filter
# change, no dispatcher change.
#
# Tests replace $UA.  No process env is read for endpoints or keys.
# ═══════════════════════════════════════════════════════════════════════════

our $UA;

my %TERMINAL = ( done => 1, error => 1 );

sub new ($class, %o) {
    my %self = %o;
    $self{id}       //= '';
    $self{api}      = lc($self{api} // '');
    $self{provider} //= '';
    $self{base}     //= '';
    $self{key}      //= '';
    $self{kind}     //= '';
    $self{upstream} //= '';
    $self{timeout}  //= 120;
    return bless \%self, $class;
}

sub id       ($self) { $self->{id} }
sub api      ($self) { $self->{api} }
sub base     ($self) { $self->{base} }
sub key      ($self) { $self->{key} }
sub upstream ($self) { $self->{upstream} }

# A hop needs both an endpoint and a credential; one without the other is
# fail-closed (same rule the chat path enforces).
sub has_hop ($self) {
    (my $b = $self->{base} // '') =~ s/\s+//g;
    (my $k = $self->{key}  // '') =~ s/\s+//g;
    return (length($b) && length($k)) ? 1 : 0;
}

sub terminal ($self, $job) {
    return $TERMINAL{ $job->{state} // '' } ? 1 : 0;
}

# ── interface (subclasses override) ─────────────────────────────────────
sub submit ($self, $req) { return { state => 'error', msg => ref($self) . ' has no submit' } }
sub poll   ($self, $job) { return $job }

# Seconds the driving filter waits between polls; providers override (the
# offline stub returns 0 so tests never sleep).
sub poll_delay ($self) { 1 }

# ── HTTP helpers ────────────────────────────────────────────────────────
sub ua ($self) {
    return $UA if $UA;
    require HTTP::Tiny;
    my $t = $self->{timeout};
    $t = 120 unless defined $t && $t =~ /^\d+$/ && $t > 0;
    return HTTP::Tiny->new(timeout => 0 + $t, verify_SSL => 1, agent => 'waihanga-amin');
}

sub join_url ($self, $base, $path) {
    $base =~ s{/+$}{};
    $path =~ s{^/+}{};
    return length $path ? "$base/$path" : $base;
}

sub auth_headers ($self, $extra = {}) {
    return {
        'Content-Type'  => 'application/json',
        'Accept'        => 'application/json',
        'Authorization' => 'Bearer ' . ($self->{key} // ''),
        %$extra,
    };
}

sub post_json ($self, $url, $body) {
    my $payload = eval { JSON::PP->new->utf8->encode($body) };
    return { ok => 0, msg => 'failed to encode provider request' } unless defined $payload;
    my $res = eval { $self->ua->post($url, { headers => $self->auth_headers, content => $payload }) };
    return { ok => 0, msg => _clean($@ // 'provider request failed', $self->{key}) } if !$res || $@;
    return $self->_decode_result($res);
}

sub get_json ($self, $url) {
    my $res = eval { $self->ua->get($url, { headers => $self->auth_headers });
    };
    return { ok => 0, msg => _clean($@ // 'provider request failed', $self->{key}) } if !$res || $@;
    return $self->_decode_result($res);
}

# ── streaming SSE hop ───────────────────────────────────────────────────
# Endpoints that carry audio require stream:true (the chat-completions
# audio modality): the reply arrives as SSE frames with the artifact
# base64-split across choices[].delta.audio.data chunks.  This posts with
# Accept: text/event-stream, stitches the deltas back together and returns
# the same { ok => 1, obj => … } shape as post_json — the object is
# message-shaped so extract_audio() finds the artifact.  A body that is
# not SSE (the server ignored stream=true) is decoded as plain JSON.
sub post_sse ($self, $url, $body, $opts = {}) {
    my $payload = eval { JSON::PP->new->utf8->encode($body) };
    return { ok => 0, msg => 'failed to encode provider request' } unless defined $payload;

    # audio lands base64-split across frames; hand a caller the decoded byte
    # count as it grows so it can render live progress mid-submit.
    my $on_progress = $opts->{on_progress};
    my $st = { buf => '', raw => '', text => '', audio => '', format => '', err => '' };
    my $res = eval {
        $self->ua->post($url, {
            headers       => $self->auth_headers({ 'Accept' => 'text/event-stream' }),
            content       => $payload,
            data_callback => sub ($chunk, $r) {
                $st->{raw} .= $chunk // '';
                $self->_sse_accum($st, $chunk);
                $on_progress->(int(length($st->{audio}) * 3 / 4)) if $on_progress;
            },
        });
    };
    return { ok => 0, msg => _clean($@ // 'provider request failed', $self->{key}) } if !$res || $@;

    $self->_sse_accum($st, "\n") if length $st->{buf};
    my $raw = $res->{content} // '';
    $raw = $st->{raw} if !length($raw) && length($st->{raw});

    # a non-SSE body means the server ignored stream=true; fall back to
    # the sync shape (and surface its error message).
    if (!length $st->{text} && !length $st->{audio} && length $raw) {
        my $obj = eval { JSON::PP->new->utf8->decode($raw) };
        if (ref $obj eq 'HASH') {
            return $self->_sse_error($obj, $res) if !$res->{success};
            return { ok => 1, obj => $obj };
        }
    }
    return $self->_sse_error(undef, $res) if !$res->{success};

    my %msg = (content => $st->{text});
    if (length $st->{audio}) {
        $msg{audio} = { data => $st->{audio} };
        $msg{audio}{mime} = _mime_for($st->{format}) if length $st->{format};
    }
    return { ok => 1, obj => { choices => [ { message => \%msg } ] } };
}

sub _sse_error ($self, $obj, $res) {
    my $msg = $obj && ref $obj->{error} eq 'HASH' ? $obj->{error}{message} : undef;
    $msg //= $res->{reason} // 'provider request failed';
    $msg = "HTTP $res->{status}: $msg" if $res->{status};
    return { ok => 0, msg => _clean($msg, $self->{key}), status => $res->{status} };
}

# pull text + audio deltas out of each data: frame; tolerant of unknown
# frames.  audio arrives base64-split across frames — concatenate.
sub _sse_accum ($self, $st, $chunk) {
    $st->{buf} .= $chunk // '';
    while ($st->{buf} =~ s/^([^\n]*)\n//) {
        my $line = $1;
        $line =~ s/\r$//;
        next unless $line =~ s/^data:\s?//;
        next if $line eq '[DONE]';
        my $obj = eval { JSON::PP->new->utf8->decode($line) };
        next unless ref $obj eq 'HASH';
        if (ref $obj->{error} eq 'HASH') {
            $st->{err} ||= $obj->{error}{message};
            next;
        }
        my $ch = ref $obj->{choices} eq 'ARRAY' ? $obj->{choices}[0] : undef;
        next unless ref $ch eq 'HASH';
        my $d = ref $ch->{delta} eq 'HASH'   ? $ch->{delta}
              : ref $ch->{message} eq 'HASH' ? $ch->{message} : {};
        $st->{text} .= $d->{content} if defined $d->{content} && !ref $d->{content};
        if (ref $d->{audio} eq 'HASH') {
            my $a = $d->{audio};
            $st->{audio} .= $a->{data} if defined $a->{data} && !ref $a->{data};
            $st->{format} = $a->{format}
                if defined $a->{format} && !ref $a->{format} && length $a->{format};
        }
    }
}

my %MIME = (
    mp3   => 'audio/mpeg', wav => 'audio/wav', flac => 'audio/flac',
    opus  => 'audio/ogg',  aac => 'audio/aac', pcm16 => 'audio/L16',
);

sub _mime_for ($fmt) {
    $fmt = lc($fmt // '');
    return length $fmt ? ($MIME{$fmt} // "audio/$fmt") : '';
}

sub _decode_result ($self, $res) {
    my $body = $res->{content} // '';
    my $obj  = eval { JSON::PP->new->utf8->decode($body) };
    $obj = {} unless ref $obj eq 'HASH' || ref $obj eq 'ARRAY';
    if (!$res->{success}) {
        my $msg = (ref $obj eq 'HASH' && ref $obj->{error} eq 'HASH' ? $obj->{error}{message} : undef)
            // (ref $obj eq 'HASH' && !ref $obj->{error} ? $obj->{error} : undef)
            // $res->{reason}
            // 'provider request failed';
        $msg = "HTTP $res->{status}: $msg" if $res->{status};
        return { ok => 0, msg => _clean("$msg", $self->{key}), status => $res->{status} };
    }
    return { ok => 1, obj => $obj };
}

sub _clean ($s, $key) {
    $s = '' unless defined $s;
    $s =~ s/\s+/ /g;
    $s =~ s/\Q$key\E/[redacted]/g if defined $key && length $key;
    return substr($s, 0, 300);
}

# ── artifact extraction (generic, tolerant) ─────────────────────────────
# Walk a decoded provider response and return the first artifact payload as
# ($bytes, $mime).  Handles: data: URIs, base64 under audio-ish keys, and
# plain http(s) URLs (fetched).  Tolerant on purpose — task APIs differ.
sub extract_audio ($self, $obj) {
    my $hit = _deep_audio($obj, 0);
    return () unless $hit;
    my ($val, $mime) = @$hit;
    return (_b64_decode($1), $2) if $val =~ m{^data:([\w/+.-]+);base64,(.*)$}s;
    if ($val =~ m{^https?://}i) {
        my $res = eval { $self->ua->get($val, { headers => { 'Accept' => '*/*' } }) };
        return () unless $res && $res->{success};
        my $m = $res->{headers}{'content-type'} // $mime // 'audio/mpeg';
        $m =~ s/;.*//;
        return ($res->{content} // '', $m);
    }
    my $bytes = _b64_decode($val);
    return () unless length $bytes;
    return ($bytes, $mime // 'audio/mpeg');
}

my %AUDIO_KEY = map { $_ => 1 }
    qw(audio data b64 b64_json audio_data audio_url audio_base64 url output output_url);

sub _deep_audio ($node, $depth) {
    return undef if $depth > 8;
    if (ref $node eq 'ARRAY') {
        for my $v (@$node) { my $r = _deep_audio($v, $depth + 1); return $r if $r }
        return undef;
    }
    return undef unless ref $node eq 'HASH';
    for my $k (sort keys %$node) {
        next unless $AUDIO_KEY{ lc $k };
        my $v = $node->{$k};
        next unless defined $v && !ref $v && length $v;
        if ($v =~ m{^data:[\w/+.-]+;base64,}s || $v =~ m{^https?://}i
            || $v =~ m{^[A-Za-z0-9+/=\s]{16,}$}) {
            my $m = $node->{mime} // $node->{format} // $node->{content_type};
            $m = "audio/$m" if defined $m && $m !~ m{/};
            return [ $v, $m ];
        }
    }
    for my $k (sort keys %$node) {
        my $r = _deep_audio($node->{$k}, $depth + 1);
        return $r if $r;
    }
    return undef;
}

sub _b64_decode ($s) {
    $s = '' unless defined $s;
    $s =~ s/\s+//g;
    require MIME::Base64;
    my $out = eval { MIME::Base64::decode_base64($s) };
    return defined $out ? $out : '';
}

1;
