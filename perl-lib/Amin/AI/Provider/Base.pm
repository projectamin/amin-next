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
