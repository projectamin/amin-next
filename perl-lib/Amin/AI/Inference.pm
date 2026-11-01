package Amin::AI::Inference;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI';

use Amin::AI qw(AI_NS);
use Amin::AI::ModelRegistry;
use JSON::PP;
use Time::HiRes qw(gettimeofday tv_interval);

use constant RC_AI_PROVIDER_ERROR => -6147;

# Tests replace $UA. Hop comes from Amin::AI::Model->current_binding
# (ai:provider + ai:model on the profile). No process env.
our $UA;

sub name    { '' }
sub element { 'request' }
sub position { 'middle' }

sub on_article_close ($self, $el) {
    my $model  = $self->_attr($el, 'model') // '';
    return unless length $model;
    my $denied = eval { require Amin::AI::Model; Amin::AI::Model->current_denied } || 0;
    if ($denied) {
        return;
    }
    if (!Amin::AI::ModelRegistry->is_allowed($model)) {
        $self->_emit_ai('result',
            kind      => 'error',
            rc        => Amin::AI::ModelRegistry::RC_AI_MODEL_DENIED,
            exit_kind => 'ai_model_denied',
            msg       => "model $model is not allowed",
            model     => $model,
        );
        return;
    }

    my $prompt_parts = $self->_child_vals('prompt');
    my $prompt = join("\n", @$prompt_parts);
    my $systems = $self->_child_vals('system');
    my $bind = _binding() // {};
    my $will_hop = (!$UA || ($UA && $UA->{force_stream}))
        && length($bind->{base} // '')
        && length($bind->{key} // '');
    $self->{_thinking_open} = 0;
    $self->{_response_open} = 0;
    $self->{_live_chars} = 0;
    $self->{_live_stream} = 0;
    if ($will_hop) {
        $self->{_live_stream} = 1;
        $self->_ensure_thinking;
        $self->_stream_chars("infer $model\n");
    }
    else {
        $self->_emit_stream('thinking', "infer $model");
    }
    my $got = $self->_infer($model, $prompt, $systems);
    if ($will_hop) {
        if ($got->{ok} && !($self->{_live_chars} // 0)
            && length($got->{text} // '')) {
            $self->_ensure_response;
            $self->_stream_resp_chars($got->{text});
        }
        $self->_close_open_streams;
    }

    if (!$got->{ok}) {
        $self->_emit_ai('result',
            kind      => 'error',
            rc        => RC_AI_PROVIDER_ERROR,
            exit_kind => $got->{exit_kind} // 'ai_provider_error',
            msg       => $got->{msg} // 'provider request failed',
            model     => $model,
        );
        return;
    }

    my $h = $self->Handler or return;
    my $AI = AI_NS();
    my %attrs = (
        model      => $model,
        tokens_in  => $got->{tokens_in}  // length($prompt),
        tokens_out => $got->{tokens_out} // length($got->{text} // ''),
        latency_ms => $got->{latency_ms} // 0,
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
    $self->_emit_stream('response', $got->{text} // '')
        unless $self->{_live_chars};
    $h->end_element({
        NamespaceURI => $AI, LocalName => 'result',
        Name => 'ai:result', Prefix => 'ai',
    });
    return;
}

sub _ensure_thinking ($self) {
    return if $self->{_thinking_open} || $self->{_response_open};
    $self->_stream_begin('thinking');
    $self->{_thinking_open} = 1;
    return;
}

sub _ensure_response ($self) {
    if ($self->{_thinking_open}) {
        $self->_stream_end();
        $self->{_thinking_open} = 0;
    }
    return if $self->{_response_open};
    $self->_stream_begin('response');
    $self->{_response_open} = 1;
    return;
}

sub _close_open_streams ($self) {
    if ($self->{_thinking_open} || $self->{_response_open}) {
        $self->_stream_end();
    }
    $self->{_thinking_open} = 0;
    $self->{_response_open} = 0;
    $self->{_live_stream} = 0;
    return;
}

sub _stream_resp_chars ($self, $text) {
    return unless defined $text && length $text;
    $self->{_live_chars} += length $text;
    $self->_stream_chars($text);
    return;
}

sub _stream_think_chars ($self, $text) {
    return unless defined $text && length $text;
    $self->_ensure_thinking;
    $self->_stream_chars($text);
    return;
}

sub _stream_begin ($self, $channel) {
    my $h = $self->Handler or return;
    my $AI = AI_NS();
    $h->start_element({
        NamespaceURI => $AI, LocalName => 'stream',
        Name => 'ai:stream', Prefix => 'ai',
        Attributes => {
            '{}channel' => {
                Name => 'ai:channel', LocalName => 'channel',
                Prefix => 'ai', NamespaceURI => $AI,
                Value => $channel // 'response',
            },
        },
    });
    return;
}

sub _stream_chars ($self, $text) {
    my $h = $self->Handler or return;
    return unless defined $text && length $text;
    $h->characters({ Data => $text });
    return;
}

sub _stream_end ($self) {
    my $h = $self->Handler or return;
    $h->end_element({
        NamespaceURI => AI_NS(), LocalName => 'stream',
        Name => 'ai:stream', Prefix => 'ai',
    });
    return;
}

sub _emit_stream ($self, $channel, $text) {
    $self->_stream_begin($channel);
    $self->_stream_chars($text);
    $self->_stream_end();
    return;
}

sub _binding {
    return eval { require Amin::AI::Model; Amin::AI::Model->current_binding } || undef;
}

sub _infer ($self, $model, $prompt, $systems = []) {
    my $bind = _binding() // {};
    my $base = $bind->{base} // '';
    my $key  = $bind->{key}  // '';
    $base =~ s/^\s+|\s+$//g;
    $key  =~ s/^\s+|\s+$//g;
    if (!length $base && !length $key) {
        my $text = $self->_stub_inference($model, $prompt);
        return {
            ok         => 1,
            text       => $text,
            tokens_in  => length($prompt),
            tokens_out => length($text),
            latency_ms => 0,
            stub       => 1,
        };
    }
    if (!length $base || !length $key) {
        return {
            ok        => 0,
            exit_kind => 'ai_provider_error',
            msg       => 'ai:provider needs both base and key',
        };
    }
    return $self->_http_complete($model, $prompt, $base, $key, $bind, $systems);
}

sub _api_kind ($bind) {
    my $api = lc($bind->{api} // '');
    return $api if length $api;
    my $p = lc($bind->{provider} // '');
    return 'anthropic' if $p eq 'anthropic';
    return 'stub' if $p eq 'stub';
    return 'openai';
}

sub _anthropic_url ($base) {
    $base =~ s{/+$}{};
    return $base if $base =~ m{/messages$};
    return "$base/messages" if $base =~ m{/v1$};
    return "$base/v1/messages";
}

sub _ua ($self, $bind = {}) {
    return $UA if $UA;
    require HTTP::Tiny;
    my $timeout = $bind->{timeout} || 120;
    $timeout = 120 unless $timeout =~ /^\d+$/ && $timeout > 0;
    return HTTP::Tiny->new(
        timeout    => 0+$timeout,
        verify_SSL => 1,
        agent      => 'waihanga-amin',
    );
}

sub _completions_url ($base) {
    $base =~ s{/+$}{};
    return "$base/chat/completions";
}

sub _http_complete ($self, $model, $prompt, $base, $key, $bind = {}, $systems = []) {
    my $upstream = $bind->{upstream} // $model;
    $upstream =~ s/^\s+|\s+$//g if defined $upstream;
    $upstream = $model unless defined $upstream && length $upstream;

    my @sys = grep { defined && length } @$systems;
    my $kind = _api_kind($bind);
    my ($url, $payload, $headers);
    my $want_stream = !$UA || ($UA && $UA->{force_stream});
    if ($kind eq 'anthropic') {
        $url = _anthropic_url($base);
        $payload = eval {
            my %body = (
                model      => $upstream,
                max_tokens => 4096,
                stream     => $want_stream ? JSON::PP::true : JSON::PP::false,
                messages   => [ { role => 'user', content => $prompt // '' } ],
            );
            $body{system} = join("\n\n", @sys) if @sys;
            JSON::PP->new->utf8->encode(\%body);
        };
        $headers = {
            'Content-Type'      => 'application/json',
            'x-api-key'         => $key,
            'anthropic-version' => '2023-06-01',
        };
    }
    else {
        $url = _completions_url($base);
        $payload = eval {
            my @msgs = map { { role => 'system', content => $_ } } @sys;
            push @msgs, { role => 'user', content => $prompt // '' };
            my %body = (
                model    => $upstream,
                stream   => $want_stream ? JSON::PP::true : JSON::PP::false,
                messages => \@msgs,
            );
            my $p = lc($bind->{provider} // '');
            my $b = $bind->{base} // '';
            if ($p =~ /zai/ || $b =~ /z\.ai/) {
                $body{thinking} = { type => 'enabled' };
            }
            JSON::PP->new->utf8->encode(\%body);
        };
        $headers = {
            'Content-Type'     => 'application/json',
            'Accept'           => $want_stream ? 'text/event-stream' : 'application/json',
            'Accept-Language'  => 'en-US,en',
            'Authorization'    => "Bearer $key",
        };
    }
    if (!$payload) {
        return { ok => 0, msg => 'failed to encode provider request' };
    }
    if ($url =~ /^https:/i
        && !eval { require IO::Socket::SSL; IO::Socket::SSL->VERSION(1.42); 1 }) {
        return {
            ok        => 0,
            exit_kind => 'ai_provider_error',
            msg       => 'HTTPS hop needs IO::Socket::SSL '
                       . '(in amin-3.0: mise run bootstrap)',
        };
    }

    my $sse = { buf => '', raw => '', text => '', think => '', kind => $kind };
    my %opts = (
        headers => $headers,
        content => $payload,
    );
    if ($want_stream) {
        $opts{data_callback} = sub ($chunk, $res_cb) {
            $sse->{raw} .= $chunk // '';
            $self->_sse_feed($sse, $chunk);
        };
    }

    my $t0 = [gettimeofday];
    my $res = eval {
        $self->_ua($bind)->post($url, \%opts);
    };
    my $latency = int(tv_interval($t0) * 1000);
    if (!$res || $@) {
        my $err = $@ // 'provider request failed';
        $err =~ s/\s+$//;
        $err =~ s/\Q$key\E/[redacted]/g if length $key;
        return { ok => 0, msg => substr($err, 0, 300), latency_ms => $latency };
    }

    # HTTP::Tiny does not accumulate 2xx bodies when data_callback is
    # set. Flush a trailing SSE line, then parse a raw JSON body if
    # the server ignored stream=true.
    if ($want_stream && length($sse->{buf} // '')) {
        $self->_sse_feed($sse, "\n");
    }
    my $body = $res->{content} // '';
    $body = $sse->{raw} if !length($body) && length($sse->{raw} // '');
    my $obj = eval { JSON::PP->new->utf8->decode($body || '{}') };
    $obj = {} unless ref $obj eq 'HASH';

    if (!$res->{success}) {
        my $msg = $obj->{error}{message}
            // $res->{reason}
            // 'provider request failed';
        # HTTP::Tiny uses 599 for TLS/connect exceptions; the
        # exception text is in content, not reason.
        if (($res->{status} // 0) == 599 && length($res->{content} // '')) {
            my $c = $res->{content};
            $c =~ s/\s+/ /g;
            $msg = $c;
        }
        $msg = "HTTP $res->{status}: $msg" if $res->{status};
        $msg =~ s/\Q$key\E/[redacted]/g if length $key;
        return { ok => 0, msg => substr($msg, 0, 300), latency_ms => $latency };
    }

    my $text = $sse->{text} // '';
    my $think = $sse->{think} // '';
    if (!length $text || !length $think) {
        if ($kind eq 'anthropic') {
            my $blocks = ref $obj->{content} eq 'ARRAY' ? $obj->{content} : [];
            for my $blk (@$blocks) {
                next unless ref $blk eq 'HASH';
                my $t = $blk->{type} // '';
                if ($t eq 'thinking' && !length $think) {
                    $think = $blk->{thinking} // '';
                }
                elsif (($t eq 'text' || !length $t) && !length $text) {
                    $text = $blk->{text} // '';
                }
            }
        }
        else {
            my $choice = ref $obj->{choices} eq 'ARRAY' ? $obj->{choices}[0] : undef;
            if (ref $choice eq 'HASH') {
                my $msg = ref $choice->{message} eq 'HASH' ? $choice->{message} : {};
                $text = $msg->{content} if !length $text && defined $msg->{content};
                $think = $msg->{reasoning_content}
                    if !length $think && defined $msg->{reasoning_content};
                $text = $choice->{text} unless defined $text && length $text;
            }
        }
        $text = '' unless defined $text;
        $think = '' unless defined $think;
        $self->_stream_think_chars($think) if $want_stream && length $think
            && !length($sse->{think} // '');
        $self->_ensure_response if $want_stream && length $text
            && !length($sse->{text} // '');
        $self->_stream_resp_chars($text) if $want_stream && length $text
            && !length($sse->{text} // '');
    }

    my $usage = ref $obj->{usage} eq 'HASH' ? $obj->{usage} : {};
    if (!length($text) && !length($think)) {
        return {
            ok         => 0,
            exit_kind  => 'ai_provider_error',
            msg        => 'provider returned an empty reply',
            latency_ms => $latency,
        };
    }
    return {
        ok         => 1,
        text       => $text,
        tokens_in  => $usage->{prompt_tokens} // $usage->{input_tokens}
                      // length($prompt),
        tokens_out => $usage->{completion_tokens} // $usage->{output_tokens}
                      // (length($text) || length($think)),
        latency_ms => $latency,
    };
}

sub _sse_feed ($self, $st, $chunk) {
    $st->{buf} .= $chunk // '';
    while ($st->{buf} =~ s/\A(.*?)(?:\r\n|\n)//) {
        my $line = $1;
        next unless $line =~ /^data:\s*(.*)/;
        my $data = $1;
        return if $data eq '[DONE]';
        my $obj = eval { JSON::PP->new->utf8->decode($data) } // {};
        next unless ref $obj eq 'HASH';
        my $delta = '';
        my $think = '';
        if (($st->{kind} // '') eq 'anthropic') {
            if (($obj->{type} // '') eq 'content_block_delta'
                && ref $obj->{delta} eq 'HASH') {
                my $d = $obj->{delta};
                if (($d->{type} // '') eq 'thinking_delta') {
                    $think = $d->{thinking} // '';
                }
                else {
                    $delta = $d->{text} // '';
                }
            }
        }
        else {
            my $ch = ref $obj->{choices} eq 'ARRAY' ? $obj->{choices}[0] : undef;
            if (ref $ch eq 'HASH') {
                if (ref $ch->{delta} eq 'HASH') {
                    $think = $ch->{delta}{reasoning_content}
                        // $ch->{delta}{reasoning}
                        // $ch->{delta}{thinking}
                        // '';
                    $delta = $ch->{delta}{content} // '';
                }
                $delta = $ch->{text}
                    if !length($delta // '') && defined $ch->{text};
            }
        }
        if (defined $think && length $think) {
            $st->{think} .= $think;
            $self->_stream_think_chars($think) if $self->{_live_stream};
        }
        next unless defined $delta && length $delta;
        $st->{text} .= $delta;
        if ($self->{_live_stream}) {
            $self->_ensure_response;
            $self->_stream_resp_chars($delta);
        }
    }
    return;
}

sub _stub_inference ($self, $model, $prompt) {
    return "[stub:$model] " . substr($prompt, 0, 200);
}

1;
