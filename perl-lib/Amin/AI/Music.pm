package Amin::AI::Music;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI';

use Amin::AI qw(AI_NS);
use Amin::AI::ModelRegistry;
use Amin::AI::Provider::Registry;

use Time::HiRes ();

use constant RC_AI_PROVIDER_ERROR => -6147;

# ═══════════════════════════════════════════════════════════════════════════
# Amin::AI::Music — an AI filter in the Amin::AI::* family (like Embed), so
# it composes into any profile; the gate splices it in only while an ai:music
# element flows, and no dispatcher change is needed to add it.
#
#   <ai:provider id="deepinfra" api="deepinfra" base="…" key="…"/>
#   <ai:model id="ace-step" provider="deepinfra" upstream="acestep-v15-xl-sft" kind="music"/>
#   <ai:music ai:model="ace-step" ai:out="/ws/.waihanga/music/take.bin">
#     <ai:style>lo-fi, warm tape hiss</ai:style>
#     <ai:prompt>rain on a tin roof</ai:prompt>
#     <ai:lyrics>…</ai:lyrics>
#   </ai:music>
#
# The filter never branches on provider shape: it calls submit() then poll()s
# until terminal(), emitting one ai:update per step so a UI can render
# progress from the same SAX stream.  The finished artifact is stored via the
# shared bitcache path and re-emitted as a bc:object kind="audio" ref.
# ai:out names a destination the caller wants the bytes written to; only a
# real run touches the filesystem, and the path is echoed on bc:object.
# ═══════════════════════════════════════════════════════════════════════════

# Never spin forever on a stuck task API.
use constant MAX_POLLS => 600;

sub name     { '' }
sub element  { 'music' }
sub position { 'middle' }

sub on_article_close ($self, $el) {
    my $model = $self->_attr($el, 'model') // '';
    return unless length $model;

    # Model/Gate already flagged an injection or denial upstream.
    my $denied = eval { require Amin::AI::Model; Amin::AI::Model->current_denied } || 0;
    return if $denied;

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

    my $bind = eval { require Amin::AI::Model; Amin::AI::Model->current_binding } // {};
    my $provider = eval {
        Amin::AI::Provider::Registry->for_binding({
            id       => $bind->{provider} // '',
            api      => $bind->{api}      // '',
            provider => $bind->{provider} // '',
            base     => $bind->{base}     // '',
            key      => $bind->{key}      // '',
            upstream => $bind->{upstream} // '',
            kind     => $bind->{kind}     // '',
            timeout  => $bind->{timeout}  // 120,
        });
    };
    if (!$provider) {
        $self->_error($model, 'no provider adapter for this binding');
        return;
    }
    if (!$provider->has_hop) {
        $self->_error($model, 'ai:provider needs both base and key');
        return;
    }

    my $req = $self->_request($el, $model, $bind);

    my $job = eval { $provider->submit($req) };
    if (ref($job) ne 'HASH') {
        $self->_error($model, 'provider submit failed');
        return;
    }
    $self->_emit_update($job, $model, 'submit');

    my $polls = 0;
    while (!$provider->terminal($job)) {
        if ($polls++ >= MAX_POLLS) {
            $self->_error($model, 'provider did not finish (poll budget exhausted)');
            return;
        }
        my $delay = eval { $provider->poll_delay } // 0;
        Time::HiRes::sleep($delay) if $delay && $delay > 0;
        my $next = eval { $provider->poll($job) };
        if (ref($next) ne 'HASH') {
            $self->_error($model, 'provider poll failed');
            return;
        }
        $job = $next;
        $self->_emit_update($job, $model, 'poll');
    }

    if (($job->{state} // '') ne 'done') {
        $self->_error($model, $job->{msg} // 'provider task failed');
        return;
    }
    if (!defined $job->{audio} || !length $job->{audio}) {
        $self->_error($model, 'provider returned no audio');
        return;
    }

    $self->_emit_artifact($model, $job, $self->_attr($el, 'out'));
    return;
}

# Gather the request from the ai: children plus the resolved binding.
sub _request ($self, $el, $model, $bind) {
    my %req = (model => $model, upstream => $bind->{upstream} // '');
    for my $f (qw(style prompt lyrics)) {
        my $v = $self->_child_vals($f);
        $req{$f} = join("\n", @$v) if @$v;
    }
    for my $a (qw(duration format instrumental)) {
        my $v = $self->_attr($el, $a);
        $req{$a} = $v if defined $v && length $v;
    }
    return \%req;
}

# One progress event per step; tier-0 like every AI event, so prod drops it.
sub _emit_update ($self, $job, $model, $phase) {
    $self->_emit_ai('update',
        kind     => 'progress',
        phase    => $phase,
        model    => $model,
        state    => $job->{state} // 'running',
        progress => $job->{progress} // 0,
        handle   => $job->{handle} // '',
    );
    return;
}

sub _emit_artifact ($self, $model, $job, $out) {
    my ($hash, $size) = $self->_bc_put(\$job->{audio});
    if (!defined $hash) {
        $self->_error($model, 'failed to store the artifact');
        return;
    }
    my $path = $self->_write_out($out, $job->{audio});
    my $h = $self->Handler or return;
    my $BC = 'http://projectamin.org/ns/bc/';
    my %a = (
        hash  => [ 'hash',  $hash ],
        size  => [ 'size',  $size ],
        kind  => [ 'kind',  'audio' ],
        model => [ 'model', $model ],
        mime  => [ 'mime',  $job->{mime} // 'audio/mpeg' ],
    );
    $a{path} = [ 'path', $path ] if defined $path && length $path;
    my %attrs;
    for my $k (keys %a) {
        my ($ln, $v) = @{ $a{$k} };
        $attrs{"{}" . $ln} = {
            Name => "bc:$ln", LocalName => $ln, Prefix => 'bc',
            NamespaceURI => $BC, Value => "$v",
        };
    }
    $h->start_element({
        NamespaceURI => $BC, LocalName => 'object',
        Name => 'bc:object', Prefix => 'bc', Attributes => \%attrs,
    });
    $h->end_element({
        NamespaceURI => $BC, LocalName => 'object',
        Name => 'bc:object', Prefix => 'bc',
    });
    return;
}

# ai:out names where the caller wants the bytes materialised.  Only a real
# run touches the filesystem (render/dryrun stay side-effect free); the path
# is echoed on the bc:object either way.  Returns the path, or undef on a
# failed write.
sub _write_out ($self, $out, $bytes) {
    return unless defined $out && length $out;
    return $out unless ($self->Mode // 'render') eq 'run';
    require File::Basename;
    require File::Path;
    my $dir = File::Basename::dirname($out);
    File::Path::make_path($dir) unless -d $dir;
    open(my $fh, '>:raw', $out) or do {
        $self->Log && $self->Log->error("[music/out] cannot write $out: $!");
        return;
    };
    print {$fh} $bytes;
    close $fh;
    $self->Log && $self->Log->info(
        "[music/out] $out <- " . length($bytes) . " bytes");
    return $out;
}

sub _error ($self, $model, $msg) {
    $self->_emit_ai('result',
        kind      => 'error',
        rc        => RC_AI_PROVIDER_ERROR,
        exit_kind => 'ai_provider_error',
        msg       => $msg,
        model     => $model,
    );
    return;
}

1;
