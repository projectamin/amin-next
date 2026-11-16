package Amin::AI::Provider::AsyncHttp;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::AI::Provider::Base';

# ═══════════════════════════════════════════════════════════════════════════
# Generic submit → poll engine.  Endpoint paths and the response vocabulary
# are overridable per subclass, so one poll engine serves many task APIs
# (DeepInfra inference, ACE-Step, …).  Subclasses set submit_path/poll_path
# and may override build_body.
#
#   submit : POST {base}/{submit_path}  → job id + optional poll_url
#   poll   : GET  poll_url              → state/progress, then artifact
# ═══════════════════════════════════════════════════════════════════════════

sub submit_path ($self) { 'v1/inference/%s' }        # sprintf(model)
sub poll_path   ($self) { 'v1/inference/%s/%s' }     # sprintf(model, id)

sub build_body ($self, $req) {
    my %b;
    $b{prompt}  = $req->{prompt}  if length($req->{prompt}  // '');
    $b{style}   = $req->{style}   if length($req->{style}   // '');
    $b{lyrics}  = $req->{lyrics}  if length($req->{lyrics}  // '');
    $b{duration} = 0 + $req->{duration} if ($req->{duration} // '') =~ /^\d+$/;
    $b{format}  = $req->{format}  if length($req->{format}  // '');
    $b{instrumental} = 1 if ($req->{instrumental} // '') =~ /^(1|true|yes)$/i;
    return \%b;
}

sub submit ($self, $req) {
    return { state => 'error', msg => 'provider needs base and key' } unless $self->has_hop;

    my $model = $self->{upstream} || $req->{model} || '';
    my $url   = $self->join_url($self->{base}, sprintf($self->submit_path, $model));
    my %body  = (%{ $self->build_body($req) }, model => $model);

    my $r = $self->post_json($url, \%body);
    return { state => 'error', msg => $r->{msg} // 'submit failed' } unless $r->{ok};

    # A provider may answer synchronously with the artifact already.
    my ($bytes, $mime) = $self->extract_audio($r->{obj});
    if (length($bytes // '')) {
        return { state => 'done', audio => $bytes, mime => $mime // 'audio/mpeg',
                 progress => 100, model => $model };
    }

    my $id = _first_key($r->{obj}, qw(request_id id task_id job_id prediction_id generation_id));
    if (!defined $id || !length $id) {
        return { state => 'error', msg => 'submit returned no job id' };
    }

    my $poll = $self->join_url($self->{base}, sprintf($self->poll_path, $model, $id));
    my $declared = _first_key($r->{obj}, qw(poll_url status_url));
    $poll = $declared if defined $declared && $declared =~ m{^https?://};

    return {
        state    => _norm_state(_first_key($r->{obj}, qw(status state)) // 'queued'),
        handle   => "$id",
        poll_url => $poll,
        progress => _first_key($r->{obj}, qw(progress percent)) // 0,
        model    => $model,
    };
}

sub poll ($self, $job) {
    my $url = $job->{poll_url};
    return { %$job, state => 'error', msg => 'job has no poll url' } unless defined $url && length $url;

    my $r = $self->get_json($url);
    return { %$job, state => 'error', msg => $r->{msg} // 'poll failed' } unless $r->{ok};

    my ($bytes, $mime) = $self->extract_audio($r->{obj});
    if (length($bytes // '')) {
        return { %$job, state => 'done', audio => $bytes,
                 mime => $mime // ($job->{mime} // 'audio/mpeg'), progress => 100 };
    }

    my $state = _norm_state(_first_key($r->{obj}, qw(status state)) // 'running');
    my $prog  = _first_key($r->{obj}, qw(progress percent)) // $job->{progress} // 0;
    return { %$job, state => $state, progress => $prog };
}

# ── response vocabulary ─────────────────────────────────────────────────
# Look for a key in the response object and its common envelopes.
sub _first_key ($obj, @keys) {
    return undef unless ref $obj eq 'HASH';
    my @layers = ($obj);
    for my $env (qw(output data result response)) {
        push @layers, $obj->{$env} if ref $obj->{$env} eq 'HASH';
    }
    for my $k (@keys) {
        for my $l (@layers) {
            next unless exists $l->{$k};
            my $v = $l->{$k};
            next if ref $v;
            return $v if defined $v && length "$v";
        }
    }
    return undef;
}

sub _norm_state ($s) {
    $s = lc($s // '');
    return 'done'    if $s =~ /^(done|succeed|succeeded|success|complete|completed|ready)$/;
    return 'error'   if $s =~ /^(error|failed|failure|cancel|failed|cancelled|rejected)$/;
    return 'running';
}

1;
