package Amin::Elt;
use v5.38; use warnings; use utf8;
use experimental qw(signatures for_list);
use parent 'XML::SAX::Base';

use Amin     qw(NS);

use Class::Tiny qw(name element Handler Log Mode),
{ _cap => 0, _matched_name => undef, attrs => sub { {} }, params => sub { [] },
  flags => sub { [] }, env => sub { {} }, dir => undef, _buf => '' };

# See end_element for why recursion warnings are scoped off here.
sub start_element ($self, $el) {
    no warnings 'recursion';
    my $want_el = $self->element // '';
    my $ln      = $el->{LocalName} // '';
    my $ns_ok   = _mine($el);

    if ($ns_ok && (!length($want_el) || $want_el eq $ln)) {
        if (_named($el, $self->name)) {
            @{$self}{qw(_cap _matched_name attrs params flags env dir _buf)} =
                (1, $el->{Attributes}{'{}name'}{Value} // $self->name // undef,
                 $el->{Attributes}, [], [], {}, undef, '');
        }
    }
    if ($self->{_cap} && $ns_ok) {
        my $name = $el->{Attributes}{'{}name'}{Value} // '';
        $self->{_last_child_name}{$ln} = $name;
        if ($ln eq 'shell') {
            my %sa;
            for my $kv (values $el->{Attributes}->%*) {
                next unless length($kv->{LocalName} // '');
                $sa{$kv->{LocalName}} = $kv->{Value};
            }
            $self->{_last_shell_attrs} = \%sa;
        }
    }
    return $self->SUPER::start_element($el);
}

# See end_element for why recursion warnings are scoped off here.
sub characters ($self, $d) { no warnings 'recursion';
    $self->{_buf} .= $d->{Data} // '' if $self->{_cap};
    return $self->SUPER::characters($d); }

# The machine-spec'd filter chain can be ~290 handlers deep when full (the
# profile-scoped selection in Dispatcher keeps everyday chains much shallower),
# so every event recurses back through XML::SAX::Base once per hop.  Past 100 frames of
# the same named sub, Perl fires its deep-recursion heuristic on these SUPER::
# hops.  That heuristic is meant for data-driven runaway recursion; this is
# linear pass-through over a chain whose length is declared in machine_spec.xml,
# so silence it in exactly the two lexical scopes that make the hops — and
# nowhere else in this file.
sub end_element ($self, $el) {
    no warnings 'recursion';
    my ($ns, $ln) = ($el->{NamespaceURI}//'', $el->{LocalName});

    if ($self->{_cap} && $ns eq NS()) {
        my $text = _trim($self->{_buf});
        my $cap_name = $self->{_last_child_name}{$ln} // '';

        for my $case (['param',  $self->{params}],
                      ['flag',   $self->{flags}]) {
            my ($tag, $list) = @$case;
            if ($ln eq $tag) { push @$list, $cap_name ? { $cap_name => $text } : $text;
                $self->{_buf}='';
                return $self->SUPER::end_element($el); }
        }

        if ($ln eq 'shell') {
            my $attrs = $self->{_last_shell_attrs} // {};
            while (my ($k, $v) = each %$attrs) {
                if    ($k eq 'dir')        { $self->{dir} = $v }
                elsif ($k =~ /^env_(.+)/)  { $self->{env}{$1} = $v }
                elsif ($k eq 'env')        {
                    my ($ek, $ev) = split /=/, $v, 2;
                    $self->{env}{$ek} = $ev if defined $ev;
                }
            }
            $self->{_buf} = '';
            return $self->SUPER::end_element($el);
        }

        my $want_el = $self->element // '';
        if (_mine($el) && (!length($want_el) || $want_el eq $ln)
            && defined($self->{_matched_name})
            && defined($self->name) && $self->{_matched_name} eq $self->name) {
            $self->on_command_close;
            $self->{_cap} = 0; $self->{_matched_name} = undef;
            %{$self->{_last_child_name} //= {}} = ();
            return $self->SUPER::end_element($el);
        }
    }
    return $self->SUPER::end_element($el);
}

# Hook overridden by Exec (short-lived run) vs Spawn (pidfd-persistent long-running).
# Amin::Elt base implementation is a no-op; command subclasses (Pass) override to
# call $self->execute.
sub on_command_close ($self) { return; }

# Short-lived synchronous execute: dryrun emits result/status without spawning;
# run mode spawns via _ipc_run_sync with streaming stdout/stderr.
sub execute ($self) {
    my @cmd = $self->build_argv or return;
    my $log  = $self->Log;
    my $mode = $self->Mode // 'render';

    if ($mode =~ /render|dryrun/) {
        $log && $log->info('[dry-run] ' . _q(@cmd));
        $self->_result_start(dryrun => \@cmd);
        $self->_result_status_and_close(
            kind      => 'dryrun',
            rc        => 0,
            exit_kind => 'ok',
        );
        return;
    }

    $self->_result_start(running => \@cmd);
    my $r = $self->_ipc_run_sync(\@cmd);
    my $kind = ($r->{exception} || $r->{rc} != 0 || $r->{signal}) ? 'error' : 'success';
    my %meta = ( kind => $kind, rc => $r->{rc} );
    $meta{pid}       = $r->{pid}       if defined $r->{pid};
    $meta{duration}  = sprintf('%.3f', $r->{duration}) if defined $r->{duration};
    $meta{exit_kind} = $r->{exit_kind} if defined $r->{exit_kind};

    if ($log) {
        my $ok = $kind eq 'success';
        my $msg = sprintf '[%s rc=%s] %s', ($ok ? 'ok' : 'fail'), $r->{rc}, _q(@cmd);
        $ok ? $log->success($msg) : $log->error($msg);
    }

    $self->{_pid}       = $r->{pid};
    $self->{_duration}  = $r->{duration};
    $self->{_exit_kind} = $r->{exit_kind};

    $self->_result_status_and_close(%meta);
    return;
}

sub build_argv ($self) { () }

sub _mine ($e) { ($e->{NamespaceURI}//'') eq NS() }
sub _named ($e,$n) {
    defined $n && length($n) && ($e->{Attributes}{'{}name'}{Value}//'') eq $n;
}
sub _trim ($s)  { $s =~ s/^\s+|\s+$//gr }
sub _chomp ($s) { local $_ = $s; s/\s+\z//r }

sub _q (@s) {
    require String::ShellQuote;
    join ' ', map String::ShellQuote::shell_quote($_), @s;
}

sub _attrs ($hash) { +{ map {;
    "{}" . $_ => { Name => $_, LocalName => $_, Prefix => 'amin',
                   NamespaceURI => NS(), Value => defined $hash->{$_} ? "$hash->{$_}" : '' }
} keys %$hash } }

sub _stream ($self, $channel, $data) {
    my $h = $self->Handler or return;
    $h->start_element({
        NamespaceURI => NS(), LocalName => 'stream', Name => 'amin:stream',
        Prefix => 'amin', Attributes => _attrs({ channel => $channel }) });
    $h->characters({ Data => $data }) if length $data;
    $h->end_element({
        NamespaceURI => NS(), LocalName => 'stream', Name => 'amin:stream',
        Prefix => 'amin' });
}

sub _result_start ($self, $kind, $argv = []) {
    my $h = $self->Handler or return;
    $h->start_element({
        NamespaceURI => NS(), LocalName => 'result', Name => 'amin:result',
        Prefix => 'amin',
        Attributes => _attrs({ kind => $kind, rc => '' }) });
    if (@$argv) {
        $self->_stream(argv => _q(@$argv));
    }
    return;
}

sub _result_status_and_close ($self, %meta) {
    my $h = $self->Handler or return;
    $h->start_element({
        NamespaceURI => NS(), LocalName => 'status', Name => 'amin:status',
        Prefix => 'amin',
        Attributes => _attrs(\%meta) });
    $h->end_element({
        NamespaceURI => NS(), LocalName => 'status', Name => 'amin:status',
        Prefix => 'amin' });
    $h->end_element({
        NamespaceURI => NS(), LocalName => 'result', Name => 'amin:result',
        Prefix => 'amin' });
    return;
}

sub _result_close ($self) {
    my $h = $self->Handler or return;
    $h->end_element({
        NamespaceURI => NS(), LocalName => 'result', Name => 'amin:result',
        Prefix => 'amin' });
    return;
}

sub _line_filter ($sv, $cb) {
    my $buf = '';
    sub ($data, @) {
        if (!defined $data) {
            if (length $buf) { $cb->($buf, $sv); $buf = '' }
            return ();
        }
        $buf .= $data;
        while ((my $i = index $buf, "\n") >= 0) {
            my $line = substr $buf, 0, $i+1, '';
            $cb->($line, $sv);
        }
        return ();
    };
}

# Run @cmd to completion via IPC::Run; streams stdout/stderr line-by-line via
# _stream.  Returns hashref: { rc, signal, exception, pid, duration, exit_kind,
# out_accum, err_accum }.  Does NOT emit <result> / <status>; caller decides.
sub _ipc_run_sync ($self, $cmd, %opts) {
    require IPC::Run;
    require Time::HiRes;
    my @argv = @$cmd;
    my $h = $self->Handler;
    my $log = $self->Log;

    my ($in, $out, $err) = ('', '', '');
    my $on_out = sub ($data, $sv) {
        length $data or return;
        $log && $log->info('[out] ' . _chomp($data));
        if (!$opts{no_stream}) {
            $self->_stream(out => $data);
        }
        $$sv .= $data;
    };
    my $on_err = sub ($data, $sv) {
        length $data or return;
        $log && $log->error('[err] ' . _chomp($data));
        if (!$opts{no_stream}) {
            $self->_stream(err => $data);
        }
        $$sv .= $data;
    };
    my $out_filter = _line_filter(\$out, $on_out);
    my $err_filter = _line_filter(\$err, $on_err);

    my $dir = $self->{dir};
    my $env = $self->{env} // {};
    my @harness_args = (\@argv, \$in, $out_filter, $err_filter,
        init => sub {
            chdir $dir if defined $dir;
            while (my ($k,$v) = each %$env) { $ENV{$k} = $v }
        }, debug => 0);
    my $hrns = IPC::Run::harness(@harness_args);

    my $t0 = [Time::HiRes::gettimeofday()];
    my $pid;
    my ($e, $rc, $signal_num) = (undef, 0, 0);
    eval {
        IPC::Run::start($hrns);
        if (ref $hrns && $hrns->{KIDS} && @{$hrns->{KIDS}}) {
            $pid = $hrns->{KIDS}[0]{PID} if $hrns->{KIDS}[0]{PID};
        }
        IPC::Run::finish($hrns);
    };
    $e = $@;
    my $duration = Time::HiRes::tv_interval($t0);

    if (defined $e && length $e) {
        return { exception => $e, duration => $duration, pid => $pid,
                 exit_kind => 'exception', rc => 1, out_accum => $out, err_accum => $err };
    }
    $rc = $? >> 8;
    $signal_num = $? & 127;
    my $exit_kind;
    if    ($signal_num) { $exit_kind = 'signal';   $rc = -$signal_num if $rc == 0 }
    elsif ($rc != 0)    { $exit_kind = 'nonzero'  }
    else                 { $exit_kind = 'ok'       }
    return { rc => $rc, signal => $signal_num, exception => undef,
             pid => $pid, duration => $duration, exit_kind => $exit_kind,
             out_accum => $out, err_accum => $err };
}

1;

