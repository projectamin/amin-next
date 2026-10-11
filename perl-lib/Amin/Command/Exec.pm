package Amin::Command::Exec;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Elt';

use Amin qw(NS);

sub name    { '' }
sub element { 'exec' }

# Exec (and only Exec) cares about <amin:exec> elements, NOT <amin:command>
# (which are handled by Mkdir/Echo/Remove via their own name-attr matching
# through Amin::Elt base capture).  Exec therefore MUST bypass Amin::Elt's
# generic name-attr capture (since name='' leaks via _named empty-string
# fallback) and implements its own LocalName='exec' child capture, calling
# XML::SAX::Base directly for chain propagation (same bypass pattern as
# Spawn/Signal).

sub start_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    if ($ns eq NS() && $ln eq 'exec') {
        @{$self}{qw(_cap attrs params flags env dir _buf)} =
            (1, $el->{Attributes}, [], [], {}, undef, '');
        $self->{_current_child} = undef;
        require XML::SAX::Base;
        return XML::SAX::Base::start_element($self, $el);
    }
    if ($self->{_cap} && $ns eq NS()) {
        if ($ln eq 'shell') {
            my $d = _find_attr($el->{Attributes}, 'dir');
            $self->{dir} = $d if defined $d && length $d;
            $self->{_current_child} = 'shell';
        } elsif ($ln eq 'argv' || $ln eq 'value' || $ln eq 'env' || $ln eq 'flag' || $ln eq 'param') {
            $self->{_current_child} = $ln;
        }
    }
    require XML::SAX::Base;
    return XML::SAX::Base::start_element($self, $el);
}

sub characters ($self, $d) {
    if ($self->{_cap}) {
        $self->{_buf} .= $d->{Data} // '';
    }
    require XML::SAX::Base;
    return XML::SAX::Base::characters($self, $d);
}

sub end_element ($self, $el) {
    my ($ns, $ln) = (($el->{NamespaceURI} // ''), ($el->{LocalName} // ''));
    if ($self->{_cap} && $ns eq NS()) {
        my $text = _trim($self->{_buf});
        if (defined $self->{_current_child}
                && $self->{_current_child} eq $ln) {
            if    ($ln eq 'argv')  { push $self->{params}->@*, $text }
            elsif ($ln eq 'value') { push $self->{params}->@*, $text }
            elsif ($ln eq 'shell') {
                my @kv = split /\s+/, $text;
                push $self->{params}->@*, @kv if @kv;
            }
            elsif ($ln eq 'flag')  { push $self->{flags}->@*, $text }
            elsif ($ln eq 'param') { push $self->{params}->@*, $text }
            elsif ($ln eq 'env')   {
                my ($k, $v) = split /=/, $text, 2;
                if (defined $v) { $self->{env}{$k} = $v }
            }
            $self->{_buf} = '';
            $self->{_current_child} = undef;
            require XML::SAX::Base;
            return XML::SAX::Base::end_element($self, $el);
        }
        if ($ln eq 'exec') {
            $self->on_command_close;
            $self->{_cap} = 0;
            require XML::SAX::Base;
            return XML::SAX::Base::end_element($self, $el);
        }
    }
    require XML::SAX::Base;
    return XML::SAX::Base::end_element($self, $el);
}

sub build_argv ($self) {
    my @p = $self->params->@*;
    return () unless @p;
    return @p;
}

sub on_command_close ($self) {
    $self->execute;
    return;
}

sub execute ($self) {
    my @cmd = $self->build_argv or return;
    my $log = $self->Log;
    my $mode = $self->Mode // 'render';

    if ($mode =~ /render|dryrun/) {
        $log && $log->info('[dry-run] ' . Amin::Elt::_q(@cmd));
        $self->_result_start(dryrun => \@cmd);
        $self->_result_status_and_close(
            kind      => 'dryrun',
            rc        => 0,
            exit_kind => 'ok',
        );
        return;
    }

    require Amin::Sandbox;
    my ($sb_ok, $sb_detail) = Amin::Sandbox->check_command(\@cmd, $self->{dir});
    if (!$sb_ok) {
        $log && $log->error('[sandbox] closed-world violation: ' . ($sb_detail // 'unknown'));
        $self->_result_start(error => \@cmd);
        $self->_result_status_and_close(
            kind      => 'error',
            rc        => -4096,
            exit_kind => 'sandbox_violation',
            detail    => $sb_detail,
        );
        return;
    }

    $self->_result_start(running => \@cmd);
    my $sb_scope = Amin::Sandbox->current_scope_attrs;
    require Amin::Net::Fabric;
    my $net_scope_id = Amin::Net::Fabric->current_scope_id;
    my $net_scope    = Amin::Net::Fabric->current_scope_attrs;
    my $have_sb  = defined $sb_scope  && %$sb_scope;
    my $have_net = defined $net_scope && %$net_scope && lc($net_scope->{mode} // 'host') ne 'host';
    my $r;
    if ($have_sb || $have_net) {
        my $bin = Amin::Sandbox->aminexec_bin_path;
        unless (-x $bin) {
            $self->_result_status_and_close(
                kind      => 'error',
                rc        => -4097,
                exit_kind => 'sandbox_missing_abi',
                detail    => "aminexec binary not found or not executable: $bin",
            );
            return;
        }
        my %extra = ( env => $self->{env} // {}, cwd => $self->{dir} );
        if ($have_net) {
            my $net_block = Amin::Net::Fabric->manifest_for_net($net_scope, $net_scope_id);
            $extra{net} = $net_block if defined $net_block;
        }
        my $manifest = Amin::Sandbox->build_manifest_for(
            ($have_sb ? $sb_scope : {}), \@cmd, \%extra);
        my $in_buf;
        eval { $in_buf = Amin::Sandbox->encode_sandbox_stdin($manifest); 1 } or do {
            my $e = $@;
            $self->_result_status_and_close(
                kind      => 'error',
                rc        => -4097,
                exit_kind => 'sandbox_missing_abi',
                detail    => "manifest encode failed: $e",
            );
            return;
        };
        $r = _ipc_run_sync_cmd([$bin, '--sandbox-stdin'], $in_buf, $self);
    } else {
        $r = $self->_ipc_run_sync(\@cmd);
    }
    my $kind = ($r->{exception} || $r->{rc} != 0 || $r->{signal}) ? 'error' : 'success';
    my %meta = ( kind => $kind, rc => $r->{rc} );
    $meta{pid}       = $r->{pid}       if defined $r->{pid};
    $meta{duration}  = sprintf('%.3f', $r->{duration}) if defined $r->{duration};
    $meta{exit_kind} = $r->{exit_kind} if defined $r->{exit_kind};

    if ($log) {
        my $ok = $kind eq 'success';
        my $msg = sprintf '[%s rc=%s] %s', ($ok ? 'ok' : 'fail'), $r->{rc},
            Amin::Elt::_q(@cmd);
        $ok ? $log->success($msg) : $log->error($msg);
    }

    $self->_result_status_and_close(%meta);
    return;
}

sub _find_attr ($attrs, $name) {
    return undef unless ref($attrs) eq 'HASH';
    for my $k (keys %$attrs) {
        next unless $attrs->{$k} && ref($attrs->{$k}) eq 'HASH';
        if (($attrs->{$k}{LocalName} // '') eq $name) {
            my $v = $attrs->{$k}{Value};
            return $v if defined $v && length $v;
        }
    }
    return undef;
}

sub _trim ($s) { ($s // '') =~ s/^\s+|\s+$//gr }

sub _ipc_run_sync_cmd ($cmd, $in_content, $self) {
    require IPC::Run;
    require Time::HiRes;
    my @argv = @$cmd;
    my $log  = $self->Log;
    my ($in, $out, $err) = (defined $in_content ? "$in_content" : '', '', '');
    my $on_out = sub ($data, $sv) {
        length $data or return;
        $log && $log->info('[out] ' . Amin::Elt::_chomp($data));
        $self->_stream(out => $data);
        $$sv .= $data;
    };
    my $out_filter = Amin::Elt::_line_filter(\$out, $on_out);
    my @harness_args = (\@argv, \$in, $out_filter, \$err, debug => 0);
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

    # ── aminexec stderr error prefix decode ──
    # Protocol: first N bytes = 4-byte LE i32 code THEN NUL-terminated C
    # string message.  code < 0 means sandbox setup error (pre-exec failure).
    # code >= 0 means reserved for generic IPC errors inside the child.
    # After we decode the prefix (if any), strip it and forward the
    # remainder to normal err logging / streaming.
    my ($sb_code, $sb_msg);
    if (defined $err && length($err) >= 5) {
        my $first4 = substr($err, 0, 4, '');
        my $maybe_code = unpack('l<', $first4);
        my $nul = index($err, "\0");
        if (defined($nul) && $nul >= 0) {
            $sb_code = $maybe_code;
            $sb_msg  = substr($err, 0, $nul, '');
            substr($err, 0, 1, '');
            $err =~ s/^\s*\n?//s;
            if (defined $log && defined $sb_msg && length $sb_msg) {
                $log->error('[err] ' . Amin::Elt::_chomp($sb_msg));
            }
            if (length $err) {
                $self->_stream(err => $err);
            }
        } else {
            substr($err, 0, 0, $first4);
            if (length $err) {
                $log && $log->error('[err] ' . Amin::Elt::_chomp($err));
                $self->_stream(err => $err);
            }
        }
    } elsif (length $err) {
        $log && $log->error('[err] ' . Amin::Elt::_chomp($err));
        $self->_stream(err => $err);
    }

    if (defined $e && length $e) {
        return { exception => $e, duration => $duration, pid => $pid,
                 exit_kind => 'exception', rc => 1, out_accum => $out, err_accum => $err,
                 (defined $sb_code ? (sb_code => $sb_code, sb_msg => $sb_msg) : ()) };
    }
    $rc = $? >> 8;
    $signal_num = $? & 127;
    my $exit_kind;
    if (defined $sb_code && $sb_code < 0) {
        $rc = $sb_code;
        $exit_kind = ($sb_code == -4096) ? 'sandbox_violation'
                   : ($sb_code == -4097) ? 'sandbox_missing_abi'
                   : ($sb_code == -4099) ? 'net_missing_abi'
                   :                        'nonzero';
        $signal_num = 0;
    } elsif ($signal_num) {
        $exit_kind = 'signal';
        $rc = -$signal_num if $rc == 0;
    } elsif ($rc != 0) {
        $exit_kind = 'nonzero';
    } else {
        $exit_kind = 'ok';
    }
    return { rc => $rc, signal => $signal_num, exception => undef,
             pid => $pid, duration => $duration, exit_kind => $exit_kind,
             out_accum => $out, err_accum => $err,
             (defined $sb_code ? (sb_code => $sb_code, sb_msg => $sb_msg) : ()) };
}

1;
