package Amin::Command::Spawn;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Elt';

use Amin qw(NS);

use Class::Tiny qw(PidRegistry), { spawn_id => undef };

# Global process registry: indexed by (pid or spawn_id) → { pid, harness,
# created_at }.  Signal looks up matching entries here.  Accessed from
# Amin::Command::Signal via Amin::Command::Spawn->registry().
{
    my %REG;
    my %BY_PID;
    sub registry { \%REG }
    sub by_pid   { \%BY_PID }
    sub _register ($pkg, $id, $pid, $harness, $extra = {}) {
        require Time::HiRes;
        my $ref = { id => $id, pid => $pid, harness => $harness,
                    created_at => [Time::HiRes::gettimeofday()],
                    err_ref    => ($extra->{err_ref} // undef),
                    sb_code    => undef,
                    sb_msg     => undef, };
        $REG{$id}     = $ref if defined $id && length $id;
        $BY_PID{$pid} = $ref if defined $pid;
        $ref;
    }
    sub _unregister_by_pid ($pkg, $pid) {
        if (my $ref = delete $BY_PID{$pid}) {
            if (defined $ref->{id}) {
                delete $REG{$ref->{id}};
            }
            return $ref;
        }
        return undef;
    }
    sub _lookup ($pkg, $id_or_pid) {
        return undef unless defined $id_or_pid;
        if (exists $REG{$id_or_pid})  { return $REG{$id_or_pid} }
        if (exists $BY_PID{$id_or_pid}) { return $BY_PID{$id_or_pid} }
        if ($id_or_pid =~ /^\d+$/)    { return $BY_PID{$id_or_pid} // undef }
        return undef;
    }
}

sub name    { '' }
sub element { 'spawn' }

# Spawn's capture rules differ from Command because spawn matching is by
# LocalName='spawn' (not by 'name' attr of a command wrapper).  Build argv
# from (<amin:argv> * N children) + (<amin:value> as trailing params).
sub start_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    if ($ns eq NS() && $ln eq 'spawn') {
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
        if ($ln eq 'spawn') {
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
    my @cmd = $self->build_argv or return;
    my $log  = $self->Log;
    my $mode = $self->Mode // 'render';

    my $attrs = $self->attrs // {};
    my $id    = _find_attr($attrs, 'id')    // _find_attr($attrs, 'spawn_id');
    my $name  = _find_attr($attrs, 'name')  // '';
    $self->spawn_id($id);

    if ($mode =~ /render|dryrun/) {
        $log && $log->info('[dry-spawn] ' . Amin::Elt::_q(@cmd)
                           . (length $id ? " id=$id" : ''));
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

    require IPC::Run;
    require Time::HiRes;
    my ($in, $out, $err) = ('', '', '');
    my $on_out = sub ($data, $sv) {
        length $data or return;
        $log && $log->info("[out:$name] " . Amin::Elt::_chomp($data));
        $self->_stream(out => $data);
        $$sv .= $data;
    };
    my $on_err = sub ($data, $sv) {
        length $data or return;
        $log && $log->error("[err:$name] " . Amin::Elt::_chomp($data));
        $self->_stream(err => $data);
        $$sv .= $data;
    };
    my $out_filter = Amin::Elt::_line_filter(\$out, $on_out);
    my $err_filter = Amin::Elt::_line_filter(\$err, $on_err);

    my $dir = $self->{dir};
    my $env = $self->{env} // {};
    my $sb_scope = Amin::Sandbox->current_scope_attrs;
    require Amin::Net::Fabric;
    my $net_scope_id = Amin::Net::Fabric->current_scope_id;
    my $net_scope    = Amin::Net::Fabric->current_scope_attrs;
    my $have_sb  = defined $sb_scope  && %$sb_scope;
    my $have_net = defined $net_scope && %$net_scope && lc($net_scope->{mode} // 'host') ne 'host';
    my @harness_cmd;
    my @harness_init;
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
        my %extra = ( env => $env, cwd => $dir );
        if ($have_net) {
            my $net_block = Amin::Net::Fabric->manifest_for_net($net_scope, $net_scope_id);
            $extra{net} = $net_block if defined $net_block;
        }
        my $manifest = Amin::Sandbox->build_manifest_for(
            ($have_sb ? $sb_scope : {}), \@cmd, \%extra);
        eval { $in = Amin::Sandbox->encode_sandbox_stdin($manifest); 1 } or do {
            my $e = $@;
            $self->_result_status_and_close(
                kind      => 'error',
                rc        => -4097,
                exit_kind => 'sandbox_missing_abi',
                detail    => "manifest encode failed: $e",
            );
            return;
        };
        @harness_cmd = ($bin, '--sandbox-stdin');
        @harness_init  = ();
    } else {
        @harness_cmd = @cmd;
        @harness_init  = (init => sub {
            chdir $dir if defined $dir;
            while (my ($k,$v) = each %$env) { $ENV{$k} = $v }
        }, debug => 0);
    }
    my @harness_args = (\@harness_cmd, \$in, $out_filter, $err_filter, @harness_init);
    my $hrns = IPC::Run::harness(@harness_args);

    my $pid;
    my $ok = eval {
        IPC::Run::start($hrns);
        if (ref $hrns && $hrns->{KIDS} && @{$hrns->{KIDS}}) {
            $pid = $hrns->{KIDS}[0]{PID} if $hrns->{KIDS}[0]{PID};
        }
        1;
    };
    if (!$ok) {
        my $e = $@;
        $self->_result_status_and_close(
            kind      => 'error',
            rc        => 1,
            exit_kind => 'exception',
            (defined $pid ? (pid => $pid) : ()),
            duration  => '0.000',
        );
        return;
    }

    # Also emit pid into the running result's stream metadata channel so
    # downstream readers can see pid without waiting for status.
    if (defined $pid) {
        $self->_stream(pid => "$pid");
    }

    __PACKAGE__->_register($id, $pid, $hrns, { err_ref => \$err });
    $self->_result_close;
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

1;
