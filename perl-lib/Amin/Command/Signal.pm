package Amin::Command::Signal;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Elt';

use Amin qw(NS);

use Class::Tiny qw(spawn_target signal_num);

sub element { 'signal' }
sub name    { '' }

sub start_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    if ($ns eq NS() && $ln eq 'signal') {
        @{$self}{qw(_cap attrs _buf)} = (1, $el->{Attributes}, '');
        require XML::SAX::Base;
        return XML::SAX::Base::start_element($self, $el);
    }
    require XML::SAX::Base;
    return XML::SAX::Base::start_element($self, $el);
}

sub characters ($self, $d) {
    if ($self->{_cap}) { $self->{_buf} .= $d->{Data} // '' }
    require XML::SAX::Base;
    return XML::SAX::Base::characters($self, $d);
}

sub end_element ($self, $el) {
    my ($ns, $ln) = (($el->{NamespaceURI} // ''), ($el->{LocalName} // ''));
    if ($self->{_cap} && $ns eq NS() && $ln eq 'signal') {
        $self->on_command_close;
        $self->{_cap} = 0;
    }
    require XML::SAX::Base;
    return XML::SAX::Base::end_element($self, $el);
}

# Signal is the authoritative closer for long-running Spawn results:
#   * Lookup Spawn entry in Amin::Command::Spawn registry by (id or pid) from
#     {target}/{pid}/{spawn_id} attrs of <amin:signal>.
#   * kill(SIGnum, $pid) sends the signal.
#   * IPC::Run::finish on the still-live harness → waitpid reaps; this is our
#     "POLLRDHUP on pidfd" proxy.  Emits <amin:result><status kind=error
#     rc=-N exit_kind=signal duration=... pid=P></amin:status></result>.
#   * If target not found: emits same result/status pair with
#     exit_kind=no_such_process rc=-1.  Pair count parity is preserved either way.
sub on_command_close ($self) {
    my $attrs = $self->attrs // {};
    my $mode  = $self->Mode // 'render';
    my $log   = $self->Log;

    my $target = _find_attr($attrs, 'target')  // _find_attr($attrs, 'id')
                 // _find_attr($attrs, 'spawn_id') // _find_attr($attrs, 'pid');
    my $sig    = _find_attr($attrs, 'signal')  // 'TERM';

    my $resolved_num = _resolve_signal($sig);
    $self->signal_num($resolved_num);
    $self->spawn_target($target);

    if ($mode =~ /render|dryrun/) {
        $log && $log->info('[dry-signal] ' . (defined $target ? $target : '(no target)')
                           . " SIG$sig");
        $self->_result_start('dryrun');
        $self->_result_status_and_close(
            kind      => 'dryrun',
            rc        => 0,
            exit_kind => 'ok',
        );
        return;
    }

    my $entry = Amin::Command::Spawn->_lookup($target);
    if (!$entry) {
        $log && $log->error('[signal] no such spawn: ' . (defined $target ? $target : '(undef)'));
        $self->_result_start('error');
        my %meta = ( kind => 'error', rc => -1, exit_kind => 'no_such_process' );
        $meta{detail} = "target=$target" if defined $target;
        $self->_result_status_and_close(%meta);
        return;
    }

    require IPC::Run;
    require Time::HiRes;

    my $pid  = $entry->{pid};
    my $hrns = $entry->{harness};
    my $created = $entry->{created_at} // [Time::HiRes::gettimeofday()];

    my $delivered = 0;
    if (defined $pid && $pid > 0) {
        $delivered = kill $resolved_num, $pid;
    }

    eval { IPC::Run::finish($hrns) if $hrns };
    my $e = $@;

    my $duration = Time::HiRes::tv_interval($created);

    my ($sb_code, $sb_msg);
    if (exists $entry->{err_ref} && ref($entry->{err_ref}) eq 'SCALAR'
        && defined ${$entry->{err_ref}} && length(${$entry->{err_ref}}) >= 5)
    {
        my $err_copy = ${$entry->{err_ref}};
        my $first4 = substr($err_copy, 0, 4, '');
        my $maybe_code = unpack('l<', $first4);
        my $nul = index($err_copy, "\0");
        if (defined($nul) && $nul >= 0) {
            $sb_code = $maybe_code;
            $sb_msg  = substr($err_copy, 0, $nul);
        }
    }

    my $child_status = $?;
    my ($rc, $signal_detected, $coredump) = (0, 0, 0);
    if (defined $child_status) {
        if ($child_status == -1) {
            $rc = -1;
        } elsif (($child_status & 127) != 127) {
            $signal_detected = $child_status & 127;
            $rc = $child_status >> 8;
            $coredump = ($child_status & 128) ? 1 : 0;
        } else {
            $rc = $child_status >> 8;
        }
    }

    Amin::Command::Spawn->_unregister_by_pid($pid);

    my ($kind, $exit_kind);
    if (defined $sb_code && $sb_code < 0) {
        $rc = $sb_code;
        $signal_detected = 0;
        $coredump = 0;
        $exit_kind = ($sb_code == -4096) ? 'sandbox_violation'
                   : ($sb_code == -4097) ? 'sandbox_missing_abi'
                   : ($sb_code == -4099) ? 'net_missing_abi'
                   :                        'nonzero';
        $kind = 'error';
    } elsif ($signal_detected) {
        $kind      = 'error';
        $exit_kind = 'signal';
        $rc        = -$signal_detected;
    } elsif ($e && length $e) {
        $kind      = 'error';
        $exit_kind = 'exception';
        $rc        = 1;
    } elsif ($rc == 0) {
        $kind      = 'success';
        $exit_kind = 'ok';
    } else {
        $kind      = 'error';
        $exit_kind = 'nonzero';
    }

    my %meta = ( kind => $kind, rc => $rc,
                 pid => $pid, duration => sprintf('%.3f', $duration),
                 exit_kind => $exit_kind );
    $meta{signal}    = $signal_detected if $signal_detected;
    $meta{coredump}  = $coredump         if $coredump;
    $meta{delivered} = $delivered        if defined $delivered;
    $meta{sb_msg}    = $sb_msg           if defined $sb_msg && length $sb_msg;

    $self->_result_start($kind);
    $self->_result_status_and_close(%meta);
    return;
}

sub _resolve_signal ($name_or_num) {
    unless (defined $name_or_num && length $name_or_num) {
        return 15;
    }
    if ($name_or_num =~ /^\d+$/) {
        my $n = $name_or_num + 0;
        return $n > 0 ? $n : 15;
    }
    my $n = $name_or_num;
    $n =~ s/^SIG//;
    $n = uc $n;
    my %map = (
        HUP => 1,  INT => 2,  QUIT => 3,  ILL => 4,  TRAP => 5,
        ABRT=> 6,  BUS => 7,  FPE  => 8,  KILL=> 9,  USR1 => 10,
        SEGV=> 11, USR2=> 12, PIPE => 13, ALRM=> 14, TERM => 15,
        STKFLT=>16, CHLD=> 17, CONT => 18, STOP=> 19, TSTP => 20,
        TTIN => 21, TTOU=>22, URG  => 24, XCPU=> 25, XFSZ => 26,
        VTALRM=>27, PROF=>28, WINCH=> 28, IO  => 29, PWR  => 30, SYS=>31,
    );
    return $map{$n} // 15;
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

1;
