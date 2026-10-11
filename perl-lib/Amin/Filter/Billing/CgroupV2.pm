package Amin::Filter::Billing::CgroupV2;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';

use Amin qw(NS);
use Class::Tiny qw(Handler Log Mode), {
    _records           => sub { +{} },
    _in_running_result => 0,
    _capturing_pid     => 0,
    _pid_buf           => '',
    _status_pid        => undef,
    _status_duration   => undef,
};

my $AMIN_NS = NS();

sub _ck ($ns, $name) { "{$ns}$name" }

sub _attr_val ($attrs, $name) {
    return undef unless $attrs && ref($attrs) eq 'HASH';
    for my $k ("{}" . $name, "{$AMIN_NS}$name") {
        return $attrs->{$k}{Value} if exists $attrs->{$k}
            && defined $attrs->{$k}{Value};
    }
    return undef;
}

sub _emit_billing_element ($self, $pid, $cpu_ms, $rss_kb, $egress, $disk, $tenant) {
    my $h = $self->Handler or return;
    my %vals = (
        pid          => $pid,
        cpu_ms       => $cpu_ms,
        rss_kb       => $rss_kb,
        egress_bytes => $egress,
        disk_rw_bytes => $disk,
        tenant_id    => $tenant // '',
    );
    my %attrs;
    for my $k (keys %vals) {
        my $v = defined $vals{$k} ? "$vals{$k}" : '';
        $attrs{"{}" . $k} = {
            Name         => $k,
            LocalName    => $k,
            Prefix       => 'amin',
            NamespaceURI => $AMIN_NS,
            Value        => $v,
        };
    }
    $h->start_element({
        NamespaceURI => $AMIN_NS, LocalName => 'billing', Name => 'amin:billing',
        Prefix => 'amin', Attributes => \%attrs,
    });
    $h->end_element({
        NamespaceURI => $AMIN_NS, LocalName => 'billing', Name => 'amin:billing',
        Prefix => 'amin',
    });
    return;
}

sub _cgroup_path_for_pid ($self, $pid) {
    return undef unless $pid && $pid =~ /^\d+$/;
    my $path = "/proc/$pid/cgroup";
    return undef unless -r $path;
    open my $fh, '<', $path or return undef;
    my $line = <$fh> // '';
    close $fh;
    if ($line =~ /^0::(\/\S+)/) {
        return "/sys/fs/cgroup$1";
    }
    return undef;
}

sub _read_file ($path) {
    return undef unless -r $path;
    open my $fh, '<', $path or return undef;
    local $/;
    my $content = <$fh>;
    close $fh;
    return $content;
}

sub _cpu_usage_usec ($self, $pid, $cg_path = undef) {
    my $cg = $cg_path // $self->_cgroup_path_for_pid($pid);
    if ($cg) {
        my $stat = _read_file("$cg/cpu.stat");
        if (defined $stat && $stat =~ /^usage_usec\s+(\d+)/m) {
            return $1 + 0;
        }
    }
    my $stat = _read_file("/proc/$pid/stat");
    if (defined $stat) {
        $stat =~ s/^\d+ \([^)]*\) //;
        my @f = split /\s+/, $stat;
        my $ticks = ($f[11] // 0) + ($f[12] // 0);
        require POSIX;
        my $clk = POSIX::sysconf(POSIX::_SC_CLK_TCK()) // 100;
        return int($ticks * 1_000_000 / $clk);
    }
    return 0;
}

sub _rss_kb ($self, $pid, $cg_path = undef) {
    my $cg = $cg_path // $self->_cgroup_path_for_pid($pid);
    if ($cg) {
        for my $f ("memory.peak", "memory.current") {
            my $v = _read_file("$cg/$f");
            if (defined $v && $v =~ /^(\d+)/) {
                return int($1 / 1024);
            }
        }
    }
    my $status = _read_file("/proc/$pid/status");
    if (defined $status && $status =~ /^VmHWM:\s+(\d+)\s+kB/m) {
        return $1 + 0;
    }
    return 0;
}

sub _tenant_id ($self) {
    eval { require Amin::Auth::ZCap; 1 } or return '';
    my $attrs = Amin::Auth::ZCap->current_scope_attrs;
    return $attrs->{tenant_id} // '';
}

sub start_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';

    if ($ns eq $AMIN_NS && $ln eq 'result') {
        my $kind = _attr_val($el->{Attributes}, 'kind') // '';
        if ($kind eq 'running') {
            $self->{_in_running_result} = 1;
        }
    }
    if ($ns eq $AMIN_NS && $ln eq 'stream') {
        my $ch = _attr_val($el->{Attributes}, 'channel') // '';
        if ($self->{_in_running_result} && $ch eq 'pid') {
            $self->{_capturing_pid} = 1;
            $self->{_pid_buf} = '';
        }
    }
    if ($ns eq $AMIN_NS && $ln eq 'status') {
        $self->{_status_pid} = _attr_val($el->{Attributes}, 'pid');
        $self->{_status_duration} = _attr_val($el->{Attributes}, 'duration');
    }

    return $self->SUPER::start_element($el);
}

sub characters ($self, $d) {
    if ($self->{_capturing_pid}) {
        $self->{_pid_buf} .= $d->{Data} // '';
    }
    return $self->SUPER::characters($d);
}

sub end_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';

    if ($ns eq $AMIN_NS && $ln eq 'stream' && $self->{_capturing_pid}) {
        $self->{_capturing_pid} = 0;
        my $pid = $self->{_pid_buf};
        $pid =~ s/^\s+|\s+$//g;
        if ($pid =~ /^\d+$/) {
            my $cg_path = $self->_cgroup_path_for_pid($pid);
            my $start_usec = $self->_cpu_usage_usec($pid, $cg_path);
            $self->{_records}{$pid} = {
                pid        => $pid,
                start_usec => $start_usec,
                cg_path    => $cg_path,
                tenant_id  => $self->_tenant_id,
            };
        }
    }

    if ($ns eq $AMIN_NS && $ln eq 'result' && $self->{_in_running_result}) {
        $self->{_in_running_result} = 0;
    }

    if ($ns eq $AMIN_NS && $ln eq 'status') {
        my $pid = delete $self->{_status_pid};
        my $duration = delete $self->{_status_duration};
        $self->SUPER::end_element($el);
        if ($pid && defined $self->{_records}{$pid}) {
            my $rec   = delete $self->{_records}{$pid};
            my $cg    = $rec->{cg_path};
            my $is_amin_cg = defined $cg && $cg =~ m{/sys/fs/cgroup/amin/};
            my ($cpu_ms, $rss_kb);

            if ($is_amin_cg) {
                my $final = $self->_cpu_usage_usec($pid, $cg);
                my $delta = $final - $rec->{start_usec};
                $delta = 0 if $delta < 0;
                $cpu_ms = int($delta / 1000);
                $rss_kb = $self->_rss_kb($pid, $cg);
            }

            if (!defined $cpu_ms || $cpu_ms == 0) {
                my $final = $self->_cpu_usage_usec($pid);
                if ($final > 0 && $rec->{start_usec} > 0) {
                    my $delta = $final - $rec->{start_usec};
                    $delta = 0 if $delta < 0;
                    $cpu_ms = int($delta / 1000) if $delta > 0;
                }
            }

            if ((!defined $cpu_ms || $cpu_ms == 0)
                    && defined $duration && $duration =~ /^\d+(\.\d+)?$/) {
                $cpu_ms = int($duration * 1000);
            }
            $cpu_ms //= 0;
            $rss_kb //= 0;
            $self->_emit_billing_element(
                $pid, $cpu_ms, $rss_kb, 0, 0, $rec->{tenant_id});
        }
        return;
    }

    return $self->SUPER::end_element($el);
}

1;
