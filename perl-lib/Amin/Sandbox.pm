package Amin::Sandbox;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Elt';

use Amin qw(NS);

sub name    { '' }
sub element { 'sandbox' }

sub position { 'middle' }

{
    my %SCOPE;
    my @STACK;
    my $SCOPE_SEQ = 0;

    sub begin_scope ($pkg_or_self, $attrs) {
        my $id = ++$SCOPE_SEQ;
        my $s = $pkg_or_self->_extract_attrs($attrs);
        $SCOPE{$id} = $s;
        push @STACK, $id;
        return $id;
    }

    sub end_scope ($pkg_or_self, $id = undef) {
        if (!defined $id) { $id = $STACK[-1] }
        if (@STACK && $STACK[-1] == $id) {
            delete $SCOPE{$id};
            pop @STACK;
            return 1;
        }
        return 0;
    }

    sub current_scope_attrs ($pkg_or_self) {
        return undef unless @STACK;
        return $SCOPE{$STACK[-1]};
    }

    sub current_scope_id ($pkg_or_self) {
        return undef unless @STACK;
        return $STACK[-1];
    }

    sub stash_for_spawn ($pkg_or_self, $spawn_id) {
        return $pkg_or_self->current_scope_attrs;
    }

    sub _scope_count_for_tests ($pkg_or_self) {
        return scalar @STACK;
    }
}

sub _extract_attrs ($self, $attrs) {
    return {} unless ref($attrs) eq 'HASH';
    my %out;
    for my $k (keys %$attrs) {
        next unless ref($attrs->{$k}) eq 'HASH';
        my $ln = $attrs->{$k}{LocalName} // '';
        my $v  = $attrs->{$k}{Value};
        next unless defined $v && length $v;
        $out{$ln} = $v;
    }
    return \%out;
}

sub start_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    if ($ns eq NS() && $ln eq 'sandbox') {
        my $scope_id = __PACKAGE__->begin_scope($el->{Attributes});
        $self->{_scope_id} = $scope_id;
        $self->{_cap} = 1;
        require XML::SAX::Base;
        return XML::SAX::Base::start_element($self, $el);
    }
    require XML::SAX::Base;
    return XML::SAX::Base::start_element($self, $el);
}

sub end_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    if ($ns eq NS() && $ln eq 'sandbox' && $self->{_cap}) {
        my $id = delete $self->{_scope_id};
        __PACKAGE__->end_scope($id);
        $self->{_cap} = 0;
        require XML::SAX::Base;
        return XML::SAX::Base::end_element($self, $el);
    }
    require XML::SAX::Base;
    return XML::SAX::Base::end_element($self, $el);
}

sub _prefix_list ($pkg_or_self, $scope_attrs, $mode) {
    return [] unless ref $scope_attrs eq 'HASH';
    my @out;
    my $field = ($mode eq 'rw') ? 'landlock_rw' : 'landlock_ro';
    if (exists $scope_attrs->{$field} && defined $scope_attrs->{$field}) {
        for my $p (split /:/, $scope_attrs->{$field}) {
            next unless defined $p && length $p;
            push @out, $p;
        }
    }
    return \@out;
}

sub _fs_allowed_path ($pkg_or_self, $path, $scope_attrs, $mode = 'any') {
    return 0 unless defined $path && length $path;
    return 1 unless ref $scope_attrs eq 'HASH' && (
        (exists $scope_attrs->{landlock_ro} && length $scope_attrs->{landlock_ro}) ||
        (exists $scope_attrs->{landlock_rw} && length $scope_attrs->{landlock_rw}));
    return 0 unless $path =~ s{^/+}{/};
    my @check;
    if ($mode eq 'rw') {
        @check = ($pkg_or_self->_prefix_list($scope_attrs, 'rw')->@*);
    } elsif ($mode eq 'ro') {
        @check = (
            $pkg_or_self->_prefix_list($scope_attrs, 'ro')->@*,
            $pkg_or_self->_prefix_list($scope_attrs, 'rw')->@*,
        );
    } else {
        @check = (
            $pkg_or_self->_prefix_list($scope_attrs, 'ro')->@*,
            $pkg_or_self->_prefix_list($scope_attrs, 'rw')->@*,
        );
    }
    for my $p (@check) {
        next unless defined $p && length $p;
        my $prefix = $p;
        $prefix =~ s{/+$}{};
        if ($path eq $prefix || $path =~ m{^\Q$prefix\E/}) {
            return 1;
        }
    }
    return 0;
}

sub _dirname ($pkg_or_self, $path) {
    return $path unless defined $path && length $path;
    if ($path =~ m{^(/.*)/[^/]+$}) { return $1 eq '' ? '/' : $1 }
    return '/';
}

sub check_command ($pkg_or_self, $argv_ref, $dir = undef) {
    my $scope = $pkg_or_self->current_scope_attrs;
    return (1, undef) unless defined $scope;
    if (defined $dir && length $dir) {
        unless ($pkg_or_self->_fs_allowed_path($dir, $scope, 'any')) {
            return (0, "dir=$dir not in landlock allowlist");
        }
    }
    my @argv = defined($argv_ref) ? @$argv_ref : ();
    for my $tok (@argv) {
        next unless defined $tok && length $tok && substr($tok, 0, 1) eq '/';
        my $d = $pkg_or_self->_dirname($tok);
        unless ($pkg_or_self->_fs_allowed_path($d, $scope, 'ro')) {
            return (0, "argv token path '$tok' (dirname '$d') not in landlock ro/rw prefixes");
        }
    }
    return (1, undef);
}

sub aminexec_bin_path ($pkg_or_self) {
    require Amin::ToolPaths;
    my $t = Amin::ToolPaths::tool_aminexec();
    # Callers distinguish "found" (executable) from "default hope"; return
    # the canonical resolved path, '' when no binary exists anywhere.
    return length $t ? $t : 'aminexec';
}

sub sb_name_for_scope ($pkg_or_self, $scope_attrs) {
    return undef unless ref $scope_attrs eq 'HASH' && %$scope_attrs;
    require Digest::SHA;
    my @keys = sort keys %$scope_attrs;
    my $canon = join "\0", map { ($_, $scope_attrs->{$_} // '') } @keys;
    return 'sb-' . substr(Digest::SHA::sha256_hex($canon), 0, 16);
}

sub build_manifest_for ($pkg_or_self, $scope_attrs, $argv_ref, $extra = {}) {
    require Digest::SHA;
    my %m;
    my $sb = ref $scope_attrs eq 'HASH' ? $scope_attrs : {};
    my @cgroup_keys = grep {
        exists $sb->{$_} && defined $sb->{$_} && length $sb->{$_}
    } qw(cpu_max memory_max memory_high pids_max io_max);
    my $sb_name;
    if (@cgroup_keys) {
        $sb_name = $pkg_or_self->sb_name_for_scope({
            map {; $_ => $sb->{$_} } @cgroup_keys
        });
        $m{sb_name} = $sb_name if defined $sb_name;
    }
    for my $k (qw(cpu_max memory_max memory_high pids_max io_max seccomp_bpf_base64)) {
        $m{$k} = $sb->{$k} if exists $sb->{$k} && defined $sb->{$k} && length $sb->{$k};
    }
    if (exists $sb->{landlock_ro} && defined $sb->{landlock_ro} && length $sb->{landlock_ro}) {
        $m{landlock_ro} = [grep { defined && length } split /:/, $sb->{landlock_ro}];
    } else { $m{landlock_ro} = [] }
    if (exists $sb->{landlock_rw} && defined $sb->{landlock_rw} && length $sb->{landlock_rw}) {
        $m{landlock_rw} = [grep { defined && length } split /:/, $sb->{landlock_rw}];
    } else { $m{landlock_rw} = [] }
    $m{argv} = [defined($argv_ref) ? @$argv_ref : ()];
    if (ref $extra eq 'HASH') {
        if (exists $extra->{env} && ref $extra->{env} eq 'HASH') {
            $m{env} = { %{$extra->{env}} };
        }
        if (exists $extra->{cwd} && defined $extra->{cwd} && length $extra->{cwd}) {
            $m{cwd} = $extra->{cwd};
        }
        if (exists $extra->{net} && ref $extra->{net} eq 'HASH') {
            my %net;
            for my $k (qw(mode vpc subnet gateway eth0_ip veth_host shared_netns_path)) {
                if (exists $extra->{net}{$k} && defined $extra->{net}{$k} && length $extra->{net}{$k}) {
                    $net{$k} = "$extra->{net}{$k}";
                }
            }
            if (%net) {
                $m{net} = \%net;
            }
        }
    }
    return \%m;
}

sub encode_sandbox_stdin ($pkg_or_self, $manifest) {
    require JSON::PP;
    my $coder = JSON::PP->new->canonical(1)->utf8(1);
    my $json  = $coder->encode($manifest);
    my $len   = length $json;
    die "sandbox manifest JSON too large ($len bytes, max 1MB)" if $len > 1_000_000;
    return pack('V', $len) . $json;
}

1;
