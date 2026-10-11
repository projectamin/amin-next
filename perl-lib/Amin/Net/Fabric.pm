package Amin::Net::Fabric;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Elt';

use Amin qw(NS);

sub name    { '' }
sub element { undef }

sub position { 'middle' }

sub aminexec_bin_path ($pkg_or_self) {
    require Amin::Sandbox;
    return Amin::Sandbox->aminexec_bin_path;
}

{
    my %SCOPE;
    my @STACK;
    my $SCOPE_SEQ = 0;
    my %IP_ALLOC_SEQ;  # scope_id => integer cursor for eth0_ip allocation

    sub begin_scope ($pkg_or_self, $attrs) {
        my $id = ++$SCOPE_SEQ;
        my $s = $pkg_or_self->_extract_attrs($attrs);
        $SCOPE{$id} = $s;
        $IP_ALLOC_SEQ{$id} = 1;  # first allocatable host IP (skip .0 net, .1 gateway)
        push @STACK, $id;
        return $id;
    }

    sub end_scope ($pkg_or_self, $id = undef) {
        if (!defined $id) { $id = $STACK[-1] }
        if (@STACK && $STACK[-1] == $id) {
            delete $SCOPE{$id};
            delete $IP_ALLOC_SEQ{$id};
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

    sub next_allocated_ip ($pkg_or_self, $scope_id = undef) {
        $scope_id //= $pkg_or_self->current_scope_id;
        return undef unless defined $scope_id;
        my $n = ($IP_ALLOC_SEQ{$scope_id} //= 1)++;
        my $attrs = $SCOPE{$scope_id} // {};
        my $subnet = $attrs->{subnet} // '10.0.0.0/24';
        my ($base) = ($subnet =~ m{^(\d+\.\d+\.\d+)\.});
        $base //= '10.0.0';
        return "$base." . ($n + 1);  # .1 reserved for gateway → first alloc = .2
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

sub manifest_for_net ($pkg_or_self, $scope_attrs, $scope_id = undef) {
    $scope_attrs //= $pkg_or_self->current_scope_attrs;
    return undef unless ref($scope_attrs) eq 'HASH' && %$scope_attrs;
    my $mode = lc($scope_attrs->{mode} // 'isolated');
    return undef if $mode eq 'host';
    my $subnet = $scope_attrs->{subnet} // '10.0.0.0/24';
    my $gateway = $scope_attrs->{gateway} // do {
        my ($base) = ($subnet =~ m{^(\d+\.\d+\.\d+)\.});
        $base //= '10.0.0';
        "$base.1";
    };
    my $eth0_ip = $pkg_or_self->next_allocated_ip($scope_id);
    my $veth_seq = sprintf("%03d", int($scope_id // 0) % 1000);
    my $cnt = sprintf("%04d", int(rand(9999)));
    my $veth_host = "vf${veth_seq}-${cnt}";
    return {
        mode              => $mode,
        vpc               => ($scope_attrs->{vpc} // ''),
        subnet            => $subnet,
        gateway           => $gateway,
        eth0_ip           => $eth0_ip,
        veth_host         => $veth_host,
        (exists $scope_attrs->{shared_netns_path} && length $scope_attrs->{shared_netns_path}
            ? (shared_netns_path => $scope_attrs->{shared_netns_path})
            : ()),
    };
}

sub _blessed_sax_el ($pkg_or_self, $localname, $attrs_hash = {}) {
    my $ns = NS();
    my $attrs = {};
    while (my ($k, $v) = each %$attrs_hash) {
        next unless defined $v && length $v;
        $attrs->{"{}$k"} = {
            Name         => $k,
            LocalName    => $k,
            Prefix       => '',
            NamespaceURI => $ns,
            Value        => "$v",
        };
    }
    return {
        NamespaceURI => $ns,
        LocalName    => $localname,
        Name         => "{$ns}$localname",
        Attributes   => $attrs,
    };
}

sub emit_net_delta ($self, $op, $extra = {}) {
    my $el = $self->_blessed_sax_el('net', {
        %$extra,
        op => $op,
    });
    require XML::SAX::Base;
    XML::SAX::Base::start_element($self, $el);
    XML::SAX::Base::end_element($self, $el);
    return;
}

sub emit_lb_delta ($self, $op, $extra = {}) {
    my $el = $self->_blessed_sax_el('lb', {
        %$extra,
        op => $op,
    });
    require XML::SAX::Base;
    XML::SAX::Base::start_element($self, $el);
    XML::SAX::Base::end_element($self, $el);
    return;
}

sub emit_netpolicy_delta ($self, $op, $extra = {}) {
    my $el = $self->_blessed_sax_el('netpolicy', {
        %$extra,
        op => $op,
    });
    require XML::SAX::Base;
    XML::SAX::Base::start_element($self, $el);
    XML::SAX::Base::end_element($self, $el);
    return;
}

sub start_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    if ($ns eq NS() && ($ln eq 'net' || $ln eq 'lb' || $ln eq 'netpolicy')) {
        my $attrs = $self->_extract_attrs($el->{Attributes});
        if ($ln eq 'net') {
            my $scope_id = __PACKAGE__->begin_scope($el->{Attributes});
            $self->{_scope_id} = $scope_id;
            $self->{_cap} = 1;
            $self->emit_net_delta('open_scope', {
                vpc      => ($attrs->{vpc}    // ''),
                subnet   => ($attrs->{subnet} // ''),
                mode     => ($attrs->{mode}   // 'isolated'),
                scope_id => $scope_id,
            });
            require XML::SAX::Base;
            return XML::SAX::Base::start_element($self, $el);
        } elsif ($ln eq 'lb') {
            $self->emit_lb_delta('init', {
                vip       => ($attrs->{vip}      // ''),
                backends  => ($attrs->{backends} // ''),
                policy    => ($attrs->{policy}   // ''),
                hc        => ($attrs->{hc}       // ''),
            });
            if (exists $attrs->{backend_drain} && defined $attrs->{backend_drain} && length $attrs->{backend_drain}) {
                $self->emit_lb_delta('drain_backend', {
                    backend_drain => $attrs->{backend_drain},
                });
            }
            require XML::SAX::Base;
            return XML::SAX::Base::start_element($self, $el);
        } elsif ($ln eq 'netpolicy') {
            $self->emit_netpolicy_delta('add_rule', {
                'from'  => ($attrs->{'from'}  // ''),
                'to'    => ($attrs->{'to'}    // ''),
                'allow' => ($attrs->{'allow'} // ''),
            });
            require XML::SAX::Base;
            return XML::SAX::Base::start_element($self, $el);
        }
    }
    require XML::SAX::Base;
    return XML::SAX::Base::start_element($self, $el);
}

sub end_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    if ($ns eq NS() && $ln eq 'net' && $self->{_cap}) {
        my $id = delete $self->{_scope_id};
        my $attrs = __PACKAGE__->current_scope_attrs // {};
        $self->emit_net_delta('close_scope', {
            scope_id => $id,
            vpc      => $attrs->{vpc} // '',
            mode     => $attrs->{mode} // 'isolated',
        });
        __PACKAGE__->end_scope($id);
        $self->{_cap} = 0;
        require XML::SAX::Base;
        return XML::SAX::Base::end_element($self, $el);
    }
    if ($ns eq NS() && ($ln eq 'lb' || $ln eq 'netpolicy')) {
        require XML::SAX::Base;
        return XML::SAX::Base::end_element($self, $el);
    }
    require XML::SAX::Base;
    return XML::SAX::Base::end_element($self, $el);
}

1;
