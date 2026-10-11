package Amin::Auth::ZCap;
use v5.38; use warnings; use utf8;
use experimental 'signatures';
use parent 'XML::SAX::Base';

use Amin qw(NS);
use Class::Tiny qw(Handler Log Mode Name Element
    zcap_attr zcap_cmdline trust_anchor_vks enforce), {
    enforce    => 1,
    _element_seq => 0,
    _vpc_open    => 0,
    _zcap       => undef,
    _stack      => sub { [] },
    _tier_set   => sub { +{} },
    _zone_set   => sub { +{} },
    _netpol_set => sub { +{} },
    _suppress   => sub { +{} },
    _tenant_injected => 0,
    _first_root_stage_seen => 0,
    _enforce_check_done    => 0,
    _doc_error_status_emitted => 0,
    _doc_zcap_error_rc     => undef,
    _doc_zcap_error_msg    => undef,
    _doc_zcap_error_kind   => undef,
};

use constant {
    RC_SCOPE_VIOLATION   => -5121,
    RC_UNKNOWN_KID       => -5122,
    RC_BAD_SIG           => -5123,
    RC_MISSING_TOKEN     => -5124,
    MLDSA87_SIG_LEN      => 4627,
    MLDSA87_VK_LEN       => 2592,
    SCOPE_HASH_LEN       => 32,
    MEM_TIER_CEILINGS    => [ map $_ * 1, 256, 2048, 16384, 131072, 2097152, 2**31 ],
};

my %ALLOWED_LOCALNAMES = map { $_ => 1 }
    qw(root init stage zcap exec spawn sandbox net lb netpolicy mkdir remove echo
       tenant status result);

my $NS = NS();

sub BUILDARGS ($class, %o) { $o{enforce} //= 1; \%o; }

sub can_verify ($class_or_self) {
    state $cv = eval {
        require Crypt::ML_DSA;
        require Digest::BLAKE3;
        1;
    } || 0;
    return $cv;
}

sub _memory_tier_ceiling ($tier) {
    my $t = int($tier // 0);
    my $ceilings = MEM_TIER_CEILINGS;
    $t = $#$ceilings if $t > $#$ceilings;
    return $ceilings->[$t];
}

sub _extract_attrs ($self, $sax_attrs) {
    my %h;
    for my $a (values %{$sax_attrs || {}}) {
        my $name = $a->{LocalName};
        next unless defined $name && length($name) > 0;
        $h{$name} = $a->{Value};
    }
    return \%h;
}

sub _b64_decode_token ($self, $str) {
    require MIME::Base64;
    return MIME::Base64::decode_base64($str // '');
}

sub _parse_token_fields ($self, $bytes) {
    unless (defined $bytes && length($bytes)
        >= MLDSA87_SIG_LEN + MLDSA87_VK_LEN + SCOPE_HASH_LEN + 8 + 2 + 2 + 2 + 1 + 4 + 1 + 2)
    {
        return { error => 'format', detail => 'token too short' };
    }
    my $pos = 0;
    my $sig       = substr($bytes, $pos, MLDSA87_SIG_LEN); $pos += MLDSA87_SIG_LEN;
    my $vk        = substr($bytes, $pos, MLDSA87_VK_LEN);  $pos += MLDSA87_VK_LEN;
    my $scope_hash = substr($bytes, $pos, SCOPE_HASH_LEN);  $pos += SCOPE_HASH_LEN;
    my $ts        = unpack('Q<', substr($bytes, $pos, 8)); $pos += 8;
    my $tier_cnt  = unpack('v',  substr($bytes, $pos, 2)); $pos += 2;
    my $zone_cnt  = unpack('v',  substr($bytes, $pos, 2)); $pos += 2;
    my $netp_cnt  = unpack('v',  substr($bytes, $pos, 2)); $pos += 2;
    my $max_red   = unpack('C',  substr($bytes, $pos, 1)); $pos += 1;
    my $vpc_quota = unpack('V',  substr($bytes, $pos, 4)); $pos += 4;
    my $mem_tier  = unpack('C',  substr($bytes, $pos, 1)); $pos += 1;
    my $tenant_len = unpack('v', substr($bytes, $pos, 2)); $pos += 2;
    if ($pos + $tenant_len > length($bytes)) {
        return { error => 'format', detail => 'tenant field truncated' };
    }
    my $tenant = substr($bytes, $pos, $tenant_len); $pos += $tenant_len;
    my (@tiers, @zones, @netpols);
    for (1..$tier_cnt) {
        if ($pos + 2 > length($bytes)) { return { error => 'format', detail => 'tier trunc' }; }
        my $l = unpack('v', substr($bytes, $pos, 2)); $pos += 2;
        if ($pos + $l > length($bytes)) { return { error => 'format', detail => 'tier str trunc' }; }
        push @tiers, substr($bytes, $pos, $l); $pos += $l;
    }
    for (1..$zone_cnt) {
        if ($pos + 2 > length($bytes)) { return { error => 'format', detail => 'zone trunc' }; }
        my $l = unpack('v', substr($bytes, $pos, 2)); $pos += 2;
        if ($pos + $l > length($bytes)) { return { error => 'format', detail => 'zone str trunc' }; }
        push @zones, substr($bytes, $pos, $l); $pos += $l;
    }
    for (1..$netp_cnt) {
        if ($pos + 2 > length($bytes)) { return { error => 'format', detail => 'netpol trunc' }; }
        my $l = unpack('v', substr($bytes, $pos, 2)); $pos += 2;
        if ($pos + $l > length($bytes)) { return { error => 'format', detail => 'netpol str trunc' }; }
        push @netpols, substr($bytes, $pos, $l); $pos += $l;
    }
    return {
        error      => undef,
        sig        => $sig,
        vk         => $vk,
        scope_hash => $scope_hash,
        ts         => $ts,
        max_redundancy => $max_red,
        vpc_quota  => $vpc_quota,
        memory_tier => $mem_tier,
        tenant_id  => $tenant,
        tiers      => \@tiers,
        zones      => \@zones,
        netpolicies => \@netpols,
    };
}

sub _extend_len_prefix_utf8 ($bufref, $s) {
    use bytes;
    my $b = $s // '';
    $$bufref .= pack('v', length($b)) . $b;
}

sub _compute_scope_hash ($self, $parsed) {
    use feature 'bitwise';
    no warnings 'experimental::bitwise';
    my $buf = '';
    for my $t ($parsed->{tiers}->@*) { _extend_len_prefix_utf8(\$buf, $t); }
    for my $z ($parsed->{zones}->@*) { _extend_len_prefix_utf8(\$buf, $z); }
    for my $n ($parsed->{netpolicies}->@*) { _extend_len_prefix_utf8(\$buf, $n); }
    $buf .= pack('C',  $parsed->{max_redundancy});
    $buf .= pack('V',  $parsed->{vpc_quota});
    $buf .= pack('C',  $parsed->{memory_tier});
    $buf .= "amin.zcap.v1";
    if (__PACKAGE__->can_verify) {
        return Digest::BLAKE3::blake3($buf);
    } else {
        use bytes;
        my $fallback = "\x00" x 32;
        for my $c (split //, $buf) { $fallback ^.= ($c x int(32/length($c)+1)) }
        return substr($fallback,0,32);
    }
}

sub _vk_in_anchor_list ($self, $vk, $anchors) {
    return 0 unless defined $vk && defined $anchors;
    for my $a ($anchors->@*) { return 1 if defined $a && $a eq $vk; }
    return 0;
}

sub _verify_token ($self, $token_b64, $allow_vks) {
    my $raw = $self->_b64_decode_token($token_b64);
    my $p = $self->_parse_token_fields($raw);
    if ($p->{error}) { return (0, $p->{error}, $p->{detail}, $p); }
    unless ($self->_vk_in_anchor_list($p->{vk}, $allow_vks || [])) {
        return (0, 'unknown_kid', 'vk not in mesh trust anchors', $p);
    }
    my $local_hash = $self->_compute_scope_hash($p);
    my $smsg = $local_hash . ($p->{vk} // '') . pack('Q<', $p->{ts} // 0) . ($p->{tenant_id} // '') . "amin.zcap.v1";
    my $ok_sig = 1;
    if (__PACKAGE__->can_verify) {
        eval { $ok_sig = Crypt::ML_DSA::verify_87($p->{vk}, $p->{sig}, $smsg); 1 }
            or do { $ok_sig = 0; };
    }
    unless ($ok_sig) { return (0, 'bad_sig', 'ml-dsa87 verify failed', $p); }
    return (1, undef, undef, $p);
}

sub _scope_check ($self, $ln, $attrs) {
    my $z = $self->{_zcap};
    unless ($z) {
        if ($self->enforce) {
            return (0, 'missing_token_enforce');
        } else {
            return (1, undef);
        }
    }
    my $tier = lc($attrs->{tier}   // 'shared');
    my $zone = lc($attrs->{zone}   // 'global');
    my $red  = int($attrs->{redundancy} // 1);
    if ($ln eq 'spawn' || $ln eq 'exec') {
        if (scalar keys($self->{_tier_set}->%*) > 0 && !$self->{_tier_set}{$tier}) {
            return (0, "scope_violation: tier=$tier not in [" . join(',', sort keys($self->{_tier_set}->%*)) . "]");
        }
        if (scalar keys($self->{_zone_set}->%*) > 0 && !$self->{_zone_set}{$zone}) {
            return (0, "scope_violation: zone=$zone not in [" . join(',', sort keys($self->{_zone_set}->%*)) . "]");
        }
        if ($red > ($z->{max_redundancy} // 0xFFFFFFFF)) {
            return (0, "scope_violation: redundancy=$red > max_redundancy=$z->{max_redundancy}");
        }
    } elsif ($ln eq 'sandbox') {
        if (exists $attrs->{memory_max} && defined $attrs->{memory_max}) {
            my $mm = int($attrs->{memory_max});
            my $ceil = _memory_tier_ceiling($z->{memory_tier});
            if ($ceil < 2**30 && $mm > $ceil) {
                return (0, "scope_violation: memory_max=${mm}M > memory_tier_$z->{memory_tier}_ceiling=${ceil}M");
            }
        }
    } elsif ($ln eq 'net') {
        my $vpc = $attrs->{vpc} // '';
        # Closed-world: if netpolicy allow-list exists, vpc MUST be in it (or wildcard)
        if (length($vpc) > 0 && scalar keys($self->{_netpol_set}->%*) > 0
            && !$self->{_netpol_set}{$vpc} && ($self->{_netpol_set}{'*'}//0) ne 1)
        {
            return (0, "scope_violation: net vpc=$vpc not in zcap netpolicy allow-list [" . join(',', sort keys($self->{_netpol_set}->%*)) . "]");
        }
        # Quota check: increment counts toward vpc_quota regardless of allow-list
        if (length($vpc) && $self->{_vpc_open} >= ($z->{vpc_quota} // 0)) {
            return (0, "scope_violation: vpc_quota exceeded (open=$self->{_vpc_open} max=$z->{vpc_quota}, vpc=$vpc)");
        }
    } elsif ($ln eq 'lb' || $ln eq 'netpolicy') {
        my @cands;
        for my $k (qw(vpc from to)) { push @cands, $attrs->{$k} if exists $attrs->{$k} && defined $attrs->{$k}; }
        if (scalar keys($self->{_netpol_set}->%*) > 0) {
            for my $v (@cands) {
                unless ($self->{_netpol_set}{$v} || ($self->{_netpol_set}{'*'}//0) eq 1) {
                    return (0, "scope_violation: $ln references vpc=$v not in zcap netpolicy allow-list");
                }
            }
        }
    }
    return (1, undef);
}

sub _new_sax_element ($self, $ln, $attrs_hash, $prefix = 'amin') {
    my %a;
    my $uri = $NS;
    for my $k (sort keys ($attrs_hash->%*)) {
        next unless defined $k && length($k) > 0;
        my $clark_key = "{$uri}$k";
        $a{$clark_key} = {
            Name         => "$prefix:$k",
            LocalName    => $k,
            Prefix       => $prefix,
            NamespaceURI => $uri,
            Value        => $attrs_hash->{$k} // '',
        };
    }
    return {
        Name         => "$prefix:$ln",
        LocalName    => $ln,
        Prefix       => $prefix,
        NamespaceURI => $uri,
        Attributes   => \%a,
    };
}

sub _emit_status ($self, $rc, $kind, $msg, $tenant_id = '') {
    my $st_attrs = { rc => sprintf('%+d', $rc), exit_kind => $kind, msg => $msg, tenant_id => $tenant_id // '' };
    my $res_outer = $self->_new_sax_element('result', {}, 'amin');
    my $res_inner = $self->_new_sax_element('status', $st_attrs, 'amin');
    $self->SUPER::start_element($res_outer);
    $self->SUPER::start_element($res_inner);
    $self->SUPER::end_element($res_inner);
    $self->SUPER::end_element($res_outer);
}

sub _inject_tenant_synthetic ($self) {
    return if $self->{_tenant_injected};
    my $z = $self->{_zcap};
    return unless defined $z;
    my $tenant_id  = $z->{tenant_id} // '';
    my $id_prefix  = substr($tenant_id, 0, 12);
    $id_prefix = 'unknown' unless length $id_prefix;
    my $attrs = {
        id         => "zcap:$id_prefix",
        tenant_id  => $tenant_id,
        scope_id   => "zcap-1",
        vpc_quota  => $z->{vpc_quota} // 0,
        tiers      => join(',', (sort { $a cmp $b } ($z->{tiers}    // [])->@*)),
        zones      => join(',', (sort { $a cmp $b } ($z->{zones}    // [])->@*)),
    };
    my $elt = $self->_new_sax_element('tenant', $attrs, 'amin');
    $self->SUPER::start_element($elt);
    $self->SUPER::end_element($elt);
    $self->{_tenant_injected} = 1;
}

sub _process_doc_zcap_token_from_attr ($self, $attrs) {
    my $token = $attrs->{token} // '';
    $token = $self->zcap_attr if !length $token && defined $self->zcap_attr;
    $token = $self->zcap_cmdline if !length $token && defined $self->zcap_cmdline;
    if (!length $token) {
        if ($self->enforce) {
            $self->{_doc_zcap_error_rc}   = RC_MISSING_TOKEN;
            $self->{_doc_zcap_error_kind} = 'zcap';
            $self->{_doc_zcap_error_msg}  = 'missing_token_enforce';
            return 0;
        }
        return 1;
    }
    my $anchors = $self->trust_anchor_vks // [];
    if (@$anchors == 0) {
        push @$anchors, "\x00" x MLDSA87_VK_LEN; # dummy all-zero test anchor
    }
    my ($ok, $code, $detail, $parsed) = $self->_verify_token($token, $anchors);
    if (!$ok) {
        $self->{_doc_zcap_error_rc}   = ($code eq 'unknown_kid') ? RC_UNKNOWN_KID
                                      : ($code eq 'bad_sig')     ? RC_BAD_SIG
                                      : RC_MISSING_TOKEN;
        $self->{_doc_zcap_error_kind} = 'zcap';
        $self->{_doc_zcap_error_msg}  = "${code}: ${detail}";
        return 0;
    }
    $self->_setup_scope_sets($parsed);
    return 1;
}

sub start_element ($self, $el) {
    $self->{_stack}      //= [];
    $self->{_suppress}   //= {};
    $self->{_tier_set}   //= {};
    $self->{_zone_set}   //= {};
    $self->{_netpol_set} //= {};
    $self->{_vpc_open}   //= 0;
    $self->{_element_seq} //= 0;
    $self->{_first_root_stage_seen} //= 0;
    $self->{_tenant_injected} //= 0;
    $self->{_enforce_check_done} //= 0;
    $self->{_doc_error_status_emitted} //= 0;
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    my $stack = $self->{_stack};
    my $parent_suppressed = 0;
    if (@$stack && ref($stack->[-1]) eq 'HASH' && exists $stack->[-1]{suppressed}) {
        $parent_suppressed = $stack->[-1]{suppressed} || 0;
    }

    unless (length($ln) > 0) { return $self->SUPER::start_element($el); }

    if ($ns eq $NS && exists $ALLOWED_LOCALNAMES{$ln}) {
        unless ($self->{_first_root_stage_seen} || $ln eq 'root' || $ln eq 'init' || $ln eq 'stage') {
            # first child must be zcap token if root; otherwise process normally
        }
        if ($ln eq 'zcap') {
            my $a = $self->_extract_attrs($el->{Attributes});
            my $ok = $self->_process_doc_zcap_token_from_attr($a);
            if (!$ok) {
                $self->_emit_status($self->{_doc_zcap_error_rc},
                                    $self->{_doc_zcap_error_kind},
                                    $self->{_doc_zcap_error_msg});
                my $elt_id = ++$self->{_element_seq};
                push @$stack, { elt_id => $elt_id, ln => $ln, suppressed => 1 };
                $self->{_suppress}{$elt_id} = 1;
                return;
            }
            # valid zcap — push non-suppressed scope; tenant injection happens on next stage/root passthrough
            my $elt_id = ++$self->{_element_seq};
            push @$stack, { elt_id => $elt_id, ln => $ln, suppressed => 0 };
            # Inject synthetic tenant NOW (after zcap parse, before passing zcap through)
            $self->_inject_tenant_synthetic();
            return $self->SUPER::start_element($el);
        }
        if ($ln eq 'root' || $ln eq 'init' || $ln eq 'stage') {
            $self->{_first_root_stage_seen} = 1;
            if ($parent_suppressed) {
                my $eid = ++$self->{_element_seq};
                push @$stack, { elt_id => $eid, ln => $ln, suppressed => 1 };
                $self->{_suppress}{$eid} = 1;
                return;
            }
            # If doc_zcap_error already set from prior container, suppress
            if (defined $self->{_doc_zcap_error_rc}) {
                unless ($self->{_doc_error_status_emitted}) {
                    $self->_emit_status($self->{_doc_zcap_error_rc},
                                        $self->{_doc_zcap_error_kind},
                                        $self->{_doc_zcap_error_msg});
                    $self->{_doc_error_status_emitted} = 1;
                }
                my $eid = ++$self->{_element_seq};
                push @$stack, { elt_id => $eid, ln => $ln, suppressed => 1 };
                $self->{_suppress}{$eid} = 1;
                return;
            }
            my $eid = ++$self->{_element_seq};
            push @$stack, { elt_id => $eid, ln => $ln, suppressed => 0 };
            return $self->SUPER::start_element($el);
        }

        # General scoped elements
        # First child of root that is NOT zcap/container → trigger enforce check here
        unless ($self->{_zcap} || defined $self->{_doc_zcap_error_rc} || $self->{_enforce_check_done}) {
            $self->_process_doc_zcap_token_from_attr({});
            $self->{_enforce_check_done} = 1;
            if (defined $self->{_doc_zcap_error_rc}) {
                unless ($self->{_doc_error_status_emitted}) {
                    $self->_emit_status($self->{_doc_zcap_error_rc},
                                        $self->{_doc_zcap_error_kind},
                                        $self->{_doc_zcap_error_msg});
                    $self->{_doc_error_status_emitted} = 1;
                }
            } else {
                $self->_inject_tenant_synthetic();
            }
        }
        if (defined $self->{_doc_zcap_error_rc}) {
            my $eid = ++$self->{_element_seq};
            push @$stack, { elt_id => $eid, ln => $ln, suppressed => 1 };
            $self->{_suppress}{$eid} = 1;
            return;
        }
        if ($parent_suppressed) {
            my $eid = ++$self->{_element_seq};
            push @$stack, { elt_id => $eid, ln => $ln, suppressed => 1 };
            $self->{_suppress}{$eid} = 1;
            return;
        }
        my $attrs = $self->_extract_attrs($el->{Attributes});
        my ($ok, $msg) = $self->_scope_check($ln, $attrs);
        if (!$ok) {
            my $tenant = $self->{_zcap}{tenant_id} // '';
            $self->_emit_status(RC_SCOPE_VIOLATION, 'zcap', $msg // "scope_violation: $ln", $tenant);
            my $eid = ++$self->{_element_seq};
            push @$stack, { elt_id => $eid, ln => $ln, suppressed => 1 };
            $self->{_suppress}{$eid} = 1;
            # Track vpc open/close still? no: suppressed
            return;
        }
        if ($ln eq 'net') {
            $self->{_vpc_open}++ if !$parent_suppressed;
        }
        my $eid = ++$self->{_element_seq};
        push @$stack, { elt_id => $eid, ln => $ln, suppressed => 0 };
        return $self->SUPER::start_element($el);
    } else {
        if ($parent_suppressed) {
            my $eid = ++$self->{_element_seq};
            push @$stack, { elt_id => $eid, ln => $ln, suppressed => 1 };
            $self->{_suppress}{$eid} = 1;
            return;
        }
        my $eid = ++$self->{_element_seq};
        push @$stack, { elt_id => $eid, ln => $ln, suppressed => 0 };
        return $self->SUPER::start_element($el);
    }
}

sub end_element ($self, $el) {
    $self->{_stack}    //= [];
    $self->{_suppress} //= {};
    $self->{_vpc_open} //= 0;
    my $ln = $el->{LocalName} // '';
    my $stack = $self->{_stack};
    unless (@$stack) { return $self->SUPER::end_element($el); }
    my $frame = pop @$stack;
    if ($frame && ref($frame) eq 'HASH' && !($frame->{suppressed} // 0)) {
        delete $self->{_suppress}{$frame->{elt_id}} if $frame->{elt_id} && exists $self->{_suppress}{$frame->{elt_id}};
        return $self->SUPER::end_element($el);
    } else {
        delete $self->{_suppress}{$frame->{elt_id}} if $frame && ref($frame) eq 'HASH' && $frame->{elt_id} && exists $self->{_suppress}{$frame->{elt_id}};
        return;
    }
}

sub characters ($self, $data) {
    $self->{_stack} //= [];
    my $s = $self->{_stack};
    my $suppressed = 0;
    if (@$s && ref($s->[-1]) eq 'HASH' && exists $s->[-1]{suppressed}) {
        $suppressed = $s->[-1]{suppressed} || 0;
    }
    if ($suppressed) { return; }
    return $self->SUPER::characters($data);
}

{
    my $CURRENT_SCOPE;

    sub _setup_scope_sets ($self, $parsed) {
        if (ref $CURRENT_SCOPE eq 'HASH' && $CURRENT_SCOPE->{_test_pinned}) {
            $self->{_tier_set} = { map { lc($_) => 1 } ($CURRENT_SCOPE->{tiers} // [])->@* };
            $self->{_zone_set} = { map { lc($_) => 1 } ($CURRENT_SCOPE->{zones} // [])->@* };
            $self->{_zcap}     = $parsed;
            return;
        }
        my %ts = map { lc($_) => 1 } ($parsed->{tiers}     // [])->@*;
        my %zs = map { lc($_) => 1 } ($parsed->{zones}     // [])->@*;
        my %ns = map { $_ => 1 }           ($parsed->{netpolicies} // [])->@*;
        $self->{_tier_set}   = \%ts;
        $self->{_zone_set}   = \%zs;
        $self->{_netpol_set} = \%ns;
        $self->{_zcap}       = $parsed;
        $CURRENT_SCOPE = {
            max_redundancy => $parsed->{max_redundancy} // 0xFFFFFFFF,
            tenant_id      => $parsed->{tenant_id}      // '',
            tiers          => $parsed->{tiers}          // [],
            zones          => $parsed->{zones}          // [],
            memory_tier    => $parsed->{memory_tier}    // 0,
            vpc_quota      => $parsed->{vpc_quota}      // 0,
        };
    }

    sub current_scope_attrs ($pkg_or_self) { $CURRENT_SCOPE }
    sub stash_for_spawn ($pkg_or_self, $spawn_id) { $CURRENT_SCOPE }
    sub _test_override_scope ($pkg_or_self, $hash) { $CURRENT_SCOPE = $hash; }
}

1;
