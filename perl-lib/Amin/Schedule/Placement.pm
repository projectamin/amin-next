package Amin::Schedule::Placement;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Elt';

use Amin qw(NS);
use Class::Tiny qw(mesh transport), {
    _placement_seq         => 0,
    _cap                   => 0,
    _cap_suppress          => 0,
    _suppress_subtree_d    => 0,
    _buf                   => '',
    _capture_attrs         => sub { +{} },
    _chain_downstream      => undef,
};
# NOTE: XML::SAX::Base (via Amin::Elt parent) overrides Class::Tiny's new(),
# so BUILD subs are NEVER invoked.  All instance defaults must be lazily
# initialized inside individual methods via `//=` or on first use.
sub _ensure_defaults ($self) {
    $self->{_suppress_subtree_d} //= 0;
    $self->{_cap} //= 0;
    $self->{_cap_suppress} //= 0;
    $self->{_placement_seq} //= 0;
    # Constructor-time downstream sink: points at the Dispatcher chain's
    # next link.  Handler may be swapped per-element later, so only capture
    # on first invocation (when Handler is still the post-begin chain link).
    if (!defined $self->{_chain_downstream}) {
        $self->{_chain_downstream} = $self->Handler
            if defined wantarray || defined $self->Handler;
    }
    return 1;
}

use constant {
    RC_NO_ELIGIBLE_PEER => -6144,
    RC_ALL_TIMEOUT      => -6145,
    RC_REMOTE_INVALID   => -6146,
    TIER_MISMATCH       => 100_000,
    ZONE_MISMATCH       => 500,
    HOT_REF_NO_OVERLAP  => 250,
    LOAD_SCALE          => 5,
    INELIGIBLE          => 100_000,
    WORKING_SET_SSD_GB  => 1,
    DEFAULT_MAX_RED     => 255,
    LOCAL_PREFERENCE    => 1_000,
};

sub name    { '' }
sub element { '' }

sub _extract_attrs ($self, $sax_attrs) {
    my %h;
    for my $a (values %{$sax_attrs || {}}) {
        my $name = $a->{LocalName};
        next unless defined $name && length($name) > 0;
        $h{$name} = $a->{Value};
    }
    return \%h;
}

sub _ns_attrs ($hash, $prefix = 'amin') {
    my $uri = NS();
    +{ map {;
        "{$uri}$_" => { Name => "$prefix:$_", LocalName => $_, Prefix => $prefix,
                        NamespaceURI => $uri,
                        Value => defined $hash->{$_} ? "$hash->{$_}" : '' }
    } keys %$hash };
}

sub _emit_synthetic ($self, $ln, $attrs_hash) {
    my $el = {
        NamespaceURI => NS(), LocalName => $ln, Name => "amin:$ln", Prefix => 'amin',
        Attributes   => _ns_attrs($attrs_hash),
    };
    $self->SUPER::start_element($el);
    $self->SUPER::end_element($el);
}

sub _emit_result_status ($self, %meta) {
    my $h = $self->Handler or return;
    $h->start_element({
        NamespaceURI => NS(), LocalName => 'result', Name => 'amin:result',
        Prefix => 'amin',
        Attributes => _ns_attrs({ kind => $meta{kind} // 'error', rc => '' }) });
    $h->start_element({
        NamespaceURI => NS(), LocalName => 'status', Name => 'amin:status',
        Prefix => 'amin',
        Attributes => _ns_attrs(\%meta) });
    $h->end_element({
        NamespaceURI => NS(), LocalName => 'status', Name => 'amin:status',
        Prefix => 'amin' });
    $h->end_element({
        NamespaceURI => NS(), LocalName => 'result', Name => 'amin:result',
        Prefix => 'amin' });
    return;
}

sub start_element ($self, $el) {
    $self->_ensure_defaults;
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    my $is_run_target = ($ns eq NS() && ($ln eq 'spawn' || $ln eq 'exec'));
    if (($self->{_suppress_subtree_d} // 0) > 0) {
        $self->{_suppress_subtree_d}++;
        return;
    }
    if ($is_run_target) {
        my $attrs = $self->_extract_attrs($el->{Attributes});
        my ($winner, $score, @topn) = $self->_score_and_pick($attrs);
        my $clamped = $self->_redundancy_count($attrs, scalar(@topn));
        @topn = splice @topn, 0, $clamped if @topn > $clamped;
        unless (defined $winner) {
            $self->_emit_synthetic(placement =>
                { decision => 'no_eligible', peer => 'none',
                  score => INELIGIBLE });
            $self->_emit_result_status(
                rc        => sprintf('%+d', RC_NO_ELIGIBLE_PEER),
                exit_kind => 'placement',
                msg       => 'no eligible peer');
            $self->{_suppress_subtree_d} = 1;
            return;
        }
        $self->{_placement_seq}++;
        my $seq = $self->{_placement_seq};
        if ($winner eq 'local') {
            $self->_emit_synthetic(placement => {
                decision => 'local', peer => 'local',
                node_id  => $self->_hex($self->_lazy_mesh->local_node_id),
                score    => $score,
                seq      => $seq,
            });
            return $self->SUPER::start_element($el);
        }
        $self->_emit_synthetic(placement => {
            decision         => 'remote',
            peer             => $self->_hex($winner->{node_id}),
            winner           => $self->_hex($winner->{node_id}),
            score            => $score,
            seq              => $seq,
            clamped_redundancy => scalar(@topn),
        });
        $self->_spawn_capture_begin($attrs, \@topn, $ln);
        return;
    }
    if (($self->{_cap} // 0) > 0) {
        $self->{_capture}{events} //= [];
        push @{$self->{_capture}{events}}, { type => 'start', el => $el };
    }
    return $self->SUPER::start_element($el) unless ($self->{_cap_suppress} // 0) > 0;
}

sub characters ($self, $d) {
    if (($self->{_suppress_subtree_d} // 0) > 0) { return; }
    if (($self->{_cap} // 0) > 0) {
        $self->{_buf} .= $d->{Data} // '';
        push @{$self->{_capture}{events}}, { type => 'chars', data => $d->{Data} };
    }
    return $self->SUPER::characters($d) unless ($self->{_cap_suppress} // 0) > 0;
}

sub end_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    if (($self->{_suppress_subtree_d} // 0) > 0) {
        $self->{_suppress_subtree_d}--;
        return;
    }
    if (($self->{_cap} // 0) > 0) {
        push @{$self->{_capture}{events}}, { type => 'end', el => $el };
        if ($ns eq NS() && ($ln eq 'spawn' || $ln eq 'exec')
            && $ln eq ($self->{_capture}{root_ln} // '')) {
            $self->_spawn_capture_end;
            return;
        }
    }
    return $self->SUPER::end_element($el) unless ($self->{_cap_suppress} // 0) > 0;
}

sub _spawn_capture_begin ($self, $attrs, $topn_peers, $root_ln = 'spawn') {
    $self->{_cap} = 1;
    $self->{_cap_suppress} = 1;
    $self->{_buf} = '';
    $self->{_capture} = { attrs => $attrs, peers => $topn_peers, events => [],
                          root_ln => $root_ln };
}

sub _spawn_capture_end ($self) {
    my $c = delete $self->{_capture};
    $self->{_cap} = 0;
    $self->{_cap_suppress} = 0;
    my @peer_ids = map { $_->{node_id} } @{$c->{peers}};
    my $bsax_bytes = $self->_serialize_capture_to_canonical($c);
    my $context = $self->_build_context;
    my @handles = $self->_lazy_transport->dispatch_spawn_remote(\@peer_ids, $bsax_bytes, $context);
    my ($winner_bytes) = $self->_first_winner_poll(\@handles);
    if (defined $winner_bytes) {
        $self->_reinject_stream_bytes_as_sax($winner_bytes);
    } else {
        $self->_emit_result_status(
            rc        => sprintf('%+d', RC_ALL_TIMEOUT),
            exit_kind => 'placement',
            msg       => 'dispatch_all_timeout');
    }
    return;
}

sub _first_winner_poll ($self, $handles) {
    my @h = @$handles;
    return () unless @h;
    my %seen;
    my $deadline = time + 5;
    my %buf;
    while (time <= $deadline) {
        my $some = 0;
        my $all_seen = 1;
        for my $hi (0 .. $#h) {
            next if $seen{$hi};
            $all_seen = 0;
            my $hd = $h[$hi];
            my $b = $hd->poll_stream(4096);
            if (defined $b && length($b)) {
                $buf{$hi} .= $b;
                $some = 1;
                if ($buf{$hi} =~ /<(?:amin:)?status[^>]*exit_kind="ok"/) {
                    my $winner_ix = $hi;
                    my $tr = $self->transport;
                    for my $lj (0 .. $#h) {
                        next if $lj == $winner_ix;
                        $h[$lj]->cancel;
                        $tr->cancel_count(($tr->cancel_count // 0) + 1) if $tr && $tr->can('cancel_count');
                    }
                    return $buf{$winner_ix};
                }
            } elsif (!defined $b) {
                $seen{$hi} = 1;
            }
        }
        last if $all_seen;
        select(undef, undef, undef, 0.001) unless $some;
    }
    {
        my $tr = $self->transport;
        for my $lj (0 .. $#h) {
            $h[$lj]->cancel;
            $tr->cancel_count(($tr->cancel_count // 0) + 1) if $tr && $tr->can('cancel_count');
        }
    }
    return undef;
}

sub _reinject_stream_bytes_as_sax ($self, $bytes) {
    return unless defined $bytes && length($bytes);
    $self->_ensure_defaults;
    require XML::LibXML::SAX;
    my $target = $self->{_chain_downstream} // $self->Handler // $self;
    my $inner = Amin::Schedule::Placement::_SAXReinject->new(
        forward       => $target,
        skip_outer    => 1,
    );
    eval {
        XML::LibXML::SAX->new(Handler => $inner)->parse_string($bytes);
    };
    return;
}

sub _score_and_pick ($self, $attrs) {
    my $mesh = $self->_lazy_mesh;
    my @all;
    my $local_id = $mesh->local_node_id;
    my $local_peer = $self->{_local_peer_override}
        // $Amin::Schedule::Placement::_LocalPeerTestOverride
        // {
        node_id     => $local_id,
        tier        => $self->_local_tier_from_profile($attrs),
        zone        => $attrs->{zone} // 'global',
        load_pct    => 50,
        free_mem_MB => 1_000_000,
        free_ssd_GB => 1_000_000,
        hot_refs    => [],
    };
    if (($mesh->peer_count // 0) == 0 && !defined $self->{_explicit_local_for_test}) {
        $all[0] = $local_peer;
    } else {
        push @all, $local_peer, $mesh->peers;
    }
    my @scored = map {;
        my $s = $self->_score_one($attrs, $_);
        if (($_->{node_id} // '') eq ($local_id // '') && $s < INELIGIBLE) {
            $s -= LOCAL_PREFERENCE;
        }
        { score => $s, peer => $_ }
    } @all;
    @scored = sort { $a->{score} <=> $b->{score} } @scored;
    return () if !@scored || $scored[0]{score} >= INELIGIBLE;
    my $winner = $scored[0]{peer};
    my $is_local = ($winner->{node_id} // '') eq ($local_id // '');
    my @topn = map { $_->{peer} } grep { $_->{score} < INELIGIBLE } @scored;
    @topn = grep { ($_->{node_id} // '') ne ($local_id // '') } @topn if !$is_local;
    return ($is_local ? 'local' : $winner), $scored[0]{score}, @topn;
}

sub _score_one ($self, $attrs, $peer) {
    my $req_tier   = lc($attrs->{tier}  // 'shared');
    my $req_zone   = lc($attrs->{zone}  // 'global');
    my $sb = Amin::Sandbox->current_scope_attrs // {};
    my $mem_need   = int(($sb->{memory_max} // 0) / 1_048_576);
    my $ssd_need   = WORKING_SET_SSD_GB;
    my $pt = lc($peer->{tier} // 'shared');
    my $pz = lc($peer->{zone} // 'global');
    my $score = 0;
    $score += TIER_MISMATCH      if $req_tier ne 'shared' && $pt ne $req_tier;
    $score += ZONE_MISMATCH      if $req_zone ne 'global' && $pz ne $req_zone;
    $score += LOAD_SCALE * int($peer->{load_pct} // 0);
    my $hot = $peer->{hot_refs} // [];
    my $req_hot = $self->_hot_refs_from_attrs($attrs);
    if (@$req_hot && !$self->_any_overlap($req_hot, $hot)) {
        $score += HOT_REF_NO_OVERLAP;
    }
    if (($mem_need > 0 && int($peer->{free_mem_MB} // 0) < $mem_need)
        || int($peer->{free_ssd_GB} // 0) < $ssd_need) {
        $score += INELIGIBLE;
    }
    return $score;
}

sub _any_overlap ($self, $a, $b) {
    my %s = map { $_ => 1 } @$a;
    for my $x (@$b) { return 1 if $s{$x} }
    return 0;
}

sub _hot_refs_from_attrs ($self, $attrs) { [] }
sub _local_tier_from_profile ($self, $attrs) { $attrs->{tier} // 'shared' }

sub _redundancy_count ($self, $attrs, $eligible_count) {
    my $spawn_red = int($attrs->{redundancy} // 1);
    $spawn_red = 1 if $spawn_red < 1;
    my $z = Amin::Auth::ZCap->current_scope_attrs;
    my $zcap_max = DEFAULT_MAX_RED;
    if (ref $z eq 'HASH' && defined $z->{max_redundancy}) {
        $zcap_max = int($z->{max_redundancy});
        $zcap_max = 1 if $zcap_max < 1;
    }
    my $red = $spawn_red < $zcap_max ? $spawn_red : $zcap_max;
    $red = $eligible_count if $eligible_count < $red;
    $red = 1 if $red < 1;
    return $red;
}

sub _serialize_capture_to_canonical ($self, $capture) {
    my $xml = '';
    for my $ev (@{$capture->{events}}) {
        if ($ev->{type} eq 'start') {
            my $el = $ev->{el};
            my $ln = $el->{LocalName} // '';
            my $attrs = $el->{Attributes} // {};
            my $attr_str = '';
            for my $k (sort keys %$attrs) {
                my $a = $attrs->{$k};
                next unless ref $a eq 'HASH';
                my $an = $a->{Name} // $a->{LocalName} // $k;
                my $av = $a->{Value} // '';
                $av =~ s/&/&amp;/g; $av =~ s/</&lt;/g; $av =~ s/"/&quot;/g;
                $attr_str .= qq{ $an="$av"};
            }
            $xml .= length($ln) ? "<amin:$ln$attr_str>" : "<start/>";
        } elsif ($ev->{type} eq 'end') {
            my $ln = $ev->{el}{LocalName} // '';
            $xml .= length($ln) ? "</amin:$ln>" : "</end>";
        } else {
            my $d = $ev->{data} // '';
            $d =~ s/&/&amp;/g; $d =~ s/</&lt;/g;
            $xml .= $d;
        }
    }
    return $xml;
}

sub _build_context ($self) {
    my $sb  = Amin::Sandbox->current_scope_attrs       // {};
    my $net = Amin::Net::Fabric->current_scope_attrs   // {};
    my $z   = Amin::Auth::ZCap->current_scope_attrs    // {};
    return { sandbox => $sb, net => $net, zcap => $z };
}

sub _hex ($self, $bytes = '') {
    $bytes //= '';
    return join('', map sprintf('%02x', ord($_)), split //, $bytes);
}

sub _lazy_mesh ($self) {
    return $self->mesh if defined $self->mesh;
    require Amin::Discovery::Mesh;
    my $m = Amin::Discovery::Mesh->new;
    $self->mesh($m);
    return $m;
}

sub _lazy_transport ($self) {
    return $self->transport if defined $self->transport;
    require Amin::Mesh::Transport::InProcess;
    my $t = Amin::Mesh::Transport::InProcess->new;
    $self->transport($t);
    return $t;
}

package Amin::Schedule::Placement::_SAXReinject;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use Amin qw(NS);

sub new ($class, %o) {
    bless { fwd => $o{forward}, skip_outer => ($o{skip_outer}//0)?1:0, _depth => 0 }, $class;
}

sub start_element ($self, $el, @rest) {
    $self->{fwd} && $self->{fwd}->can('start_element') or return;
    my $emit = 1;
    if ($self->{skip_outer} && $self->{_depth} == 0) {
        $emit = 0;
    }
    $self->{_depth}++;
    if ($emit && ref $el eq 'HASH' && ($el->{NamespaceURI} // '') eq NS() && !length($el->{Prefix} // '')) {
        my $ln = $el->{LocalName} // '';
        $el->{Prefix} = 'amin';
        $el->{Name}   = length $ln ? "amin:$ln" : $el->{Name} // '';
        if (ref $el->{Attributes} eq 'HASH') {
            for my $k (keys %{$el->{Attributes}}) {
                my $a = $el->{Attributes}{$k};
                next unless ref $a eq 'HASH';
                my $ans = $a->{NamespaceURI} // '';
                if ($ans eq NS() && !length($a->{Prefix} // '')) {
                    $a->{Prefix} = 'amin';
                    my $aln = $a->{LocalName} // $a->{Name} // '';
                    $a->{Name} = length $aln ? "amin:$aln" : $a->{Name} // '';
                }
            }
        }
    }
    return $emit ? $self->{fwd}->start_element($el, @rest) : ();
}

sub end_element ($self, $el, @rest) {
    $self->{fwd} && $self->{fwd}->can('end_element') or return;
    $self->{_depth}--;
    my $emit = 1;
    if ($self->{skip_outer} && $self->{_depth} == 0) {
        $emit = 0;
    }
    if ($emit && ref $el eq 'HASH' && ($el->{NamespaceURI} // '') eq NS() && !length($el->{Prefix} // '')) {
        my $ln = $el->{LocalName} // '';
        $el->{Prefix} = 'amin';
        $el->{Name}   = length $ln ? "amin:$ln" : $el->{Name} // '';
    }
    return $emit ? $self->{fwd}->end_element($el, @rest) : ();
}

for my $m (qw(characters processing_command comment ignorable_whitespace)) {
    no strict 'refs';
    *$m = sub ($self, @args) {
        $self->{fwd} && $self->{fwd}->can($m) or return;
        if ($self->{skip_outer} && $self->{_depth} <= 1) {
            return;
        }
        return $self->{fwd}->$m(@args);
    };
}

1;
