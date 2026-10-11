package Amin::Filter::Init::ProfileValidator;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';

use Class::Tiny qw(Handler Log Mode Name Element), {
    _is_init_profile   => 0,
    _in_stage_depth    => 0,
    _seen_order        => sub { +{} },
    _validated_ok      => 0,
    _failed            => 0,
};

use Amin qw(NS);
my $AMIN_NS = NS();

sub BUILD ($self, @) {
    $self->_is_init_profile;
    $self->_in_stage_depth;
    $self->_seen_order;
    $self->_validated_ok;
    $self->_failed;
}

my @REQUIRED_ORDERS = (1, 2, 3, 4, 5, 6);
my %REQUIRED_SET     = map { $_ => 1 } @REQUIRED_ORDERS;

my %DATA_PLANE_LOCALNAMES = map { $_ => 1 } qw(
    command spawn exec signal sandbox
    net lb netpolicy
    vol mount bitcache migrate
    secret autoscale
    rc
);

sub _ck ($ns, $name) { "{$ns}$name" }
sub _amin_key ($name) { _ck($AMIN_NS, $name) }

sub _find_attr_val ($attrs, $name, @preferred_ns) {
    return undef unless $attrs && ref($attrs) eq 'HASH';
    for my $ns (@preferred_ns, '') {
        my $k = length($ns) ? "{$ns}$name" : "{}" . $name;
        if (exists $attrs->{$k} && defined $attrs->{$k}{Value}
                && length $attrs->{$k}{Value}) {
            return $attrs->{$k}{Value};
        }
    }
    return undef;
}

sub _is_amin_stage ($self, $el) {
    return 0 unless $el && ref($el) eq 'HASH';
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    return $ns eq $AMIN_NS && $ln eq 'stage';
}

sub _is_data_plane ($self, $el) {
    return 0 unless $el && ref($el) eq 'HASH';
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    return $ns eq $AMIN_NS && exists $DATA_PLANE_LOCALNAMES{$ln};
}

sub _run_validation ($self) {
    return 1 if $self->{_validated_ok};
    return 0 if $self->{_failed};
    my $seen = $self->{_seen_order};
    my @missing = sort { $a <=> $b }
                  grep { !exists $seen->{$_} } keys %REQUIRED_SET;
    my @bogus   = sort { $a <=> $b }
                  grep { !exists $REQUIRED_SET{$_} } keys %$seen;
    if (@missing || @bogus) {
        $self->{_failed} = 1;
        my $msg;
        if (@missing) {
            $msg = "init-profile missing stages: order=" . join(',', @missing);
        } else {
            $msg = "init-profile invalid stage orders present: " . join(',', @bogus);
        }
        $self->Log && $self->Log->error("[init-profile] $msg");
        $self->_emit_malformed($msg);
        return 0;
    }
    $self->{_validated_ok} = 1;
    return 1;
}

sub _emit_malformed ($self, $detail = '') {
    my $h = $self->Handler or return;
    my $rc_attrs = {};
    _set_attr_in_ns($rc_attrs, $AMIN_NS, 'kind',      'machine',   'amin');
    _set_attr_in_ns($rc_attrs, $AMIN_NS, 'id',        'init-profile-validator', 'amin');
    $h->start_element({
        NamespaceURI => $AMIN_NS, LocalName => 'rc',
        Name         => 'amin:rc', Prefix    => 'amin',
        Attributes   => $rc_attrs,
    });
    my $result_attrs = {};
    _set_attr_in_ns($result_attrs, $AMIN_NS, 'kind', 'init_profile', 'amin');
    $h->start_element({
        NamespaceURI => $AMIN_NS, LocalName => 'result',
        Name         => 'amin:result', Prefix => 'amin',
        Attributes   => $result_attrs,
    });
    my $status_attrs = {};
    _set_attr_in_ns($status_attrs, $AMIN_NS, 'kind',      'error',   'amin');
    _set_attr_in_ns($status_attrs, $AMIN_NS, 'rc',        '2',       'amin');
    _set_attr_in_ns($status_attrs, $AMIN_NS, 'exit_kind', 'init_profile_malformed', 'amin');
    if (length $detail) {
        _set_attr_in_ns($status_attrs, $AMIN_NS, 'detail', $detail, 'amin');
    }
    $h->start_element({
        NamespaceURI => $AMIN_NS, LocalName => 'status',
        Name         => 'amin:status', Prefix => 'amin',
        Attributes   => $status_attrs,
    });
    $h->end_element({
        NamespaceURI => $AMIN_NS, LocalName => 'status',
        Name         => 'amin:status', Prefix => 'amin',
    });
    $h->end_element({
        NamespaceURI => $AMIN_NS, LocalName => 'result',
        Name         => 'amin:result', Prefix => 'amin',
    });
    $h->end_element({
        NamespaceURI => $AMIN_NS, LocalName => 'rc',
        Name         => 'amin:rc', Prefix    => 'amin',
    });
}

sub _set_attr_in_ns ($attrs, $ns, $name, $value, $prefix = '') {
    my $k = length($ns) ? "{$ns}$name" : "{}" . $name;
    my $full = length($prefix) ? "$prefix:$name" : $name;
    $attrs->{$k} = {
        Name         => $full,
        LocalName    => $name,
        Prefix       => $prefix,
        NamespaceURI => $ns,
        Value        => $value,
    };
    return;
}

sub start_element ($self, $el) {
    if ($self->_is_amin_stage($el)) {
        $self->{_is_init_profile} = 1;
        $self->{_in_stage_depth} = ($self->{_in_stage_depth} // 0) + 1;
        my $order = _find_attr_val($el->{Attributes}, 'order', $AMIN_NS);
        if (defined $order && length($order) && $order =~ /^\d+$/) {
            $self->{_seen_order}{$order + 0} = 1;
        }
        return $self->SUPER::start_element($el);
    }
    if (($self->{_in_stage_depth} // 0) > 0) {
        return $self->SUPER::start_element($el);
    }
    if (($self->{_is_init_profile} // 0) && !($self->{_validated_ok} // 0)
            && $self->_is_data_plane($el)) {
        my $ok = $self->_run_validation;
        if (!$ok) {
            return;
        }
    }
    if ($self->{_failed} // 0) {
        return;
    }
    return $self->SUPER::start_element($el);
}

sub end_element ($self, $el) {
    if ($self->_is_amin_stage($el)) {
        my $d = $self->{_in_stage_depth} // 0;
        $self->{_in_stage_depth} = $d > 0 ? $d - 1 : 0;
    }
    if ($self->{_failed} // 0) {
        return;
    }
    return $self->SUPER::end_element($el);
}

sub characters ($self, $d) {
    if ($self->{_failed} // 0) { return }
    return $self->SUPER::characters($d);
}

sub end_document ($self, @) {
    if (($self->{_is_init_profile} // 0) && !($self->{_validated_ok} // 0)
            && !($self->{_failed} // 0)) {
        $self->_run_validation;
    }
    if ($self->{_failed} // 0) { return }
    return $self->SUPER::end_document;
}

1;
