package Amin::Filter::Ledger;
# ═══════════════════════════════════════════════════════════════════════════
# Audited-event ledger filter.
#
# Passes the stream through untouched and records selected elements as typed
# entries in the Amin ledger (bitcache tlog).  Billing and settlement are just
# two rules; anything in the stack can add its own by emitting
#
#   <ledger:event kind="ai.action" actor="agent-7" subject="tool:fs.write"
#                 auth="<64-hex hash of the authorising zcap>" … />
#
# or by registering a rule for its own element.  Perl never encodes an entry:
# `bctool ledger-append` (Rust) assigns the per-actor seq/prev chain and does
# the canonical encoding, so Perl and Rust cannot disagree about a byte.
#
# FAIL CLOSED: if events were captured and cannot be committed, the stream
# dies.  An audited action that cannot be recorded must not appear to succeed.
# ═══════════════════════════════════════════════════════════════════════════
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';

use Encode ();
use IPC::Run qw(harness start finish);
use Amin qw(NS);
use Class::Tiny qw(slab_path bctool_path actor batch_max Handler Log Mode), {
    _pending => sub { [] },
    _receipts => sub { [] },
    rules    => sub { +{ %{ _default_rules() } } },
};

use constant LEDGER_NS => 'http://projectamin.org/ns/ledger/';
use constant UCC_NS_URI => 'http://projectamin.org/ns/ucc/';

# "{ns}local" → { kind, actor_attr, subject_attr }
sub _default_rules () {
    return {
        '{' . NS() . '}billing'        => { kind => 'billing',    actor_attr => 'tenant_id', subject_attr => 'pid' },
        '{' . _ucc_ns() . '}settlement' => { kind => 'settlement', subject_attr => 'kind' },
        '{' . LEDGER_NS . '}event'     => { generic => 1 },
    };
}

sub _ucc_ns () {
    require Amin::UCC;
    return Amin::UCC::UCC_NS();
}

sub add_rule ($self, $ns, $local, %spec) {
    die "rule needs a kind\n" unless length($spec{kind} // '');
    $self->rules->{"{$ns}$local"} = {%spec};
    return $self;
}

# Receipts of committed batches: { first, size, root } each.
sub receipts ($self) { return @{ $self->_receipts } }

sub _esc ($s) {
    $s = Encode::encode('UTF-8', $s // '');
    $s =~ s/([^A-Za-z0-9._:\/@+,-])/sprintf('%%%02X', ord $1)/ge;
    return $s;
}

sub _attr_map ($el) {
    my %m;
    for my $a (values %{ $el->{Attributes} // {} }) {
        next unless defined $a->{Value};
        $m{ $a->{LocalName} // $a->{Name} } = $a->{Value};
    }
    return \%m;
}

sub _default_actor ($self) {
    my $a = $self->actor;
    return $a if defined $a && length $a;
    my $t = eval { require Amin::Auth::ZCap; Amin::Auth::ZCap->current_scope_attrs->{tenant_id} };
    return $t if defined $t && length $t;
    return 'node';
}

sub _capture ($self, $rule, $el) {
    my $at = _attr_map($el);
    my (%skip, $kind, $actor, $subject, $auth);
    if ($rule->{generic}) {
        $kind    = delete $at->{kind};
        $actor   = delete $at->{actor};
        $subject = delete $at->{subject};
        $auth    = delete $at->{auth};
        return unless defined $kind && length $kind;       # not a well-formed event: ignore
    } else {
        $kind = $rule->{kind};
        $actor   = $at->{ $rule->{actor_attr} }   if $rule->{actor_attr};
        $subject = $at->{ $rule->{subject_attr} } if $rule->{subject_attr};
        $auth    = delete $at->{auth};
    }
    $actor = $self->_default_actor unless defined $actor && length $actor;
    $subject //= '';
    $auth = '-' unless defined $auth && $auth =~ /\A[0-9a-f]{64}\z/;
    my @kv = map { _esc($_) . '=' . _esc($at->{$_}) } sort keys %$at;
    push @{ $self->_pending }, join("\t", _esc($kind), _esc($actor), _esc($subject), $auth, @kv);
    $self->flush if @{ $self->_pending } >= ($self->batch_max || 64);
    return;
}

sub start_element ($self, $el) {
    my $rule = $self->rules->{ '{' . ($el->{NamespaceURI} // '') . '}' . ($el->{LocalName} // '') };
    $self->_capture($rule, $el) if $rule;
    return $self->SUPER::start_element($el);
}

sub end_document ($self, @a) {
    $self->flush;
    return $self->SUPER::end_document(@a);
}

sub _bctool ($self) {
    return $self->bctool_path if defined $self->bctool_path && length $self->bctool_path;
    require Amin::ToolPaths;
    my $t = Amin::ToolPaths::tool_bctool();
    return length $t ? $t : 'bctool';
}

sub _slab ($self) {
    my $p = $self->slab_path // $ENV{AMIN_LEDGER_SLAB};
    die "Amin::Filter::Ledger: no ledger slab configured (slab_path / AMIN_LEDGER_SLAB)\n"
        unless defined $p && length $p;
    return $p;
}

# Commit everything captured so far in one atomic bctool call.
sub flush ($self) {
    my $p = $self->_pending;
    return 0 unless @$p;
    my $in = join("\n", @$p) . "\n";
    my ($out, $err) = ('', '');
    my $h = harness [$self->_bctool, 'ledger-append', '--slab', $self->_slab],
        \$in, \$out, \$err;
    eval { start $h; finish $h; 1 };
    my $rc = $? >> 8;
    if ($@ || $rc != 0) {
        my $n = @$p;
        $self->Log && $self->Log->error("[ledger] commit of $n event(s) failed rc=$rc $err");
        die "Amin::Filter::Ledger: could not record $n audited event(s) (rc=$rc): $err\n";
    }
    my (%kv, $first);
    for my $l (split /\n/, $out) {
        my @f = split /\t/, $l;
        $first //= $f[1] if $f[0] eq 'entry';
        $kv{$f[0]} = $f[1] if $f[0] eq 'size' || $f[0] eq 'root';
    }
    push @{ $self->_receipts }, { first => $first, size => $kv{size}, root => $kv{root}, count => scalar @$p };
    @$p = ();
    return 1;
}

1;
