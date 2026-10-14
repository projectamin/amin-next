package Amin::Filter::Storage::Bitcache;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';

use IPC::Run  qw(harness start finish);
use Class::Tiny qw(slab_path bctool_path Handler Log Mode Name Element),
    { _capturing => 0, _cap_attrs => {}, _buf => '' };

my $BC_NS   = 'http://projectamin.org/ns/bc/';
my $AMIN_NS = 'http://projectamin.org/ns/2026/';

# Clark-notation attribute key helpers
sub _ck ($ns, $name) { "{$ns}$name" }
sub _bc_key ($name)  { _ck($BC_NS,   $name) }   # "{http://…bc/}hash"
sub _amin_key ($name){ _ck($AMIN_NS, $name) }   # "{http://…2026/}channel"
sub _unamesp_key ($name) { "{}" . $name }        # "{}id"

# ── Match: element LocalName eq 'object' with BC namespace ────────────────
sub _is_bc_object ($self, $el) {
    return 0 unless $el && ref($el) eq 'HASH';
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    return $ns eq $BC_NS && $ln eq 'object';
}

# ── Find an attribute value by local name across namespace URIs ─────────
# Used when either {}localname or {$NS}localname might be the key.
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

# ── Start capture on <bc:object>, otherwise forward ──────────────────────
sub start_element ($self, $el) {
    if ($self->_is_bc_object($el)) {
        $self->{_capturing} = 1;
        # Preserve user-set attrs so we can merge hash/size results into them
        $self->{_cap_attrs} = { %{ $el->{Attributes} // {} } };
        $self->{_buf}       = '';
        return;   # do NOT forward — we'll re-emit the compact <bc:object> at end
    }
    if ($self->{_capturing}) {
        # Nested content inside <bc:object> is captured via characters() only;
        # start_element/end_element of sub-tags would mean malformed input.
        # Just ignore them (no SUPER forward) — keeps SAX stream single-stream.
        return;
    }
    return $self->SUPER::start_element($el);
}

sub characters ($self, $d) {
    if ($self->{_capturing}) {
        $self->{_buf} .= $d->{Data} // '';
        return;
    }
    return $self->SUPER::characters($d);
}

# ── On </bc:object>: IPC to bctool → re-emit compact <bc:object hash= size=>─
sub end_element ($self, $el) {
    if ($self->{_capturing} && $self->_is_bc_object($el)) {
        $self->{_capturing} = 0;
        my $data = $self->{_buf};
        $self->{_buf} = '';
        my $merged_attrs = delete $self->{_cap_attrs};
        my $h = $self->Handler;

        my $hash_v = _find_attr_val($merged_attrs, 'hash', $BC_NS);
        my $has_hash = defined $hash_v;
        my $has_data = length($data) > 0;

        if ($has_data && !$has_hash) {
            # ── STORE path: raw data → bctool put → get hash+size ────────
            my ($hash, $size) = $self->_bctool_put(\$data);
            if (defined $hash) {
                _set_attr_in_ns($merged_attrs, $BC_NS, 'hash', $hash, 'bc');
                _set_attr_in_ns($merged_attrs, $BC_NS, 'size', $size, 'bc');
                $h && $self->_emit_object($h, $merged_attrs);
            } else {
                $self->Log && $self->Log->error(
                    "[bc/object] bctool put failed on payload len " . length($data));
            }
        } elsif ($has_hash && !$has_data) {
            # ── RETRIEVE path: hash → bctool get → re-emit object + stream─
            my $raw = $self->_bctool_get($hash_v);
            # Forward the <bc:object> as-is (keeps ref semantics upstream)
            $h && $self->_emit_object($h, $merged_attrs);
            if (defined $raw && length($$raw) && $h) {
                my $stream_attrs = {};
                _set_attr_in_ns($stream_attrs, $AMIN_NS, 'channel', 'bc-object', 'amin');
                $h->start_element({
                    NamespaceURI => $AMIN_NS,
                    LocalName    => 'stream',
                    Name         => 'amin:stream',
                    Prefix       => 'amin',
                    Attributes   => $stream_attrs,
                });
                $h->characters({ Data => $$raw });
                $h->end_element({
                    NamespaceURI => $AMIN_NS,
                    LocalName    => 'stream',
                    Name         => 'amin:stream',
                    Prefix       => 'amin',
                });
            } elsif (!defined $raw) {
                $self->Log && $self->Log->error(
                    "[bc/object] bctool get failed for hash=" . $hash_v);
            }
        } else {
            # Passthrough: either both or neither — emit the object unchanged.
            $h && $self->_emit_object($h, $merged_attrs);
            if ($has_data && $has_hash && length($data) && $h) {
                my $stream_attrs = {};
                _set_attr_in_ns($stream_attrs, $AMIN_NS, 'channel', 'bc-object', 'amin');
                $h->start_element({
                    NamespaceURI => $AMIN_NS,
                    LocalName    => 'stream', Name => 'amin:stream',
                    Prefix       => 'amin',
                    Attributes   => $stream_attrs,
                });
                $h->characters({ Data => $data });
                $h->end_element({
                    NamespaceURI => $AMIN_NS,
                    LocalName    => 'stream', Name => 'amin:stream',
                    Prefix       => 'amin',
                });
            }
        }
        return;
    }
    if ($self->{_capturing}) { return }   # swallow nested closes
    return $self->SUPER::end_element($el);
}

# ── Helpers ───────────────────────────────────────────────────────────────

sub _emit_object ($self, $h, $attrs) {
    $h->start_element({
        NamespaceURI => $BC_NS, LocalName => 'object',
        Name         => 'bc:object', Prefix => 'bc',
        Attributes   => $attrs });
    $h->end_element({
        NamespaceURI => $BC_NS, LocalName => 'object',
        Name         => 'bc:object', Prefix => 'bc' });
}

sub _bctool ($self) {
    require Amin::ToolPaths;
    my $default = Amin::ToolPaths::tool_bctool();
    return $self->bctool_path if defined $self->bctool_path;
    return length $default ? $default : 'bctool';
}

sub _slab ($self) {
    state $default = do {
        require File::Temp;
        File::Temp::tempdir(CLEANUP => 1) . '/default.slab';
    };
    my $p = $self->slab_path;
    return (defined $p && length $p) ? $p : $default;
}

# Returns ($hash_hex64, $size) or undef on failure.
sub _bctool_put ($self, $dataref) {
    my $bctool = $self->_bctool;
    my $slab   = $self->_slab;
    unless (-x $bctool || `command -v $bctool 2>/dev/null`) {
        $self->Log && $self->Log->error("[bc] bctool binary not found at $bctool");
        return;
    }
    my ($out, $err) = ('', '');
    my ($in, $out_filter, $err_filter) = ($$dataref, _simple_accum(\$out), _simple_accum(\$err));
    my $h = harness [$bctool, 'put', '--slab', $slab],
        \$in, $out_filter, $err_filter, debug => 0;
    eval { start $h; finish $h };
    my $rc = $? >> 8;
    if ($@ || $rc != 0) {
        $self->Log && $self->Log->error(
            "[bc/put] bctool rc=$rc" . (length($err) ? " stderr=$err" : ""));
        return;
    }
    my (%kv, $line);
    for my $ln (split /\n/, $out) {
        ($line = $ln) =~ s/\r?\n?$//;
        my ($k, $v) = split /\t/, $line, 2;
        $kv{$k} = $v if defined $v;
    }
    return unless exists $kv{hash} && length($kv{hash}) == 64;
    return ($kv{hash}, $kv{size} // length($$dataref));
}

# Returns scalar-ref to raw bytes or undef on failure.
sub _bctool_get ($self, $hash) {
    return unless defined $hash && length($hash) == 64;
    my $bctool = $self->_bctool;
    my $slab   = $self->_slab;
    my ($in, $out, $err) = ('', '', '');
    my $out_filter = _simple_accum(\$out);
    my $err_filter = _simple_accum(\$err);
    my $h = harness [$bctool, 'get', '--slab', $slab, '--hash', $hash],
        \$in, $out_filter, $err_filter, debug => 0;
    eval { start $h; finish $h };
    my $rc = $? >> 8;
    if ($@ || $rc != 0) {
        $self->Log && $self->Log->error(
            "[bc/get] bctool rc=$rc hash=$hash" .
            (length($err) ? " stderr=$err" : ""));
        return;
    }
    return \$out;
}

sub _simple_accum ($sv) {
    sub ($data, @) {
        if (defined $data) { $$sv .= $data }
        return ();
    }
}

1;
