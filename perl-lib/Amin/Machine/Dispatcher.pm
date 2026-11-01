package Amin::Machine::Dispatcher;
use v5.38; use warnings; use utf8;
use experimental 'signatures';
use parent 'XML::SAX::Base';

use Amin qw(NS);
use Class::Tiny qw(Handler Log Mode), { chain => undef };

our %FILTERS;
our %RUNTIME_ALLOWED;
my $CATALOG_FROZEN = 0;

# Escape hatch: when true, every machine-spec'd filter is stacked statically
# exactly as before lazy gating existed.  Operational off-switch only —
# t/48 uses it to compare gated output against the legacy full chain.
our $DISABLE_LAZY_CHAIN = 0;

INIT { $CATALOG_FROZEN = 1 }

sub register ($pkg, $class, %meta) {
    my $pos = delete($meta{position}) // 'middle';
    push $FILTERS{$pos}->@*, { class => $class, meta => \%meta };
    $RUNTIME_ALLOWED{$class} = 1 if $CATALOG_FROZEN;
}


sub new ($class, %o) {
    my $self = bless { %o }, $class;
    my $spec = _resolve_spec(\%o);
    $self->{machine_spec} = $spec;
    $self->{Handler} //= _instantiate_handler($spec->{handler});
    $self->{Log}     //= _instantiate_log($spec->{log});
    $self->{chain} = _build_chain($self->Handler, $self->Log, $self->Mode // 'render',
        $self->{late_filters_enable} // { map => 1, ui => 1, ai => 1 },
        $spec->{allowed}, $spec->{filters});
    return $self;
}

sub _resolve_spec ($o) {
    my $raw = delete $o->{machine_spec};
    my $spec;
    if ($raw && ref $raw eq 'HASH') {
        if (exists $raw->{allowed}) {
            $spec = $raw;
        } else {
            $spec = { allowed => $raw };
        }
    } else {
        require Amin::Machine::MachineSpec;
        my $ms = Amin::Machine::MachineSpec->new(
            (exists $o->{machine_spec_xml}  ? (xml  => delete $o->{machine_spec_xml})  : ()),
            (exists $o->{machine_spec_path} ? (path => delete $o->{machine_spec_path}) : ()),
            (exists $o->{bc_uri}            ? (bc_uri       => delete $o->{bc_uri})            : ()),
            (exists $o->{bc_hash}           ? (bc_hash      => delete $o->{bc_hash})           : ()),
            (exists $o->{slab_path}         ? (slab_path    => delete $o->{slab_path})         : ()),
            (exists $o->{bctool_path}       ? (bctool_path  => delete $o->{bctool_path})       : ()),
            (exists $o->{signer_name}       ? (signer_name  => delete $o->{signer_name})       : ()),
            (exists $o->{signer_ts}         ? (signer_ts    => delete $o->{signer_ts})         : ()),
            (exists $o->{signer_vk}         ? (signer_vk    => delete $o->{signer_vk})         : ()),
            (exists $o->{signer_sig}        ? (signer_sig   => delete $o->{signer_sig})        : ()),
            (exists $o->{trust_anchor_dir}  ? (trust_anchor_dir => delete $o->{trust_anchor_dir}) : ()),
        );
        $spec = $ms->spec;
    }
    if (%RUNTIME_ALLOWED) {
        $spec->{allowed} = { $spec->{allowed}->%*, %RUNTIME_ALLOWED };
    }
    return $spec;
}

sub _instantiate_handler ($h) {
    return undef unless $h && ref $h eq 'HASH' && $h->{class};
    (my $file = "$h->{class}.pm") =~ s{::}{/}g;
    eval { require $file };
    return undef if $@;
    return $h->{class}->new($h->{attrs} ? $h->{attrs}->%* : ());
}

sub _instantiate_log ($l) {
    return undef unless $l && ref $l eq 'HASH' && $l->{class};
    (my $file = "$l->{class}.pm") =~ s{::}{/}g;
    eval { require $file };
    return undef if $@;
    return $l->{class}->new($l->{attrs} ? $l->{attrs}->%* : ());
}

sub _generator_class ($g) {
    return undef unless $g && ref $g eq 'HASH' && $g->{class};
    (my $file = "$g->{class}.pm") =~ s{::}{/}g;
    eval { require $file };
    return $@ ? undef : $g->{class};
}

# ── Lazy chain composition ─────────────────────────────────────────────
# The machine spec declares every filter the machine *supports*, with its
# position and element/name binding.  _build_chain composes the base graph
# from what must always be present:
#   • all PERMANENT-position filters            (trust boundary — TR-2.1),
#   • element-agnostic spec filters             (no event can gate them —
#                                                 zcap/net/billing/…),
#   • all runtime-registered (--with-*) filters (explicit user intent).
# Every remaining spec filter (element-scoped, non-permanent) becomes a
# candidate of its position; that position gets a _LazyGate which splices
# the candidate in as its element's start_element flows through, and un-splices
# it after the matching end_element.  No pre-scan, no DOM: the profile itself
# is the decision signal — the same mechanism serves Dispatcher->run and
# event-fed Dispatchers alike.
package Amin::Machine::Dispatcher::_LazyGate;
use v5.38; use warnings; use utf8;
use experimental 'signatures';

use Class::Tiny qw(Handler Log Mode candidates), {
    active => sub { [] },      # [{ node, d, class, doc }] — currently spliced instances
    depth  => sub { 0 },       # shadow element depth for pop bookkeeping
};

# Remember the un-spliced child so window="document" cleanup can restore it.
sub BUILD ($self, $args) { $self->{_base_child} = $self->{Handler} }

# The gate deliberately does NOT inherit XML::SAX::Base.  Dynamic mid-stream
# handler swaps (the splice) go through XML::SAX::Base's event-dispatch caches,
# which are resolved from the construction-time handler — after a splice those
# caches route events along stale paths (observed: starts bypass the newly
# spliced filter, ends reach it).  Instead the gate does what the Dispatcher
# itself does: direct, per-event dispatch to the CURRENT child held in
# {_child}.  Every forwarded event set below matches the Dispatcher's `*$m`
# forwarder list exactly; anything else falls back to AUTOLOAD.

# (element, ns, name-attr) extraction for one SAX event; name picked from any
# `name` attribute form ({}name or {http://…}name).
sub _event_key ($el) {
    my $ln = $el->{LocalName} // $el->{Name} // '';
    my $ns = $el->{NamespaceURI} // '';
    my ($name, $attrs) = (undef, $el->{Attributes} // {});
    for my $k (keys %$attrs) {
        (my $base = $k) =~ s/^\{[^}]*\}//;
        if ($base eq 'name') { $name = $attrs->{$k}{Value}; last }
    }
    return ($ln, $ns, $name);
}

sub start_element ($self, $el) {
    my ($ln, $ns, $name) = _event_key($el);
    $self->depth($self->depth + 1);
    if (length $ln) {
        CAND: for my $c ($self->candidates->@*) {
            next unless ($c->{meta}{element} // '') eq $ln;
            my $cns = $c->{meta}{namespace};
            next if defined $cns && length $cns && $cns ne $ns;
            # Verb matching mirrors how the STATIC chain matches: command
            # classes carry their own verb as a class-level `sub name`
            # (MachineSpec deliberately never copies the spec's name=
            # attribute into meta — the class is the source of truth).
            #   sub name → non-empty verb : event name attr must equal it
            #   sub name → ''  (Exec/Spawn/Signal): matches ANY name attr
            #   no sub name (Sandbox/UCC/AI/Bitcache/…)  : element-only
            my $verb;
            {
                local $@;
                if (defined(&{"$c->{class}::name"})) {
                    $verb = eval { $c->{class}->name };
                }
            }
            if (defined $verb && length $verb) {
                next unless defined $name && length $name && $name eq $verb;
            }
            my $cn = $c->{meta}{name};   # ≈ always undef (see comment above)
            # One live instance per candidate: a nested same-key element is
            # still inside the active instance's capture scope (this mirrors
            # the static chain, where exactly one instance exists).
            next if grep { $_->{class} eq $c->{class} } $self->active->@*;
            # window="document" candidates (spec meta) claim the whole
            # document once triggered: they stay spliced until end_document
            # — filters whose state machine spans beyond their trigger
            # element (ProfileValidator validates across stages +
            # end_document).
            my $doc = (($c->{meta}{window} // '') eq 'document') ? 1 : 0;
            (my $file = "$c->{class}.pm") =~ s{::}{/}g;
            unless ($c->{class}->can('new')) {
                my $ok = eval { require $file; 1 };
                next unless $ok;
            }
            my $rest = $self->{Handler} // return;
            my $new = $c->{class}->new(
                Handler => $rest, Log => $self->Log, Mode => $self->Mode,
                Name    => $cn,   Element => $c->{meta}{element});
            $new->can('name')    && $new->name($cn);
            $new->can('element') && $new->element($c->{meta}{element});
            $self->{Handler} = $new;          # splice BEFORE forwarding
            push $self->active->@*, { node => $new, d => $self->depth, class => $c->{class}, doc => $doc };
            last CAND;
        }
    }
    my $c = $self->{Handler} or return;         # direct dispatch — no XML::SAX::Base
    return $c->start_element($el);
}

sub end_element ($self, $el) {
    my $c = $self->{Handler};                    # direct dispatch to the CURRENT child
    my $ret = $c ? $c->end_element($el) : undef; # instance sees its own close first
    my $ln = $el->{LocalName} // $el->{Name} // '';
    return $ret unless length $ln;
    my $d = $self->depth - 1;
    $self->depth($d);
    my $st = $self->active;
    if (@$st && !$st->[-1]{doc} && $st->[-1]{d} == $d + 1) {
        my $top = pop @$st;
        $self->{Handler} = $top->{node}->Handler;   # un-splice
    }
    return $ret;
}

# Document-window cleanup: document-scope candidates un-splice at the end of
# the document; the gate returns to its base child thereafter.
sub end_document ($self, @a) {
    my $c = $self->{Handler};
    my $ret = $c ? $c->end_document(@a) : undef;
    @{$self->active} = ();
    $self->{Handler} = $self->{_base_child};
    return $ret;
}

# Direct forwarders for the remaining Dispatcher event set (no XML::SAX::Base
# machinery — see the class-header comment for why caching breaks splices).
sub start_document       ($self, @a) { my $c = $self->{Handler}; return $c ? $c->start_document(@a) : undef }
sub characters           ($self, $d) { my $c = $self->{Handler}; return $c ? $c->characters($d)     : undef }
sub processing_command   ($self, @a) { my $c = $self->{Handler}; return $c ? $c->processing_command(@a) : undef }
sub comment              ($self, @a) { my $c = $self->{Handler}; return $c ? $c->comment(@a)            : undef }
sub ignorable_whitespace ($self, @a) { my $c = $self->{Handler}; return $c ? $c->ignorable_whitespace(@a) : undef }

# Exotic driver calls (set_document_locator, …) follow the current child too.
sub AUTOLOAD {
    my $self = shift;
    (my $m = our $AUTOLOAD) =~ s/.*:://;
    return if $m eq 'DESTROY';
    my $c = $self->{Handler} // return undef;
    return $c->$m(@_) if $c->can($m);
    return undef;
}

package Amin::Machine::Dispatcher;   # resume outer package after _LazyGate
use experimental 'signatures';

for my $m (qw(start_document end_document
              start_element end_element characters
              processing_command comment ignorable_whitespace)) {
    no strict 'refs';
    *$m = sub ($self, @args) { $self->{chain}->$m(@args) };
}

sub run ($pkg_or_self, %o) {
    my $mode      = $o{mode}      // 'render';
    my $late_en   = $o{late_filters_enable} // { map => 1, ui => 1, ai => 1 };
    my $source    = $o{source_xml}  // die "Dispatcher->run needs source_xml";
    my $spec      = _resolve_spec(\%o);
    my $Handler   = $o{Handler} // _instantiate_handler($spec->{handler})
                    // do { require Amin::Handler::Writer; Amin::Handler::Writer->new(indent => 2) };
    my $Log       = $o{Log}     // _instantiate_log($spec->{log})
                    // do { require Amin::Log::Standard; Amin::Log::Standard->new(stderr => 0) };
    my $gen_class = _generator_class($spec->{generator}) // 'XML::LibXML::SAX';

    my $self;
    if (ref($pkg_or_self)) { $self = $pkg_or_self; $self->{Mode} = $mode;
        $self->{Handler} //= $Handler; $self->{Log} //= $Log;
        $self->{machine_spec} = $spec;
        $self->{chain} = _build_chain($self->Handler, $self->Log, $mode, $late_en,
            $spec->{allowed}, $spec->{filters});
    } else {
        $self = bless({ Mode => $mode, Handler => $Handler, Log => $Log, machine_spec => $spec }, $pkg_or_self);
        $self->{chain} = _build_chain($self->Handler, $self->Log, $mode, $late_en,
            $spec->{allowed}, $spec->{filters});
    }
    (my $gen_file = "$gen_class.pm") =~ s{::}{/}g;
    eval { require $gen_file };
    $gen_class->new(Handler => $self)->parse_string($source);
    $self->Handler->can('output') && return $self->Handler->output;
    return;
}

sub _build_chain ($h, $l, $mode, $late_enable = {}, $allowed = undef, $spec_filters = undef, $realized = undef) {
    my $head = $h;
    # Filters are never auto-loaded; they are always machine-spec declared.
    # When _build_chain is called directly without a spec (e.g. from tests),
    # fall back to the bundled default machine_spec.xml so the chain still
    # composes the full filter set from a declared source.
    if (!$spec_filters || !@$spec_filters) {
        require Amin::Machine::MachineSpec;
        my $default = Amin::Machine::MachineSpec->new->spec;
        $spec_filters = $default->{filters};
        $allowed //= $default->{allowed};
    }
    my %by_p;
    my %cands_by_p;
    if ($spec_filters && @$spec_filters) {
        for my $f (@$spec_filters) {
            my $p = $f->{meta}{position} // 'middle';
            my $el = $f->{meta}{element};
            # Partition (see lazy-composition block above): element-scoped,
            # non-permanent spec filters become gate candidates; permanent and
            # element-agnostic filters are always in the graph statically.
            # Candidate classes load here too — code and tests rely on statics
            # of loaded filter classes (registry / current_scope_attrs — see
            # Placement.pm and Spawn), and a gated instance needs its class.
            if (!$DISABLE_LAZY_CHAIN && defined $el && length $el && $p ne 'permanent') {
                (my $file = "$f->{class}.pm") =~ s{::}{/}g;
                # Capture per-require: a stale $@ here would poison the
                # instantiate loop's own guard below (next-if-$@).
                my $ok = eval { require $file; 1 };
                next unless $ok;    # unloadable class was never in the static chain either
                push @{ $cands_by_p{$p} }, $f;
            }
            else {
                push @{ $by_p{$p} }, $f;
            }
        }
    }
    # Merge runtime-registered filters (%FILTERS) — covers --with-begin /
    # --with-middle / --with-end CLI registration and any register() calls
    # after INIT.  Only include those present in $allowed (or all when no
    # allowlist is in effect).  Runtime entries are tagged so the chain
    # loop below never applies profile-scoped selection to them:
    # --with-* registration is explicit user intent, always honored.
    for my $pos (qw(end late middle begin permanent)) {
        my $filters = $FILTERS{$pos} // [];
        for my $f (@$filters) {
            next if defined $allowed && !$allowed->{$f->{class}};
            $f->{meta}{position} //= $pos;
            my $p = $f->{meta}{position};
            push @{ $by_p{$p} }, $f;
        }
    }
    # Canonical order: end → late → middle → begin → permanent.
    # Within each position, reverse so the first-listed/registered filter is
    # the outermost of that position.  permanent ends up outermost overall
    # (trust boundary sees events first — TR-2.1).
    for my $pos (qw(end late middle begin permanent)) {
        # Position gate — created BEFORE the region's static members, so it
        # sits at the region's INNERMOST boundary (below them, above the next
        # deeper position).  This keeps canonical ordering and the trust
        # boundary intact: the outermost static member of each region (e.g.
        # Auth::ZCap for begin) remains the region's outermost node, and
        # begin-region candidates splice in BELOW the auth/HW filters rather
        # than ahead of them (TR-2.1).  Start/end events crossing the gate
        # splice in / un-splice the region's element-scoped candidates.
        if (!$DISABLE_LAZY_CHAIN && (my $cands = $cands_by_p{$pos})) {
            $head = Amin::Machine::Dispatcher::_LazyGate->new(
                Handler    => $head,
                Log        => $l,
                Mode       => $mode,
                candidates => $cands,
            );
        }
        my $filters = $by_p{$pos} // [];
        for my $f (reverse @$filters) {
            next if $pos eq 'late' && (
                ($f->{class} =~ /::Map::/ && !$late_enable->{map}) ||
                ($f->{class} =~ /::UI::/  && !$late_enable->{ui}) ||
                ($f->{class} =~ /::AI::Graph/ && !$late_enable->{ai}));
            (my $file = "$f->{class}.pm") =~ s{::}{/}g;
            unless ($f->{class}->can('new')) {
                my $ok = eval { require $file; 1 };   # locally scoped: no stale $@ into the loop
                next unless $ok;
            }
            $head = $f->{class}->new(
                Handler => $head, Log => $l, Mode => $mode,
                Name    => $f->{meta}{name},
                Element => $f->{meta}{element});
            $head->can('name')    && $head->name($f->{meta}{name});
            $head->can('element') && $head->element($f->{meta}{element});
        }
    }
    return $head;
}

1;
