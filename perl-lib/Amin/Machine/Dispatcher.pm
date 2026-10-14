package Amin::Machine::Dispatcher;
use v5.38; use warnings; use utf8;
use experimental 'signatures';
use parent 'XML::SAX::Base';

use Amin qw(NS);
use Class::Tiny qw(Handler Log Mode), { chain => undef };

our %FILTERS;
our %RUNTIME_ALLOWED;
my $CATALOG_FROZEN = 0;

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

sub _build_chain ($h, $l, $mode, $late_enable = {}, $allowed = undef, $spec_filters = undef) {
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
    if ($spec_filters && @$spec_filters) {
        for my $f (@$spec_filters) {
            my $p = $f->{meta}{position} // 'middle';
            push @{ $by_p{$p} }, $f;
        }
    }
    # Merge runtime-registered filters (%FILTERS) — covers --with-begin /
    # --with-middle / --with-end CLI registration and any register() calls
    # after INIT.  Only include those present in $allowed (or all when no
    # allowlist is in effect).
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
        my $filters = $by_p{$pos} // [];
        for my $f (reverse @$filters) {
            next if $pos eq 'late' && (
                ($f->{class} =~ /::Map::/ && !$late_enable->{map}) ||
                ($f->{class} =~ /::UI::/  && !$late_enable->{ui}) ||
                ($f->{class} =~ /::AI::Graph/ && !$late_enable->{ai}));
            (my $file = "$f->{class}.pm") =~ s{::}{/}g;
            eval { require $file } unless $f->{class}->can('new');
            next if $@;
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
