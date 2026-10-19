package Amin::Handler::BSAX;
use v5.38; use warnings; use utf8;
use parent 'XML::SAX::Base';

use Amin qw(NS);
use Amin::Handler::Writer;  # for indentation-equivalent stack mirror (decoder side)
use Class::Tiny qw(fh autoflush), {
    buf     => '',
    stack   => sub { [] },   # CODE default: non-CODE refs are one shared ref per class
    last_ns => 0+0,
    wrote_magic => 0,
};

# 4-bit NS_IDs MUST stay 1:1 with Rust bsax/src/lib.rs NS_ID enum.
use constant {
    NS_NONE    => 0,
    NS_AMIN    => 1,
    NS_UI      => 2,
    NS_MAP     => 3,
    NS_BITCACHE=> 4,   # http://projectamin.org/ns/bc/  (legacy Bitcache namespace URI)
    NS_ESCAPE  => 15,
};

my %NS2ID = (
    'http://projectamin.org/ns/2026/'    => NS_AMIN,
    'http://projectamin.org/ns/ui/1'     => NS_UI,
    'http://projectamin.org/ns/map/1'    => NS_MAP,
    'http://projectamin.org/ns/bc/'      => NS_BITCACHE,
    ''                                   => NS_NONE,
);

# NAME_ID closed-world vocabulary — 1:1 with Rust bsax/src/vocab.rs BY_ID.
#
# ── NOTE on BEGIN ordering ─────────────────────────────────────────────────
# In Perl, `use constant EXPR` has IMPLICIT BEGIN-time evaluation of EXPR.
# If we naively write:
#     my @VOCAB = (...);
#     use constant ESCAPE => scalar @VOCAB;
#     my %ID; @ID{@VOCAB} = (0..$#VOCAB);
# The `use constant` RHS `scalar @VOCAB` runs at BEGIN BEFORE the list
# assignment has happened (runs only at FILE runtime after BEGINs finish) →
# ESCAPE would be 0, and %ID stays empty!  So: DECLARE the lexicals at file
# scope, but INITIALIZE them (and the constant) inside a single explicit
# BEGIN block so order is deterministic.
my @VOCAB_DECL;  # unused after BEGIN; declared for scope only
our %ID;         # runtime-accessible name→id map; populated in BEGIN below
BEGIN {
    my @VOCAB = (
        # amin core  (element + attribute LocalNames used by Amin::Command::* and
        #             the 5-position SAX chain inner filters)
        qw(profile result command stream status cond argv
           id version kind rc pid duration exit_kind name target
           channel dir mode level value type size),
        # map:*      (Amin::Filter::Map::Topology element + attr LocalNames)
        qw(region server link node a b cost phase flavor
           latency_ms bw_gbps tier zone value),
        # ui:*       (Amin::Filter::UI::SwiftUIView known-views + late-sax attrs)
        qw(app scene list row column hstack vstack stack grid section
           card progress alert sheet toolbar searchable item label
           text badge sparkline button navigate image asyncimage
           title spacing points for-each bind url),
        # bc:*       (projectamin/bitcache 2014 namespace LocalNames —
        #             object envelope, signer envelope, mesh topology, slab lifecycle)
        qw(object hash date signer networkmap server ip port search ref
           refcount stripe parity redundancy slab snap gc pull push),
        # ainit:*    (stage vocabulary for init-profile.xml PID 1 handoff)
        qw(stage order node_id refused init_profile_ref slab_dev),
        # exec+net   (Sandbox + Net::Fabric + expanded Command surface inner names)
        qw(exec spawn signal sandbox cpu_max memory_high landlock_ro seccomp
           vpc subnet lb vip backends netpolicy),
    );
    # ESCAPE constant via direct symbol-table import so subsequent runtime
    # code (e.g. start_element L122) can say `ESCAPE` bareword.
    require constant;
    constant->import(ESCAPE => scalar @VOCAB);  # 1 LEB byte still (<128)
    # Populate package %ID (declared `our` above) for runtime lookup.
    %ID = ();
    @ID{@VOCAB} = (0 .. $#VOCAB);
}

sub output ($s) { $s->buf }

sub _push ($self, $data) {
    $self->buf($self->buf . $data);
    if ($self->fh && ($self->autoflush // 1)) {
        print { $self->fh } $data;
        $self->fh->can('flush') && $self->fh->flush;
    }
    return;
}

# ── LEB128 u32 (same encoding as Wire Format / Rust bsax encode::leb_u32)
sub _leb ($n) {
    use integer;
    my $out = '';
    while (1) {
        my $b = $n & 0x7F;
        $n >>= 7;
        if ($n == 0) { $out .= chr $b; last }
        $out .= chr ($b | 0x80);
    }
    $out;
}

sub start_document ($self, @) {
    $self->_push("AMINBSA1") unless $self->wrote_magic; # 8 bytes, matched with Rust bsax::MAGIC
    $self->wrote_magic(1);
    $self->_push("\x00");  # Tag::StartDoc 0x00
}

sub end_document ($self, @) {
    $self->_push("\x20");  # Tag::EndDoc 0x20
}

sub start_element ($self, $el) {
    my ($ln, $ns) = @{$el}{qw(LocalName NamespaceURI)};
    my $ns_id = $NS2ID{$ns // ''} // NS_ESCAPE;

    my $name_id = exists $ID{$ln} ? $ID{$ln} : undef;
    my @attrs_raw = values $el->{Attributes}->%*;
    my @attrs;
    for my $a (@attrs_raw) {
        # xmlns:* namespace declarations are carried via 4-bit NS_ID inline;
        # encoding them again as attributes is pure waste on the wire.
        next if ($a->{Prefix} // '') eq 'xmlns';
        my $an = $a->{LocalName} // $a->{Name} // next;
        next unless length $an;
        my $av = $a->{Value} // '';
        next unless length $av || defined $a->{Value};
        my $aid = exists $ID{$an} ? $ID{$an} : undef;
        push @attrs, [$aid, $an, $av];
    }
    my $count = scalar @attrs;

    # Tag byte: StartEl 0x40 | NS_INLINE(1<<4)=0x10 always (stateless decoder)
    # | low4 count or 15
    my $count_field = $count <= 14 ? $count : 15;
    my $tag = chr (0x40 | 0x10 | $count_field);
    $self->_push($tag);
    $self->_push(chr(($ns_id & 0x0F) << 4));
    if ($ns_id == NS_ESCAPE) {
        # NS_ID=15 means the NamespaceURI was not in the Amin/MAP/UI/BITCACHE
        # closed-world set; carry it as length-prefixed UTF-8 on the wire so
        # Corp custom namespaces (DI-2 extensibility) survive BSAX roundtrip
        # without Amin fork.
        $self->_push(_leb(length($ns // '')) . ($ns // ''));
    }
    $self->_push(_leb($name_id // ESCAPE));
    if (!defined $name_id) {
        $self->_push(_leb(length($ln)) . $ln);
    }
    if ($count > 14) { $self->_push(_leb($count)) }
    for my $kv (@attrs) {
        my ($aid, $an, $av) = @$kv;
        $self->_push(_leb($aid // ESCAPE));
        if (!defined $aid) { $self->_push(_leb(length($an)) . $an) }
        $self->_push(_leb(length($av)) . $av);
    }
    push @{$self->stack}, [$ln, $ns_id];
}

sub end_element ($self, @) {
    pop @{$self->stack};
    $self->_push("\x60");  # Tag::EndEl 0x60 — 1 byte only; name on stack
}

sub characters ($self, $d) {
    my $t = $d->{Data} // '';
    return unless length $t;
    if (length($t) < 32) {
        $self->_push(chr(0x80 | length($t)));  # Tag::Chars short form
        $self->_push($t);
    } else {
        $self->_push("\x9F");  # Tag::Chars + flags=31 => len follows
        $self->_push(_leb(length($t)));
        $self->_push($t);
    }
}

1;
