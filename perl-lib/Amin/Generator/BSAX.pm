package Amin::Generator::BSAX;
use v5.38; use warnings; use utf8;
use parent 'XML::SAX::Base';  # Generator, not Handler — ISA SAX so Handler chain works

use Amin qw(NS);
use Class::Tiny qw(Handler), {
    inbuf       => '',    # unconsumed bytes (compacted as events are emitted)
    magic_seen  => 0,
    last_ns     => 0+0,
    last_ns_uri => '',    # set ONLY if last_ns == NS_ESCAPE (custom Corp URI)
    stack       => sub { [] },
    vocab       => undef, # spec-declared band names (raw, document order)
};
# Mirrors of Amin::Handler::BSAX constants — MUST stay 1:1 with Handler::BSAX
# and rust/crates/bsax/src/vocab.rs BY_ID slice.
use constant {
    NS_NONE=>0, NS_AMIN=>1, NS_UI=>2, NS_MAP=>3, NS_BITCACHE=>4, NS_SEC=>5,
    NS_ESCAPE=>15
};
my %NSBYID = (
    NS_NONE, '',
    NS_AMIN, NS(),
    NS_UI,   'http://projectamin.org/ns/ui/1',
    NS_MAP,  'http://projectamin.org/ns/map/1',
    NS_BITCACHE, 'http://projectamin.org/ns/bc/',
    NS_SEC,  'http://projectamin.org/ns/sec/1',
);
# Platform document-generation elements — the grammar lives in NS_AMIN, so
# their attributes are amin:* even when the LocalName's NAME_ID sits in an
# earlier vocabulary region (id/name/type/size/title/min/max are shared).
my %AMIN_DOC_ELEM = map { $_ => 1 }
    qw(document style sheet column row cell freeze autofilter merge);
# See Handler::BSAX comment for BEGIN-ordering explanation: `use constant` runs
# its RHS at BEGIN so we must populate VOCAB first inside the same explicit BEGIN.
our @NAMEBYID_BY_POS;  # placeholder; real data is the hash below
our %NAMEBYID;         # id→name lookup, populated in BEGIN
our %CORENAME;         # name→1 core-name set, populated in BEGIN
BEGIN {
    my @VOCAB = (
        # amin core (Handler::BSAX 1:1 copy)
        qw(profile result command stream status cond argv
           id version kind rc pid duration exit_kind name target
           channel dir mode level value type size),
        # map:*
        qw(region server link node a b cost phase flavor
           latency_ms bw_gbps tier zone value),
        # ui:*  (33 kinds + late-sax attrs; grown in place — see Handler::BSAX)
        qw(app scene list row column hstack vstack stack grid section
           card progress alert sheet toolbar searchable item label
           text badge sparkline button navigate image asyncimage
           form field select option table tr cell style
           title spacing points for-each bind url
           action method min max placeholder selected header),
        # bc:*  (projectamin/bitcache 2014 ns: object/signer/networkmap/slab)
        qw(object hash date signer networkmap server ip port search ref
           refcount stripe parity redundancy slab snap gc pull push),
        # ainit stage (init-profile.xml PID 1 handoff)
        qw(stage order node_id refused init_profile_ref slab_dev),
        # exec+net sandbox/surface (Sandbox + Net::Fabric + expanded Command)
        qw(exec spawn signal sandbox cpu_max memory_high landlock_ro seccomp
           vpc subnet lb vip backends netpolicy),
        # sec:* post-quantum E2EE surface (Handler::BSAX 1:1 copy; appended last)
        qw(seal sealed ciphertext header
           ratchet prev_count msg_index
           session prekey pqprekey onetime bundle
           senderkey identity require),
        # document generation grammar in the core amin: namespace
        # (Handler::BSAX 1:1 copy; names already in the table are not repeated).
        qw(document merge freeze autofilter
           index width hidden height ht r range
           bold italic underline font color fill numfmt format
           align valign wrap tab-color
           author subject keywords description out root
           mime path sheets rows cells msg),
    );
    require constant;
    constant->import(ESCAPE => scalar @VOCAB);  # 172 ⇒ 2-byte LEB128 (≥128)
    %NAMEBYID = ();
    @NAMEBYID{0 .. $#VOCAB} = @VOCAB;
    %CORENAME = ();
    @CORENAME{@VOCAB} = (1) x @VOCAB;
}

# Spec-declared BSAX vocabulary band — the dynamic half of the NAME_ID space.
# Mirrors Amin::Handler::BSAX exactly: spec-declared LocalNames not in the Amin
# core table get NAME_IDs ESCAPE+1, ESCAPE+2, … in first-seen order (core wins,
# first-seen wins).  Both ends derive the identical map from the same signed
# spec, so no name is wired into Amin core.  An absent vocab ⇒ empty band ⇒ ids
# >= ESCAPE resolve to nothing and the escape path applies — i.e. a spec that
# declares nothing behaves exactly as before.
#
# Derived LAZILY (not in BUILD): XML::SAX::Base supplies this class's
# constructor, so Class::Tiny's BUILD hook is never invoked.  Cached on first
# name lookup.
sub _band ($self) {
    return $self->{_band} if exists $self->{_band};
    my (%seen, @band);
    for my $n (@{ $self->vocab // [] }) {
        next unless length $n;
        next if $CORENAME{$n};  # core wins — a core name never needs a band id
        next if $seen{$n}++;    # first-seen wins
        push @band, $n;
    }
    return $self->{_band} = \@band;
}

# ── Streaming entry points ─────────────────────────────────────────────────
# BSAX is a streamed protocol: a caller pushes transport chunks in with
# feed() and declares the end with finish().  Events are emitted the moment
# their last byte has arrived; a partial event is retained in `inbuf` and
# completed by the next feed(), so an event never straddles a chunk boundary
# incorrectly.  parse_bytes() is the one-shot convenience on top.

# reset() — drop all state so the instance can decode a fresh stream.
sub reset ($self) {
    $self->{inbuf}       = '';
    $self->{magic_seen}  = 0;
    $self->{last_ns}     = 0;
    $self->{last_ns_uri} = '';
    $self->{stack}       = [];
    return;
}

# feed($bytes) — append a chunk and emit every event it completes.
sub feed ($self, $bytes) {
    return unless defined $bytes && length $bytes;
    $self->{inbuf} .= $bytes;
    $self->_pump;
    return;
}

# finish() — declare end of stream.  A partial event or a missing magic is a
# hard error: a silently truncated BSAX stream is worse than a loud failure.
sub finish ($self) {
    $self->_pump;
    die "BSAX magic missing" unless $self->{magic_seen};
    die "BSAX truncated stream: " . length($self->{inbuf}) . " trailing bytes"
        if length $self->{inbuf};
    return;
}

# parse_bytes($bytes) — one-shot: XML if the first byte is '<', else a whole
# BSAX document.  Retained so existing callers (Amin->parse, tests) are
# unchanged, but implemented entirely on top of the streaming core.
sub parse_bytes ($self, $bytes) {
    if (defined $bytes && !ref($bytes) && substr($bytes,0,1) eq '<') {
        return $self->_parse_xml_fallback($bytes);
    }
    $self->reset;
    $self->feed($bytes);
    $self->finish;
    return;
}

# ── the pump: drain whole events out of inbuf, keeping any partial tail ─────
sub _pump ($self) {
    my $h = $self->Handler or return;
    my $br = \$self->{inbuf};

    unless ($self->{magic_seen}) {
        return if length($$br) < 8;
        die "BSAX magic missing" unless substr($$br,0,8) eq "AMINBSA1";
        substr($$br,0,8,'');
        $self->{magic_seen} = 1;
    }

    my $p = 0;
    my $n = length $$br;
    while ($p < $n) {
        my $tag   = ord substr($$br,$p,1);
        my $kind  = $tag & 0xE0;
        my $flags = $tag & 0x1F;
        my $q     = $p + 1;                     # local cursor; committed on success
        my $done  = $self->_one_event($br, \$q, $h, $tag, $kind, $flags, $p);
        last unless $done;                      # 0 ⇒ need more input
        $p = $q;
    }
    substr($$br, 0, $p, '') if $p;
    return;
}

# _lex_name($id) — resolve a NAME_ID to bytes.  Three regions, mirroring Rust
# decode:
#   id <  ESCAPE                 ⇒ core closed-world vocab (NAMEBYID)
#   id == ESCAPE                 ⇒ returns undef ⇒ caller reads the length-
#                                  prefixed inline name off the wire (escape path)
#   ESCAPE < id <= band_max      ⇒ spec band (derived from this consumer's spec)
#   id >  band_max               ⇒ LOUD contract error.  A band id outside this
#                                  spec's declared band means the producer and
#                                  consumer specs disagree — a desync we refuse
#                                  to paper over with a silent inline read.
sub _lex_name ($self, $id) {
    return $NAMEBYID{$id} if $id < ESCAPE;
    return undef          if $id == ESCAPE;   # escape: inline name follows
    my $band = $self->_band;
    my $idx  = $id - ESCAPE - 1;
    return $band->[$idx] if $idx < @$band;
    die sprintf 'BSAX NAME_ID %d out of range: codec vocab has ESCAPE=%d entries '
              . 'and the machine spec band declares %d name(s)',
        $id, ESCAPE, scalar @$band;
}

# Decode exactly one event into the handler.  Returns 1 when a whole event was
# consumed (and $$qr advanced past it), 0 when more bytes are required (leaving
# $$qr untouched).  Dies on an unknown tag byte.
sub _one_event ($self, $br, $qr, $h, $tag, $kind, $flags, $tag_start) {
    my $b = $$br;
    my $q = $$qr;

    if    ($kind == 0x00) { $h->start_document({}); $$qr = $q; return 1 }  # StartDoc
    elsif ($kind == 0x20) { $h->end_document({});   $$qr = $q; return 1 }  # EndDoc
    elsif ($kind == 0x60) { $self->_emit_end($h);   $$qr = $q; return 1 }  # EndEl

    if ($kind == 0x80 || $kind == 0xA0) {                                  # Chars / IWS
        my $len;
        if ($flags < 31) { $len = $flags }
        else {
            $len = _leb_at($br, \$q);
            return 0 unless defined $len;
        }
        return 0 if $q + $len > length $b;
        my $t = substr($b, $q, $len); $q += $len;
        # 0xA0 is XML::SAX `ignorable_whitespace` — keep it distinct from
        # `characters` so an IWS tag from a Rust producer never masquerades as
        # significant text (see bsax lib.rs Tag::Iws).
        if ($kind == 0xA0) { $h->ignorable_whitespace({ Data => $t }) }
        else               { $h->characters({ Data => $t }) }
        $$qr = $q; return 1;
    }

    if ($kind == 0x40) {                                                    # StartEl
        my $ns_id = $self->{last_ns};
        my $ns_uri = $self->{last_ns_uri} // '';
        if ($flags & 0x10) {
            return 0 if $q >= length $b;
            my $nbb = ord substr($b,$q++,1);
            $ns_id = ($nbb >> 4) & 0x0F;
            if ($ns_id == NS_ESCAPE) {
                # Custom Corp namespace (DI-2): length-prefixed UTF-8 URI
                # written by Amin::Handler::BSAX.  Fallback to empty string
                # if 0-length.
                my $l = _leb_at($br, \$q);
                return 0 unless defined $l;
                return 0 if $q + $l > length $b;
                $ns_uri = $l > 0 ? substr($b, $q, $l) : '';
                $q += $l;
            } else {
                $ns_uri = $NSBYID{$ns_id} // '';
            }
            $self->{last_ns} = $ns_id;
            $self->{last_ns_uri} = $ns_uri;
        }
        my $nid = _leb_at($br, \$q);
        return 0 unless defined $nid;
        my $ln = $self->_lex_name($nid);
        if (!defined $ln) {  # NAME_ID escape (>= ESCAPE): length-prefixed raw name
            my $l = _leb_at($br,\$q);
            return 0 unless defined $l;
            return 0 if $q + $l > length $b;
            $ln = substr($b,$q,$l); $q += $l;
        }
        my $count;
        if (($flags & 0x0F) == 15) {
            $count = _leb_at($br,\$q);
            return 0 unless defined $count;
        } else { $count = $flags & 0x0F }

        my $attrs = {};
        for (1..$count) {
            my $aid = _leb_at($br,\$q);
            return 0 unless defined $aid;
            my $an = $self->_lex_name($aid);
            if (!defined $an) {
                my $l = _leb_at($br,\$q);
                return 0 unless defined $l;
                return 0 if $q + $l > length $b;
                $an = substr($b,$q,$l); $q += $l;
            }
            my $vl = _leb_at($br,\$q);
            return 0 unless defined $vl;
            return 0 if $q + $vl > length $b;
            my $av = substr($b,$q,$vl); $q += $vl;
            # Attribute namespace is derived from VOCAB REGION of the
            # attribute NAME_ID, since the VOCAB is split contiguously:
            #   0..22   amin core (NS_AMIN)
            #  23..36   map       (NS_MAP)
            #  37..82   ui        (NS_UI)  — 33 kinds + 13 attrs
            #  83..101  bc        (NS_BITCACHE)
            # 102..107  ainit-stage — these attr names live on amin:*
            #           elements so use NS_AMIN.
            # 108..121  exec-net/sandbox — likewise NS_AMIN.
            # 122..136  sec:* post-quantum E2EE surface (NS_SEC).
            # 137..171  document-generation grammar — platform vocabulary in
            #           the core amin: namespace (NS_AMIN).
            # Anything >= ESCAPE (172) falls back to the parent element's
            # NS (possibly a Corp custom escape URI).
            my $a_ns;
            if    ($aid < 23)      { $a_ns = NS_AMIN }
            elsif ($aid < 37)      { $a_ns = NS_MAP }
            elsif ($aid < 83)      { $a_ns = NS_UI }
            elsif ($aid < 102)     { $a_ns = NS_BITCACHE }
            elsif ($aid < 108)     { $a_ns = NS_AMIN }
            elsif ($aid < 137)     { $a_ns = NS_SEC }
            elsif ($aid < ESCAPE)  { $a_ns = NS_AMIN }
            else                   { $a_ns = $ns_id }   # unknown: inherit elem NS
            # An application/Rust element in a custom namespace has no low
            # NS_ID slot, so every one of its attributes must inherit that
            # element's URI.  The NAME_ID region is only a hint for core
            # vocabulary; without this an app's sox:id would decode as amin:id.
            $a_ns = NS_ESCAPE if $ns_id == NS_ESCAPE;
            # Element-aware override: `type`/`name`/`value` are ui: form
            # attributes but their LocalNames also occupy the amin/map NAME_ID
            # slots, so the region rule above would resolve a ui: form's
            # attribute to the wrong NS.  Every attribute of a ui: element
            # belongs to the ui: vocabulary regardless of its NAME_ID region.
            $a_ns = NS_UI if $ns_id == NS_UI && $aid < ESCAPE;
            # Same for the amin: document grammar: id/name/type/size/title/
            # min/max are shared LocalNames whose ids sit in earlier regions,
            # but on amin:document/sheet/row/cell/… they are amin:* attributes.
            $a_ns = NS_AMIN if $ns_id == NS_AMIN && $AMIN_DOC_ELEM{$ln}
                && $aid < ESCAPE;
            # For custom escape NS, use the element's already-resolved
            # $ns_uri (possibly the inline Corp URI) not the (undefined)
            # $NSBYID{NS_ESCAPE} entry.
            my $a_uri = ($a_ns == NS_ESCAPE)
                ? $ns_uri
                : ($NSBYID{$a_ns} // '');
            my $a_pfx = $a_ns == NS_AMIN     ? 'amin'
                      : $a_ns == NS_UI       ? 'ui'
                      : $a_ns == NS_MAP      ? 'map'
                      : $a_ns == NS_BITCACHE ? 'bc'
                      : $a_ns == NS_SEC      ? 'sec' : '';
            my $a_qname = length($a_pfx) ? "$a_pfx:$an" : $an;
            $attrs->{"{}$an"} = {
                Name => $a_qname, LocalName => $an, Prefix => $a_pfx,
                NamespaceURI => $a_uri, Value => $av,
            };
        }
        my $pfx = $ns_id == NS_AMIN ? 'amin'
                 : $ns_id == NS_UI   ? 'ui'
                 : $ns_id == NS_MAP  ? 'map'
                 : $ns_id == NS_BITCACHE ? 'bc'
                 : $ns_id == NS_SEC  ? 'sec' : '';
        my $qname = length($pfx) ? "$pfx:$ln" : $ln;
        push @{$self->{stack}}, [$ln, $ns_uri, $qname, $pfx];
        $h->start_element({
            NamespaceURI => $ns_uri, LocalName => $ln,
            Name => $qname, Prefix => $pfx, Attributes => $attrs,
        });
        $$qr = $q; return 1;
    }

    # PI (XML::SAX `processing_instruction`, `<?target data?>`).  This is a
    # standard XML event mirrored 1:1 — NOT an Amin invention — kept so BSAX and
    # the XML path stay equivalent (a parser differential would be the real
    # bug, since the transport auto-detects XML vs BSAX by peeking the first
    # byte).  The Dispatcher answers this event with warn-and-drop: the PI never
    # enters the chain, and the attempt is logged on the machine's loaded Log.
    # Any further allow-list/refusal policy on Target/Data belongs there, never
    # here.  See bsax lib.rs "Escape hatches are not a trust boundary".
    if ($kind == 0xC0) {                                                    # PI
        my $tid = _leb_at($br, \$q);
        return 0 unless defined $tid;
        my $tgt = $self->_lex_name($tid);
        if (!defined $tgt) {    # escaped/PROHIBITED target: len-prefixed name
            my $l = _leb_at($br, \$q);
            return 0 unless defined $l;
            return 0 if $q + $l > length $b;
            $tgt = substr($b, $q, $l); $q += $l;
        }
        my $dl = _leb_at($br, \$q);         # data is ALWAYS length-prefixed
        return 0 unless defined $dl;
        return 0 if $q + $dl > length $b;
        my $data = substr($b, $q, $dl); $q += $dl;
        $h->processing_instruction({ Target => $tgt, Data => $data });
        $$qr = $q; return 1;
    }

    # 0xE0 (was DICT_ENTRY, stream-local interning) is retired: it had no
    # XML::SAX analogue, so a pure 1:1 codec has no event for it.  It falls
    # through to the unknown-tag error, matching the Rust decoder's behaviour.
    die sprintf "BSAX unknown tag 0x%02X at offset %d", $tag, $tag_start;
}

# ── SAX stack pop equivalent — Handler::Writer / XML decode use the same model
sub _emit_end ($self, $h) {
    my $pop = pop @{$self->{stack}} or return;
    my ($ln, $ns, $qname, $pfx) = @$pop;
    $h->end_element({
        NamespaceURI => $ns, LocalName => $ln,
        Name => $qname, Prefix => $pfx,
    });
    return;
}

# ── Transparent fallback: first byte '<' means XML.  Lets Amin pipeline
#    peers mix XML and BSAX on the same AWP/3 transport with zero config.
sub _parse_xml_fallback ($self, $bytes) {
    require Amin::Generator::XML;
    Amin::Generator::XML->new(Handler => $self->Handler)->parse_string($bytes);
    return;
}

# ── LEB128 u32 reader — 5 bytes max to match Rust decode::leb.  Returns undef
#    (without advancing $qr beyond what it consumed) when the buffer holds an
#    incomplete varint, so the caller can wait for the next feed().
sub _leb_at ($br, $qr) {
    my $r = 0; my $s = 0; my $i = 0;
    my $n = length $$br;
    while (1) {
        die "BSAX LEB128 overflow" if $i++ >= 5;
        return undef if $$qr >= $n;
        my $byte = ord substr($$br, $$qr, 1);
        $$qr++;
        $r |= (($byte & 0x7F) << $s);
        return $r if ($byte & 0x80) == 0;
        $s += 7;
    }
}

1;
