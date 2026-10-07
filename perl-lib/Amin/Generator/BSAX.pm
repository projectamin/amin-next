package Amin::Generator::BSAX;
use v5.38; use warnings; use utf8;
use parent 'XML::SAX::Base';  # Generator, not Handler — ISA SAX so Handler chain works

use Amin qw(NS);
use Amin::Util::Fold qw(_flags _vals);  # re-use allow-list contracts
use Class::Tiny qw(Handler), {
    last_ns => 0+0,
    stack   => [],
};

# Mirrors of Amin::Handler::BSAX constants — MUST stay 1:1 with Handler::BSAX
# and rust/crates/bsax/src/vocab.rs BY_ID slice.
use constant { NS_NONE=>0, NS_AMIN=>1, NS_UI=>2, NS_MAP=>3, NS_ESCAPE=>15 };
my %NSBYID = ( NS_NONE, '', NS_AMIN, NS(),
   NS_UI,  'http://projectamin.org/ns/ui/1',
   NS_MAP, 'http://projectamin.org/ns/map/1' );
my @VOCAB = (
    # amin core (Handler::BSAX 1:1 copy)
    qw(profile result command stream status cond argv
       id version kind rc pid duration exit_kind name target
       channel dir mode level value type size),
    # map:*
    qw(region server link node a b cost phase flavor
       latency_ms bw_gbps tier zone value),
    # ui:*
    qw(app scene list row column hstack vstack stack grid section
       card progress alert sheet toolbar searchable item label
       text badge sparkline button navigate image asyncimage
       title spacing points for-each bind url),
);
use constant ESCAPE => do { my $n = scalar @VOCAB; $n };
my %NAMEBYID; @NAMEBYID{0..$#VOCAB} = @VOCAB;

# ── public entry: parse binary buffer, emit SAX events into $self->Handler ──
sub parse_bytes ($self, $bytes) {
    my $h = $self->Handler or return;
    my $p = 0; my $n = length($bytes);

    # Validate magic (8 bytes) — if the first byte is '<' or 0x3C then it's
    # XML → transparently fall back to XML::LibXML::SAX.  Allows hybrid input.
    if ($n >= 1 && substr($bytes,0,1) eq '<') { return $self->_parse_xml_fallback($bytes) }

    die "BSAX magic missing" unless $n >= 8 && substr($bytes,0,8) eq "AMINBSA1";
    $p = 8;
    $h->start_document({});

    while ($p < $n) {
        my $tag = ord substr($bytes,$p++,1);
        my $kind  = $tag & 0xE0;
        my $flags = $tag & 0x1F;

        if    ($kind == 0x00) { $h->start_document({}); }     # StartDoc
        elsif ($kind == 0x20) { $h->end_document({}); }       # EndDoc
        elsif ($kind == 0x60) { $self->_emit_end($h); }       # EndEl
        elsif ($kind == 0x80 || $kind == 0xA0) {              # Chars / IWS
            my $len = ($flags < 31) ? $flags : _rd_leb(\$p, $bytes);
            my $t = substr($bytes, $p, $len); $p += $len;
            $h->characters({ Data => $t });
        }
        elsif ($kind == 0x40) {                                # StartEl
            my $ns_inline = ($flags & 0x10) != 0;
            my $ns_id = $self->{last_ns};
            if ($ns_inline) {
                my $b = ord substr($bytes,$p++,1);
                $ns_id = ($b >> 4) & 0x0F;
                $self->{last_ns} = $ns_id;
            }
            my $nid = _rd_leb(\$p, $bytes);
            my $ln = $NAMEBYID{$nid};
            if (!defined $ln) {  # NAME_ID escape (>= ESCAPE): length-prefixed raw name
                my $l = _rd_leb(\$p,$bytes);
                $ln = substr($bytes,$p,$l); $p += $l;
            }
            # ── P/B/N guard — match Util::Fold allow-list semantics ──
            # Closed-world enforcement: non-vocab events are DROPPED while
            # still walking their attribute bytes to keep the stream aligned.
            if ($self->{allowed_names} && $nid >= ESCAPE) {
                my $count = ($flags & 0x0F) == 15 ? _rd_leb(\$p,$bytes) : ($flags & 0x0F);
                for (1..$count) {
                    my $aid = _rd_leb(\$p,$bytes);
                    if ($aid >= ESCAPE) { my $l=_rd_leb(\$p,$bytes); $p += $l }
                    my $vl = _rd_leb(\$p,$bytes); $p += $vl;
                }
                next;
            }
            my $count = ($flags & 0x0F) == 15 ? _rd_leb(\$p,$bytes) : ($flags & 0x0F);
            my $attrs = {};
            for (1..$count) {
                my $aid = _rd_leb(\$p,$bytes);
                my $an = $NAMEBYID{$aid};
                if (!defined $an) { my $l=_rd_leb(\$p,$bytes); $an=substr($bytes,$p,$l); $p+=$l }
                my $vl = _rd_leb(\$p,$bytes);
                my $av = substr($bytes,$p,$vl); $p += $vl;
                # Attribute namespace is derived from VOCAB section (0-22 amin,
                # 23-36 map, 37+ ui) — NOT inherited from the parent element,
                # because cross-namespace attrs like amin:id inside ui:app are
                # common in the SAX pipeline (e.g. late filter overlays).
                my $a_ns;
                if ($aid < 23)      { $a_ns = NS_AMIN }   # amin core 0..22
                elsif ($aid < 37)   { $a_ns = NS_MAP }    # map 23..36
                elsif ($aid < ESCAPE){ $a_ns = NS_UI }    # ui 37..ESCAPE-1
                else                { $a_ns = $ns_id }   # unknown: use elem NS
                my $a_uri = $NSBYID{$a_ns} // '';
                my $a_pfx = $a_ns == NS_AMIN ? 'amin'
                          : $a_ns == NS_UI   ? 'ui'
                          : $a_ns == NS_MAP  ? 'map' : '';
                my $a_qname = length($a_pfx) ? "$a_pfx:$an" : $an;
                $attrs->{"{}$an"} = {
                    Name => $a_qname, LocalName => $an, Prefix => $a_pfx,
                    NamespaceURI => $a_uri, Value => $av,
                };
            }
            my $ns_uri = $NSBYID{$ns_id} // '';
            my $pfx = $ns_id == NS_AMIN ? 'amin'
                     : $ns_id == NS_UI   ? 'ui'
                     : $ns_id == NS_MAP  ? 'map' : '';
            my $qname = length($pfx) ? "$pfx:$ln" : $ln;
            push @{$self->{stack}}, [$ln, $ns_uri, $qname, $pfx];
            $h->start_element({
                NamespaceURI => $ns_uri, LocalName => $ln,
                Name => $qname, Prefix => $pfx, Attributes => $attrs,
            });
        }
        else { die sprintf "BSAX unknown tag 0x%02X at offset %d", $tag, $p-1 }
    }
    return;
}

# ── SAX stack pop equivalent — Handler::Writer / XML decode use the same model
sub _emit_end ($self, $h) {
    my $pop = pop @{$self->{stack}} or return;
    my ($ln, $ns, $qname, $pfx) = @$pop;
    $h->end_element({
        NamespaceURI => $ns, LocalName => $ln,
        Name => $qname, Prefix => $pfx,
    });
}

# ── Transparent fallback: first byte '<' means XML.  Lets Amin pipeline
#    peers mix XML and BS AX on the same AWP/3 transport with zero config.
sub _parse_xml_fallback ($self, $bytes) {
    require XML::LibXML::SAX;
    my $p = XML::LibXML::SAX->new( Handler => $self->Handler );
    open my $fh, '<', \$bytes or die $!;
    $p->parse_file($fh);
    close $fh;
}

# ── LEB128 u32 reader — 5 bytes max to match Rust decode::leb_u32 cap
sub _rd_leb ($pref, $bytes) {
    use integer;
    my $r = 0; my $s = 0; my $i = 0;
    while (1) {
        die "BSAX LEB128 overflow" if $i++ >= 5 || $$pref >= length($bytes);
        my $b = ord substr($bytes, $$pref++, 1);
        $r |= (($b & 0x7F) << $s);
        last if ($b & 0x80) == 0;
        $s += 7;
    }
    $r;
}

1;
