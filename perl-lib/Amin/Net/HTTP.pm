package Amin::Net::HTTP;
use v5.38; use warnings; use utf8; use experimental 'signatures';

# Shared HTTP/1.1 message grammar (proxy-plan §5, axa-plan §4.1).  The L7 proxy
# front and the AXA origin both speak the same wire, so the request line, the
# header fields and the body framing are parsed once, here, and used by both.
# Pure functions over bytes: no sockets, no state, nothing to configure.

# Split a request head (the bytes before the first CRLFCRLF) into
# (method, target, version, [[name, value], ...]).  An empty list means the
# head is malformed; the caller answers 400.
sub parse_request_head ($head) {
    my @lines = split /\r\n/, $head, -1;
    my $rl = shift @lines // '';
    my ($method, $target, $version) = $rl =~ m{^(\S+)[ \t]+(\S+)[ \t]+HTTP/(\d\.\d)$}
        or return;
    my @headers;
    for my $l (@lines) {
        my ($n, $v) = $l =~ m{^([^:]+):[ \t]*(.*)$} or return;
        push @headers, [ $n, $v ];
    }
    return ($method, $target, $version, \@headers);
}

# Split an upstream/response status head into (code, reason, [[name, value], ...]).
sub parse_status_head ($head) {
    my @lines = split /\r\n/, $head, -1;
    my $sl = shift @lines // '';
    my ($code, $reason) = $sl =~ m{^HTTP/\d\.\d[ \t]+(\d{3})[ \t]*(.*)$}
        or return;
    my @hl;
    for my $l (@lines) {
        my ($n, $v) = $l =~ m{^([^:]+):[ \t]*(.*)$} or next;
        push @hl, [ $n, $v ];
    }
    return ($code + 0, $reason, \@hl);
}

# Fold a header list to last-wins, keyed by lower-cased field name.
sub fold_headers ($headers) {
    my %h;
    $h{ lc $_->[0] } = $_->[1] for $headers->@*;
    return \%h;
}

# Body framing declared by the client: a byte count (Content-Length) or a
# chunked stream.  Neither is buffered — the plan is consumed as bytes arrive.
sub body_plan ($folded) {
    my $te = $folded->{'transfer-encoding'} // '';
    if ($te =~ /\bchunked\b/i) {
        return { chunked => Amin::Net::HTTP::Chunked->new };
    }
    my $cl = $folded->{'content-length'};
    if (defined $cl && $cl =~ /\A\d+\z/) {
        return { left => $cl + 0 };
    }
    return undef;   # no body
}

# Index of the CRLFCRLF that ends a head, or -1 while it is still incomplete.
sub head_end ($buf) { return index($buf, "\r\n\r\n") }

1;

# ── Chunked-body end detector ───────────────────────────────────────────────
package Amin::Net::HTTP::Chunked;
use v5.38; use experimental 'signatures';

# A chunked body is forwarded verbatim (no buffering, proxy-plan §9).  To know
# when the client has finished sending we only need to recognise the terminating
# zero-length chunk; the body itself is never held.
sub new ($class) { return bless { phase => 'size', buf => '', left => 0, done => 0 }, $class }

sub feed ($self, $bytes) {
    $self->{buf} .= $bytes;
    while (!$self->{done}) {
        if ($self->{phase} eq 'size') {
            my $i = index($self->{buf}, "\r\n");
            return 0 if $i < 0;
            my $line = substr($self->{buf}, 0, $i, '');
            substr($self->{buf}, 0, 2, '');
            my ($hex) = $line =~ /^([0-9a-fA-F]+)/;
            return $self->{done} = 1
                unless defined $hex && hex($hex) > 0;   # zero chunk => end
            $self->{left}  = hex($hex);
            $self->{phase} = 'data';
        }
        else {
            return 0 if length($self->{buf}) < $self->{left} + 2;
            substr($self->{buf}, 0, $self->{left} + 2, '');
            $self->{left}  = 0;
            $self->{phase} = 'size';
        }
    }
    return 1;
}

1;
