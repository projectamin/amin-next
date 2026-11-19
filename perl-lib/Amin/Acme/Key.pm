package Amin::Acme::Key;
use v5.38; use warnings; use utf8; use experimental 'signatures';

use Class::Tiny qw(path jwk thumbprint);
use MIME::Base64 ();
use Digest::SHA ();
use JSON::PP ();
use IPC::Run qw(harness start finish);

# ── the ACME account key, and the openssl work around it ─────────────────────
#
# RFC 8555 (ACME) is a JWS protocol: every request is a flattened JSON JWS
# signed by the account key, and the HTTP-01 key authorization a CA fetches is
# `token "." base64url(SHA-256(canonical JWK))` — the *thumbprint* of the same
# key (RFC 7638).  This module is the whole crypto layer: derive the JWK and
# thumbprint from an EC P-256 key, sign a JWS (ES256), and make the CSRs and
# cert keys an order finalizes with.
#
# All primitive operations shell out to the `openssl` CLI — the same choice the
# rest of the tree makes for key material, and the one the ACME workstream
# locked in (no Perl XS crypto dependency).
#
# ES256 is served.  The key is prime256v1:
#
#   openssl ecparam -name prime256v1 -genkey -noout -out acct.key
#
# `openssl ec -pubout -outform DER` yields a SubjectPublicKeyInfo whose final
# 65 bytes are the uncompressed point `04 || X(32) || Y(32)`; the JWK `x`/`y`
# are those two halves, base64url.  `openssl dgst -sha256 -sign` yields an
# *ASN.1 DER* ECDSA signature `SEQUENCE( INTEGER r, INTEGER s )`, which RFC 8555
# does NOT want: JWS ES256 carries the raw 64-byte `R || S`, so a signature is
# transcoded here (each integer left-padded to 32 bytes) before it is base64url.
#
# The JWK text is built by hand in the one canonical order RFC 7638 fixes for
# EC keys (`crv`, `kty`, `x`, `y`); the Rust peer builds the identical bytes, so
# the two implementations derive byte-identical thumbprints (proxy-plan §7).

our $ALG = 'ES256';
our $CURVE = 'P-256';

# ── construction ────────────────────────────────────────────────────────────

# new(path => '...') is fail-fast: a missing or malformed key dies here rather
# than at the first request, and the JWK + thumbprint are derived once.
sub BUILD ($self, $args) {
    my $path = $self->path;
    die "acme: key path required\n" unless defined $path && length $path;
    die "acme: key not found: $path\n" unless -f $path;
    my $der = $self->_openssl('ec', '-in', $path, '-pubout', '-outform', 'DER');
    # The uncompressed point is the trailing 65 bytes of the SPKI.
    die "acme: cannot read public key from $path\n" unless length $der >= 65;
    my $pt = substr $der, -65;
    die "acme: key $path is not an uncompressed EC point\n" unless ord(substr $pt, 0, 1) == 0x04;
    my %jwk = (
        crv => $CURVE,
        kty => 'EC',
        x   => _b64url(substr $pt, 1,  32),
        y   => _b64url(substr $pt, 33, 32),
    );
    # RFC 7638 canonical form: the required members in lexicographic order,
    # with no whitespace — this exact string is what is hashed.
    my $json = sprintf '{"crv":"%s","kty":"%s","x":"%s","y":"%s"}',
        $jwk{crv}, $jwk{kty}, $jwk{x}, $jwk{y};
    $self->jwk(\%jwk);
    $self->thumbprint(_b64url(Digest::SHA::sha256($json)));
    return;
}

# ── key authorization (the HTTP-01 answer) ──────────────────────────────────

# keyauth(token) = token "." thumbprint(RFC 7638(account key))  — RFC 8555 §8.1.
# It is a pure function of the account key and the token, so the responder needs
# no per-challenge state: given the key it can answer any token the CA issues.
sub key_authorization ($self, $token) {
    return ($token // '') . '.' . $self->thumbprint;
}

# ── JWS (RFC 7515 flattened JSON, ES256) ────────────────────────────────────

# jws($protected_href, $payload) → the flattened JWS JSON text to POST as
# `application/jose+json`.  `$payload` is the request body's JSON text, or ''
# for a POST-as-GET (RFC 8555 §6.3), which is b64url of zero octets.
#
# The protected header is canonicalised (sorted keys), matching the Rust peer,
# so a fixed {nonce, url, jwk} always yields the same protected bytes.
sub jws ($self, $protected, $payload = '') {
    my $ph  = _b64url(_json($protected));
    my $pl  = length($payload // '') ? _b64url($payload) : '';
    my $sig = $self->sign("$ph.$pl");
    return _json({ protected => $ph, payload => $pl, signature => _b64url($sig) });
}

# sign($input) → the raw 64-byte ES256 signature (R || S) over SHA-256(input).
sub sign ($self, $input) {
    my $der = $self->_openssl(
        'dgst', '-sha256', '-sign', $self->path, _stdin($input // ''));
    return _der_es_to_raw($der);
}

# ── cert keys and CSRs (an order finalizes with a CSR) ──────────────────────

# gen_ec($path) — a fresh prime256v1 key for a certificate (the *server* key,
# distinct from the account key), written 0600.
sub gen_ec ($class, $path) {
    my $pem = $class->_openssl('ecparam', '-name', 'prime256v1', '-genkey', '-noout');
    _write($path, $pem, 0600);
    return $path;
}

# csr_der($key_path, @domains) — a DER PKCS#10 CSR for the certificate key,
# carrying every domain as a subjectAltName (a single-domain CSR is just the
# one-element case).  DER is what RFC 8555 §7.4 wants in the finalize payload.
sub csr_der ($class, $key_path, @domains) {
    die "acme: csr needs at least one domain\n" unless @domains;
    my $san = 'subjectAltName=' . join ',', map { "DNS:$_" } @domains;
    return $class->_openssl(
        'req', '-new', '-key', $key_path, '-subj', "/CN=$domains[0]",
        '-addext', $san, '-outform', 'DER');
}

# ── openssl bridge ──────────────────────────────────────────────────────────

# Run openssl with @args, feeding $stdin on stdin (a `_stdin` marker or '').
# Returns stdout as raw bytes; dies on a non-zero exit or a missing binary.
sub _openssl ($class, @args) {
    my $stdin = '';
    $stdin = ${ pop @args } if @args && ref($args[-1]) eq 'SCALAR';
    my ($out, $err) = ('', '');
    my $h = harness ['openssl', @args], \$stdin, _accum(\$out), _accum(\$err), debug => 0;
    my $ok = eval { start $h; finish $h; 1 };
    my $rc = $? >> 8;
    my $cmd = join ' ', 'openssl', @args;
    if (!$ok) {
        my $e = $@ // 'exec failed';
        die "acme: $cmd: $e\n";
    }
    die "acme: $cmd failed ($rc): $err\n" if $rc != 0;
    return $out;
}

# A stdin payload marker, so an argument and the standard input can never be
# confused: _openssl pops the last arg only when it is a scalar reference.
sub _stdin ($bytes) { return \$bytes }

sub _accum ($sv) {
    sub ($data, @) { $$sv .= $data if defined $data; return () }
}

# ── ASN.1: openssl's `SEQUENCE(r, s)` → the raw R||S JWS wants ──────────────

sub _der_es_to_raw ($der) {
    my $i = 0;
    die "acme: bad DER signature\n" unless _tag($der, \$i) == 0x30;
    _len($der, \$i);
    die "acme: bad DER signature (r)\n" unless _tag($der, \$i) == 0x02;
    my $rl = _len($der, \$i);
    my $r  = substr $der, $i, $rl; $i += $rl;
    die "acme: bad DER signature (s)\n" unless _tag($der, \$i) == 0x02;
    my $sl = _len($der, \$i);
    my $s  = substr $der, $i, $sl; $i += $sl;
    return _pad32($r) . _pad32($s);
}

sub _tag ($der, $ip) { die "acme: DER underrun\n" if $$ip >= length $der; my $b = ord substr($der, $$ip, 1); $$ip += 1; return $b }

# A DER length: a single byte < 0x80, else the low 7 bits are the count of
# following big-endian length bytes.  Returns the length.
sub _len ($der, $ip) {
    my $b = _tag($der, $ip);
    return $b if $b < 0x80;
    my $n = $b & 0x7F;
    my $len = 0;
    for (1 .. $n) { $len = $len * 256 + _tag($der, $ip) }
    return $len;
}

# A big-endian INTEGER to exactly 32 bytes: strip the DER sign byte (a leading
# 0x00 on a high-bit value) then left-pad; ES256 coordinates are 32 bytes.
sub _pad32 ($int) {
    $int =~ s/^\x00+//;
    die "acme: ECDSA integer too large\n" if length($int) > 32;
    return ("\x00" x (32 - length $int)) . $int;
}

# ── small helpers ───────────────────────────────────────────────────────────

# base64url, unpadded (RFC 7515 §2).  MIME::Base64's encoder is the standard
# alphabet; translate to url-safe and drop the padding.
sub _b64url ($bytes) {
    my $b = MIME::Base64::encode_base64($bytes // '', '');
    $b =~ s{\+}{-}g;
    $b =~ s{/}{_}g;
    $b =~ s/=+$//;
    return $b;
}

# Canonical JSON (sorted keys, no extra whitespace) — the same byte form the
# Rust peer's serde with a BTreeMap produces, so JWS bytes agree (§7).
sub _json ($data) {
    return JSON::PP->new->canonical->utf8->encode($data);
}

sub _write ($path, $bytes, $mode) {
    open(my $fh, '>:raw', $path) or die "acme: write $path: $!\n";
    print {$fh} $bytes;
    close $fh;
    chmod $mode, $path;
    return;
}

1;
