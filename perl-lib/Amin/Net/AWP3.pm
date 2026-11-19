package Amin::Net::AWP3;

# ═══════════════════════════════════════════════════════════════════════════
# Perl binding for the AWP/3 mesh transport (the rust/crates/awp3 cdylib).
#
# Perl owns no framing of its own (docs/proxy-plan.md §6/§7): it drives the
# crate's three entry points — handshake_initiator, handshake_responder and
# frame — through FFI::Platypus, so a Perl front and a Rust peer derive
# byte-identical frames from one transcript.  One object per connection; the
# opaque Rust handle is released in free()/DESTROY.
#
# The C ABI is small and fixed-size: every structure has a compile-time length
# (bundle_len/msg1_len/msg2_len/receipt_len/frame_overhead), so each call is
# given a precisely sized buffer and every fallible entry point returns a byte
# count on success or a negative error code.
# ═══════════════════════════════════════════════════════════════════════════

use v5.38; use warnings; use utf8; use experimental 'signatures';

use FFI::Platypus 2.00;
use Amin::ToolPaths qw(awp3_lib);

# AWP/3 frame kinds live in the cleartext header (byte 1).  The bridge reads it
# only to recognise a CLOSE; it frames nothing itself.
use constant KIND_CLOSE => 0x01;

# Error codes mirror Awp3Error in rust/crates/awp3/src/ffi.rs.
my %ERR = (
    -1 => 'invalid key material',        -2 => 'signature verification failed',
    -3 => 'aead authentication failed',  -4 => 'ml-kem-768 operation failed',
    -5 => 'malformed handshake message', -6 => 'malformed or out-of-order frame',
    -7 => 'session already closed',      -8 => 'output buffer too small',
    -9 => 'invalid argument',
);

my $FFI;

# Bind every symbol once, as code refs (->function installs nothing into this
# package; the refs live in the returned hash and are reached via _ffi()->{…}).
#
# Byte buffers — every argument that points at a fixed-size structure — use the
# `string` type with a plain scalar.  Platypus points C at the scalar's own PV
# (embedded NULs and explicit lengths survive) and copies any in-place writes
# back, which is exactly the in/out buffer contract the fixed-size ABI wants.
# Only the connection handle is `opaque`.
sub _ffi () {
    return $FFI if $FFI;
    my $lib = awp3_lib();
    die "Amin::Net::AWP3: awp3 cdylib not found; run `cargo build -p awp3` "
      . "or set AMIN_AWP3_LIB\n" unless length $lib;
    my $f = FFI::Platypus->new(api => 2);
    $f->lib($lib);
    return $FFI = {
        bundle_len       => $f->function('awp3_bundle_len'       => [] => 'size_t'),
        msg1_len         => $f->function('awp3_msg1_len'         => [] => 'size_t'),
        msg2_len         => $f->function('awp3_msg2_len'         => [] => 'size_t'),
        receipt_len      => $f->function('awp3_receipt_len'      => [] => 'size_t'),
        frame_overhead   => $f->function('awp3_frame_overhead'   => [] => 'size_t'),
        responder_new    => $f->function('awp3_responder_new'    => ['string', 'string'] => 'opaque'),
        client_new       => $f->function('awp3_client_new'       => ['string', 'string'] => 'opaque'),
        client_msg1      => $f->function('awp3_client_msg1'      => ['opaque', 'string'] => 'ssize_t'),
        responder_accept => $f->function('awp3_responder_accept' => ['opaque', 'string', 'string'] => 'ssize_t'),
        client_finish    => $f->function('awp3_client_finish'    => ['opaque', 'string'] => 'ssize_t'),
        seal             => $f->function('awp3_seal'             => ['opaque', 'string', 'size_t', 'string'] => 'ssize_t'),
        open             => $f->function('awp3_open'             => ['opaque', 'string', 'size_t', 'string'] => 'ssize_t'),
        close            => $f->function('awp3_close'            => ['opaque', 'string', 'string'] => 'ssize_t'),
        free             => $f->function('awp3_free'             => ['opaque'] => 'void'),
    };
}

# ── Error handling ──────────────────────────────────────────────────────────

sub _ok ($n, $what) {
    return $n if $n >= 0;
    die sprintf "Amin::Net::AWP3: %s: %s (%d)\n", $what, $ERR{$n} // 'unknown error', $n;
}

sub _random_seed () {
    open my $fh, '<:raw', '/dev/urandom' or die "Amin::Net::AWP3: /dev/urandom: $!\n";
    my $seed = '';
    my $n = read $fh, $seed, 32;
    close $fh;
    die "Amin::Net::AWP3: short read from /dev/urandom\n" unless defined $n && $n == 32;
    return $seed;
}

sub _seed ($o) {
    my $seed = $o->{seed} // _random_seed();
    die "Amin::Net::AWP3: seed must be 32 bytes\n" unless length($seed) == 32;
    return $seed;
}

# ── Constructors ────────────────────────────────────────────────────────────

# Amin::Net::AWP3->responder(seed => $bytes)
#
# A backend/responder identity.  ->bundle returns the self-signed public bundle
# a connecting initiator feeds to ->client.
sub responder ($class, %o) {
    my $seed = _seed(\%o);
    my $len  = _ffi()->{bundle_len}->();
    my $buf  = "\0" x $len;
    my $h    = _ffi()->{responder_new}->($seed, $buf);
    die "Amin::Net::AWP3: responder identity creation failed\n" unless defined $h;
    return bless { h => $h, role => 'responder', bundle => substr($buf, 0, $len) }, $class;
}

# Amin::Net::AWP3->client(bundle => $bytes, seed => $bytes)
#
# A front/initiator that already trusts the responder bundle.
sub client ($class, %o) {
    my $bundle = $o{bundle} // die "Amin::Net::AWP3: client requires a bundle\n";
    my $seed   = _seed(\%o);
    my $len    = _ffi()->{bundle_len}->();
    die "Amin::Net::AWP3: bundle must be $len bytes\n"
        unless length($bundle) == $len;
    my $h = _ffi()->{client_new}->($bundle, $seed);
    die "Amin::Net::AWP3: client handshake creation failed\n" unless defined $h;
    return bless { h => $h, role => 'client' }, $class;
}

# ── Handshake ───────────────────────────────────────────────────────────────

sub bundle ($self) { $self->{bundle} }
sub role   ($self) { $self->{role} }

# The initiator's first flight.
sub msg1 ($self) {
    my $len = _ffi()->{msg1_len}->();
    my $buf = "\0" x $len;
    _ok(_ffi()->{client_msg1}->($self->{h}, $buf), 'msg1');
    return substr($buf, 0, $len);
}

# Responder side: consume msg1, return the msg2 flight.  Both sides are now
# live sessions.
sub accept ($self, $msg1) {
    my $in  = _ffi()->{msg1_len}->();
    die "Amin::Net::AWP3: msg1 must be $in bytes\n" unless length($msg1) == $in;
    my $len = _ffi()->{msg2_len}->();
    my $buf = "\0" x $len;
    _ok(_ffi()->{responder_accept}->($self->{h}, $msg1, $buf), 'accept');
    return substr($buf, 0, $len);
}

# Initiator side: consume msg2, completing the handshake.
sub finish ($self, $msg2) {
    my $in = _ffi()->{msg2_len}->();
    die "Amin::Net::AWP3: msg2 must be $in bytes\n" unless length($msg2) == $in;
    _ok(_ffi()->{client_finish}->($self->{h}, $msg2), 'finish');
    return $self;
}

# ── Frames ──────────────────────────────────────────────────────────────────

# Seal one DATA frame around $pt.
sub seal ($self, $pt='') {
    my $ov  = _ffi()->{frame_overhead}->();
    my $buf = "\0" x (length($pt) + $ov);
    my $n = _ok(_ffi()->{seal}->($self->{h}, $pt, length($pt), $buf), 'seal');
    return substr($buf, 0, $n);
}

# Open one frame.  Returns the plaintext for a DATA frame, or undef for a CLOSE
# (which carries no payload but ends the session).
sub open ($self, $frame) {
    my $ov  = _ffi()->{frame_overhead}->();
    my $cap = length($frame) - $ov;
    die "Amin::Net::AWP3: frame shorter than the $ov-byte overhead\n" if $cap < 0;
    my $buf = "\0" x ($cap || 1);
    my $n = _ok(_ffi()->{open}->($self->{h}, $frame, length($frame), $buf), 'open');
    return undef if $n == 0 && ord(substr($frame, 1, 1)) == KIND_CLOSE;
    return substr($buf, 0, $n);
}

# Seal the CLOSE frame and sign the final chain into a receipt.  Returns
# ($close_frame, $receipt); the peer opens the frame and verifies the receipt.
sub close ($self) {
    my $fbuf = "\0" x _ffi()->{frame_overhead}->();
    my $rlen = _ffi()->{receipt_len}->();
    my $rbuf = "\0" x $rlen;
    my $n = _ok(_ffi()->{close}->($self->{h}, $fbuf, $rbuf), 'close');
    return (substr($fbuf, 0, $n), substr($rbuf, 0, $rlen));
}

# ── Lifetime ────────────────────────────────────────────────────────────────

sub free ($self) {
    if (my $h = delete $self->{h}) { _ffi()->{free}->($h) }
    return;
}

sub DESTROY ($self) { $self->free }

1;
