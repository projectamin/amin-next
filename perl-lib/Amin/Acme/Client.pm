package Amin::Acme::Client;
use v5.38; use warnings; use utf8; use experimental 'signatures';

use Class::Tiny qw(directory key contact log),
    { kid => undef, nonce => undef, _http => undef, _dir => undef, _key => undef };
use HTTP::Tiny;
use JSON::PP ();
use MIME::Base64 ();

use Amin::Acme::Key;

# ── the ACME RFC 8555 client (the issuance side of "Responder + client") ─────
#
# A minimal, dependency-light RFC 8555 client for HTTP-01 issuance: it walks
# the directory, registers or reuses an account, opens an order, points the CA
# at the HTTP-01 challenge the *responder* filter already answers (the key
# authorization is a pure function of the account key — see Amin::Acme::Key), and
# finalizes with a CSR.
#
# Every request is a flattened JSON JWS (Amin::Acme::Key->jws) POSTed as
# `application/jose+json`; a POST-as-GET (RFC 8555 §6.3) is a JWS whose payload
# is the empty octet string.  `Replay-Nonce` is captured from every response, so
# only the first request pays a newNonce round trip.
#
# The client never mints authority: it proves control of a name the operator
# already serves, and the responder only ever answers tokens for a key it holds.
# Scope locked with the ACME workstream: HTTP-01, openssl CLI crypto.

our $HTTP_01 = 'http-01';
my $JSON_CT = 'application/jose+json';

# ── construction ────────────────────────────────────────────────────────────

sub BUILD ($self, $args) {
    my $path = $self->key;
    die "acme: client needs an account key path\n" unless defined $path && length $path;
    $self->_key(Amin::Acme::Key->new(path => $path));
    $self->_http(HTTP::Tiny->new(
        agent      => 'amin-acme/3.0',
        verify_SSL => 1,
        timeout    => $args->{timeout} // 30,
    ));
    return;
}

sub key_obj ($self) { $self->_key }

# ── the directory (RFC 8555 §7.1.1) ─────────────────────────────────────────

# directory_doc() → the parsed directory document, fetched once and cached.
# (Not `directory` — that is the Class::Tiny accessor for the configured URL.)
sub directory_doc ($self) {
    return $self->_dir if $self->_dir;
    my $url = $self->directory;
    die "acme: directory URL required\n" unless defined $url && length $url;
    my $res = $self->_http->get($url);
    _absorb_nonce($self, $res);
    _ok_or_die($self, 'directory', $res);
    my $doc = _decode($res->{content});
    die "acme: directory has no newNonce URL\n" unless $doc->{newNonce};
    $self->_dir($doc);
    return $doc;
}

# ── account (RFC 8555 §7.3) ─────────────────────────────────────────────────

# new_account(%o): register (or find) an account and record its kid.  `contact`
# defaults to the client's configured list; `only => 1` asks the CA to return an
# existing account only (no new one created), which is the idempotent path.
sub new_account ($self, %o) {
    my $contact = $o{contact} // $self->contact // [];
    my %payload = (termsOfServiceAgreed => JSON::PP::true);
    $payload{contact} = $contact if $contact && @$contact;
    $payload{onlyReturnExisting} = JSON::PP::true if $o{only};
    my $dir = $self->directory_doc;
    my ($res) = $self->_post($dir->{newAccount}, \%payload, jwk => 1);
    my $kid = $res->{headers}{location};
    die "acme: newAccount returned no Location (kid)\n"
        unless defined $kid && length $kid;
    $self->kid($kid);
    _log($self, "account registered: $kid");
    return $kid;
}

sub ensure_account ($self, %o) {
    return $self->kid if defined $self->kid && length $self->kid;
    if (my $k = $o{kid}) { $self->kid($k); return $k }
    return $self->new_account(%o);
}

# ── order (RFC 8555 §7.4) ───────────────────────────────────────────────────

# new_order(@domains) → the parsed order, with `_url` and `_finalize` folded in.
sub new_order ($self, @domains) {
    $self->ensure_account(%{ $self->{_acct_opts} // {} });
    die "acme: order needs at least one domain\n" unless @domains;
    my @ids = map { +{ type => 'dns', value => $_ } } @domains;
    my $dir = $self->directory_doc;
    my ($res, $decoded) = $self->_post($dir->{newOrder}, { identifiers => \@ids });
    my $order = $decoded // _decode($res->{content});
    $order->{_url}      = $res->{headers}{location};
    $order->{_finalize} = $order->{finalize};
    _log($self, "order opened: $order->{_url} (" . join(',', @domains) . ")");
    return $order;
}

# authorization($url) → the parsed authorization (its challenges included).
sub authorization ($self, $url) {
    my ($res) = $self->_post($url, undef);   # POST-as-GET
    return _decode($res->{content});
}

# order($url) → the parsed order (POST-as-GET), for status polling.
sub order ($self, $url) {
    my ($res) = $self->_post($url, undef);
    return _decode($res->{content});
}

# http_01($authz) → the HTTP-01 challenge from an authorization, or undef.
sub http_01 ($class, $authz) {
    for my $c ($authz->{challenges}->@*) {
        return $c if ($c->{type} // '') eq $HTTP_01;
    }
    return undef;
}

# trigger($challenge_url) → tell the CA to validate (RFC 8555 §7.5.1).  The
# responder already answers the token, so there is nothing to publish.
sub trigger ($self, $url) {
    my ($res) = $self->_post($url, {});
    _log($self, "challenge triggered: $url");
    return $res;
}

# finalize($url, $csr_der) → submit the CSR (RFC 8555 §7.4) and return the order.
sub finalize ($self, $url, $csr_der) {
    my ($res, $decoded) = $self->_post($url, { csr => _b64url($csr_der) });
    return $decoded // _decode($res->{content});
}

# certificate($url) → the PEM certificate chain (RFC 8555 §7.4.2), fetched as a
# POST-as-GET with the one Accept the RFC defines.
sub certificate ($self, $url) {
    my ($res) = $self->_post($url, undef,
        accept => 'application/pem-certificate-chain');
    return $res->{content};
}

# ── polling ─────────────────────────────────────────────────────────────────

# poll($url) → the resource once its `status` leaves `pending`/`processing`.
# `valid` returns it; `invalid` dies with the resource's problem detail.  The
# server's Retry-After is honoured, bounded by `tries`.
sub poll ($self, $url, $tries = 30) {
    my $delay = 1;
    for my $n (1 .. $tries) {
        my ($res) = $self->_post($url, undef);
        my $doc = _decode($res->{content});
        my $st  = $doc->{status} // '';
        return $doc if $st eq 'valid' || $st eq 'ready';
        if ($st eq 'invalid') {
            my $d = $doc->{error}{detail} // $doc->{error}{type} // 'no detail';
            die "acme: $url is invalid: $d\n";
        }
        $delay = _retry_after($res->{headers}{'retry-after'}) // $delay;
        sleep $delay if $n < $tries;
    }
    die "acme: $url did not become valid after $tries polls\n";
}

sub _retry_after ($v) {
    return undef unless defined $v && length $v;
    return $1 if $v =~ /^(\d+)$/;
    return undef;   # HTTP-date form: fall back to the caller's delay
}

# ── the whole issuance (§7.4, HTTP-01) ──────────────────────────────────────

# issue(\@domains, $cert_key_path) → the PEM chain, having ordered, validated
# and finalized for @domains.  The certificate key at $cert_key_path is made if
# it does not exist.  The responder is assumed to be serving already.
sub issue ($self, $domains, $cert_key_path, %o) {
    $self->{_acct_opts} = { %o };
    $self->ensure_account(%o);
    my $order = $self->new_order(@$domains);

    for my $az_url ($order->{authorizations}->@*) {
        my $az = $self->authorization($az_url);
        next if ($az->{status} // '') eq 'valid';
        my $chal = $self->http_01($az)
            or die "acme: no $HTTP_01 challenge offered for " . ($az->{identifier}{value} // '?') . "\n";
        $self->trigger($chal->{url});
    }
    for my $az_url ($order->{authorizations}->@*) {
        $self->poll($az_url);
    }

    Amin::Acme::Key->gen_ec($cert_key_path) unless -f $cert_key_path;
    my $csr = Amin::Acme::Key->csr_der($cert_key_path, @$domains);

    my $final = $self->finalize($order->{_finalize}, $csr);
    my $url   = $final->{order} // $order->{_url};
    my $done  = ($final->{status} // '') eq 'valid' ? $final : $self->poll($url);
    die "acme: order finished without a certificate URL\n"
        unless $done->{certificate};
    my $pem = $self->certificate($done->{certificate});
    _log($self, 'certificate issued for ' . join(',', @$domains));
    return $pem;
}

# ── JWS POST plumbing ───────────────────────────────────────────────────────

# _post($url, $payload_href) → ($res, $decoded_or_undef).  `$payload_href` undef
# is a POST-as-GET (empty payload).  Uses the account kid once known, else the
# embedded JWK (only newAccount).  Every response's Replay-Nonce is absorbed.
sub _post ($self, $url, $payload, %o) {
    my $nonce = $self->nonce // $self->_fetch_nonce;
    my %protected = (alg => $Amin::Acme::Key::ALG, nonce => $nonce, url => $url);
    if ($o{jwk} || !$self->kid) {
        $protected{jwk} = $self->_key->jwk;
    }
    else {
        $protected{kid} = $self->kid;
    }
    my $body = $self->_key->jws(
        \%protected,
        defined $payload ? JSON::PP->new->canonical->utf8->encode($payload) : '',
    );
    my %headers = ('Content-Type' => $JSON_CT);
    $headers{Accept} = $o{accept} if $o{accept};
    my $res = $self->_http->request('POST', $url, { headers => \%headers, content => $body });
    $self->nonce(undef);
    _absorb_nonce($self, $res);
    _ok_or_die($self, $url, $res);
    my $decoded = (($res->{headers}{'content-type'} // '') =~ m{application/json})
        ? eval { _decode($res->{content}) } : undef;
    return ($res, $decoded);
}

# A fresh nonce (RFC 8555 §7.2): HEAD the directory's newNonce.
sub _fetch_nonce ($self) {
    my $dir = $self->directory_doc;
    my $res = $self->_http->request('HEAD', $dir->{newNonce});
    _ok_or_die($self, 'newNonce', $res);
    my $n = $res->{headers}{'replay-nonce'};
    die "acme: newNonce returned no Replay-Nonce\n" unless defined $n && length $n;
    return $n;
}

sub _absorb_nonce ($self, $res) {
    my $n = $res->{headers}{'replay-nonce'};
    $self->nonce($n) if defined $n && length $n;
    return;
}

# ── errors (RFC 8555 §6.7, problem+json) ────────────────────────────────────

sub _ok_or_die ($self, $what, $res) {
    my $st = $res->{status} // 0;
    return if $st >= 200 && $st < 300;
    my $detail = $res->{content} // '';
    if (my $d = eval { _decode($detail) }) {
        $detail = join ' ', grep { defined && length } ($d->{type}, $d->{detail});
    }
    $detail =~ s/\s+$//;
    die "acme: $what: HTTP $st $detail\n";
}

# ── helpers ─────────────────────────────────────────────────────────────────

sub _decode ($text) { return JSON::PP->new->utf8->decode($text // '') }

sub _b64url ($bytes) {
    my $b = MIME::Base64::encode_base64($bytes // '', '');
    $b =~ s{\+}{-}g;
    $b =~ s{/}{_}g;
    $b =~ s/=+$//;
    return $b;
}

sub _log ($self, $msg) {
    my $l = $self->log or return;
    if    ($l->can('info')) { $l->info("[acme] $msg") }
    elsif ($l->can('warn')) { $l->warn("[acme] $msg") }
    return;
}

1;
