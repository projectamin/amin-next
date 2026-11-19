package Amin::Filter::Acme;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'XML::SAX::Base';

use Class::Tiny qw(Handler Log Mode Name Element key directory contact), {
    # Swallow depth (an auto-accessor: handled by the generated `_depth`).
    _depth => 0,
};

use Amin::Acme::Key;
use Amin::Acme::Client;

# ── the ACME filter (RFC 8555, HTTP-01), at the app level ────────────────────
#
# ACME is NOT a proxy concern (proxy-plan §5.5): the front only ever sees an
# already-provisioned cert/key.  It is a *filter* the app declares in its own
# machine_spec.xml, so it is dealt with at the app level — the same place the
# bundle's other filters live — and never at the proxy level.
#
# It is "Responder + RFC 8555 client", two halves of one capability:
#
#   <amin:acme-challenge token="{token}"/>   the Responder
#       The CA fetches http://<domain>/.well-known/acme-challenge/<token> and
#       expects `token "." thumbprint(account key)` (RFC 8555 §8.1).  The route
#       that carries this element declares type="text/plain", so the emitted
#       characters ARE the body — byte-exact, unwrapped, unescaped (the route's
#       media type is a property of the route, not of this or any filter).  The
#       key authorization is a pure function of the account key, so the
#       responder holds no per-challenge state: given the key it answers any
#       token the CA issues.
#
#   <amin:acme-order domain="…" cert="…" key="…"/>   the client
#       Drives issuance for a name the operator already serves: order, trigger
#       each HTTP-01 challenge the Responder is already answering, finalize with
#       a CSR, and write the returned PEM chain to `cert`.  The certificate key
#       at `key` is made if absent.  Every step is an RFC 8555 POST-as-GET/JWS
#       over the account key (Amin::Acme::Client), signed with the openssl CLI.
#
# Both bind the machine's own profile namespace because that namespace is the
# one every profile declares (the response envelope only binds `amin`), so a
# fragment carrying one of these elements needs no namespace declaration of its
# own and reconstructs identically in the Perl and Rust fronts (§7).
#
# It is `middle`, element-scoped: the dispatcher splices one instance in as the
# element's start flows through and un-splices it at the matching end, so the
# element never reaches the serialiser — only what this filter emits does.

use constant AMIN_NS => 'http://projectamin.org/ns/2026/';

# ── the element contract ─────────────────────────────────────────────────────
sub start_element ($self, $el) {
    # Nesting: an instance owns exactly its trigger element.  Anything inside it
    # is swallowed, so no fragment content can leak past the responder.
    if ($self->_depth) { $self->_depth($self->_depth + 1); return }
    return $self->SUPER::start_element($el) unless ($el->{NamespaceURI} // '') eq AMIN_NS;
    $self->_depth(1);
    my $ln = $el->{LocalName} // $el->{Name} // '';
    if    ($ln eq 'acme-challenge') { $self->_challenge($el) }
    elsif ($ln eq 'acme-order')     { $self->_order($el) }
    else { $self->SUPER::start_element($el) }
    return;
}

sub end_element ($self, $el) {
    if ($self->_depth) { $self->_depth($self->_depth - 1); return }
    return $self->SUPER::end_element($el);
}

sub characters ($self, $c) {
    return if $self->_depth;
    return $self->SUPER::characters($c);
}

sub start_document ($self, @a) { return $self->SUPER::start_document(@a) }
sub end_document   ($self, @a) { return $self->SUPER::end_document(@a) }

# ── Responder: the HTTP-01 key authorization ─────────────────────────────────
sub _challenge ($self, $el) {
    my %a = _attrs($el);
    my $token = $a{token} // '';
    my $ka    = $self->_acme_key->key_authorization($token);
    $self->Handler && $self->Handler->characters({ Data => $ka });
    return;
}

# The account key, built once from the spec's `key` path.  A missing or
# malformed key is a misconfiguration and dies here (fail-fast, → 500) rather
# than answering an empty body that would look like a wrong authorization.
sub _acme_key ($self) {
    return $self->{_account} //= do {
        my $path = $self->key;
        die "acme: no account key configured for the filter\n"
            unless defined $path && length $path;
        Amin::Acme::Key->new(path => $path);
    };
}

# ── client: drive issuance for a served name ─────────────────────────────────
sub _order ($self, $el) {
    my %a = _attrs($el);
    my $domain = $a{domain} // '';
    my $cert   = $a{cert}   // '';
    my $keyp   = $a{key}    // '';
    die "acme: <amin:acme-order> needs domain, cert and key\n"
        unless length $domain && length $cert && length $keyp;

    my $contact = $self->contact;
    my $client  = Amin::Acme::Client->new(
        directory => $self->directory,
        key       => $self->key,
        log       => $self->Log,
        contact   => defined $contact && length $contact ? [ split /,/, $contact ] : [],
    );
    my $pem = $client->issue([$domain], $keyp);
    _write($cert, $pem, 0644);
    $self->Handler && $self->Handler->characters(
        { Data => "issued $domain -> $cert\n" });
    return;
}

# ── helpers ──────────────────────────────────────────────────────────────────
sub _attrs ($el) {
    my %a;
    for my $k (keys %{ $el->{Attributes} // {} }) {
        my $at = $el->{Attributes}{$k} // next;
        my $n  = $at->{LocalName} // $at->{Name};
        $a{$n} = $at->{Value} // '' if defined $n && length $n;
    }
    return %a;
}

sub _write ($path, $bytes, $mode) {
    open(my $fh, '>:raw', $path) or die "acme: write $path: $!\n";
    print {$fh} $bytes;
    close $fh;
    chmod $mode, $path;
    return;
}

1;
