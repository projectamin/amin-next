package Amin::AXA::Session;
use v5.38; use warnings; use utf8;
use Digest::SHA qw(sha256_hex);
use Class::Tiny;

# Adapter-side session plumbing (plan §4.7 / §5.6): an opaque cookie id and
# a CSRF token.  Transport hygiene only — a session is never a principal;
# it selects which store record to attach to the principal a token proves.
# First pass: no ZCap binding over HTTP (anonymous browsing), so the CSRF
# token is what the cookie must present on mutations.

use constant COOKIE => 'axa_sid';

sub mint ($class) {
    my $sid  = sha256_hex(join '/', map { rand } 1 .. 4, $$, time(), rand());
    my $csrf = sha256_hex(join '/', map { rand } 1 .. 4, $sid, rand());
    return ($sid, $csrf);
}

sub cookie_sid ($class, $cookie_header) {
    for my $pair (split /;\s*/, $cookie_header // '') {
        my ($k, $v) = split /=/, $pair, 2;
        next unless defined $k && defined $v && $k eq COOKIE;
        return $v if $v =~ /^[0-9a-f]{64}$/;
    }
    return undef;
}

sub set_cookie ($class, $sid) {
    return COOKIE . "=$sid; Path=/; HttpOnly; SameSite=Lax";
}

1;
