package Amin::Test::ZCapSign;

# ═══════════════════════════════════════════════════════════════════════════
# Sign real zcap.v1 tokens for trust-layer tests.
#
# The Perl layer (Amin::Auth::ZCap) is verify-only by design; issuance lives
# in the Rust toolchain (crates/bitcache `bctool zcap-token`, which signs the
# exact smsg the verifier recomputes).  These helpers therefore:
#
#   1. generate one ML-DSA-87 keypair per process via `bctool genkey`
#      (32-byte Seed SK file, 0600), raw VK bytes → registered as a ZCap
#      mesh trust anchor (register_trust_anchor);
#   2. issue signed tokens via `bctool zcap-token` using the caller's %
#      scope overrides (tiers, zones, netpols, quotas, tenant, ts);
#   3. support `vk_override` — splice a foreign VK over the embedded anchor
#      slot after signing (used to exercise unknown_kid, which fails before
#      any signature verification);
#   4. fall back to the legacy structural placeholder token when no bctool
#      binary is available (mirrors the "no crypto module" Case B used by
#      t/29) so suites keep a deterministic degraded path.
# ═══════════════════════════════════════════════════════════════════════════

use v5.38;
use warnings;
use utf8;
use experimental 'signatures';

use Exporter 'import';
our @ISA       = ('Exporter');
our @EXPORT_OK = qw(
    zcap_can_sign zcap_signed_token zcap_structural_token
    zcap_signer_keypair make_zcap_token
);

# ── locate bctool ───────────────────────────────────────────────────────────

sub _bctool_path {
    require Amin::ToolPaths;
    return Amin::ToolPaths::tool_bctool();
}

sub zcap_can_sign { return _bctool_path() ? 1 : 0 }

# ── one keypair per process, VK registered as a mesh trust anchor ──────────

sub zcap_signer_keypair {
    state $pair;
    return $pair if $pair;
    my $bctool = _bctool_path() or return undef;
    require File::Temp;
    my $dir = File::Temp::tempdir(CLEANUP => 1);
    my $sk  = "$dir/zcap-test.sk";
    _run_tool([ $bctool, 'genkey', '--name', 'amin-test-suite', '--sk', $sk ]);
    $sk = "$dir/zcap-test.sk" if -f "$dir/zcap-test.sk";
    # Dry-run token to learn the VK (bctool prints `vk\t<b64>`)
    my $out = _run_tool([ $bctool, 'zcap-token', '--sk', $sk,
        '--tenant', 't-probe', '--tier', 'probe-tier',
        '--max-redundancy', 1, '--vpc-quota', 1, '--memory-tier', 1 ]);
    my %kv = %{ _kv($out) };
    my $vk = $kv{vk} or die "zcap test signer: no vk from bctool";
    require MIME::Base64;
    require Amin::Auth::ZCap;
    my $vk_bytes = MIME::Base64::decode_base64($vk);
    Amin::Auth::ZCap->register_trust_anchor($vk_bytes);
    return $pair = { sk => $sk, vk_b64 => $vk, vk_bytes => $vk_bytes };
}

# minimal list-exec runner (never routes through a shell)
sub _run_tool ($cmd) {
    my $out = '';
    my $pid = open(my $fh, '-|', @$cmd) or die "zcap test signer: open @$cmd: $!";
    while (defined(my $l = <$fh>)) { $out .= $l }
    close($fh);
    die "zcap test signer: @$cmd failed with rc " . ($? >> 8)
        if $? != 0;
    return $out;
}

sub _kv ($out) {
    my %kv;
    for my $line (split /\n/, $out) {
        my ($k, $v) = split /\t/, $line, 2;
        next unless defined $k && defined $v;
        $kv{$k} = $v;
    }
    return \%kv;
}

# ── signed token ────────────────────────────────────────────────────────────

sub zcap_signed_token (%o) {
    my $key = zcap_signer_keypair() or die
        "zcap test signer: no bctool binary — cannot issue signed tokens";
    my $bctool = _bctool_path();
    die "zcap test signer: no bctool binary"
        unless $bctool;
    my @cmd = (
        $bctool, 'zcap-token', '--sk', $key->{sk},
        '--tenant',              $o{tenant_id}      // 't-tenant-signed',
        '--max-redundancy',      $o{max_redundancy} // 3,
        '--vpc-quota',           $o{vpc_quota}      // 4,
        '--memory-tier',         $o{memory_tier}    // 1,
        (defined $o{ts} ? ('--ts', $o{ts}) : ()),
        (map { ('--tier',   $_) } @{ $o{tiers}      // [] }),
        (map { ('--zone',   $_) } @{ $o{zones}       // [] }),
        (map { ('--netpol', $_) } @{ $o{netpols}     // [] }),
    );
    my %kv = %{ _kv(_run_tool(\@cmd)) };
    my $token = $kv{token} or die "zcap test signer: no token line";
    if (defined $o{vk_override}) {
        # splice a foreign VK over the embedded anchor slot (bytes 4627..).
        # The signature no longer matches — by design — but unknown_kid
        # verification fails BEFORE any signature check.
        require MIME::Base64;
        my $raw = MIME::Base64::decode_base64($token);
        substr($raw, 4627, 2592) = $o{vk_override};
        $token = MIME::Base64::encode_base64($raw, '');
    }
    return $token;
}

# ── legacy structural fallback (no crypto module / no bctool) ──────────────
# Same bytes the suites used before real signing existed: placeholder sig,
# all-zero VK, XOR scope hash.  t/29's Case B depends on this exact shape.

sub zcap_structural_token (%o) {
    use feature 'bitwise'; no warnings 'experimental::bitwise'; use bytes;
    my @tiers  = @{ $o{tiers}       // ['metal-32c', 'metal-16c'] };
    my @zones  = @{ $o{zones}       // ['us-east-1', 'us-west-2'] };
    my @netps  = @{ $o{netpols}     // ['vpc-a', 'vpc-b'] };
    my $max_r  = $o{max_redundancy} // 3;
    my $vpc_q  = $o{vpc_quota}      // 4;
    my $mem_t  = $o{memory_tier}    // 1;
    my $tenant = $o{tenant_id}      // 't-tenant-0123456789abc';
    my $ts     = $o{ts}             // 1735689600;
    my $vk     = $o{vk}             // ("\x00" x 2592);
    my $sig    = $o{sig}            // ("\xaa" x 4627);
    my $tier_data = join('', map { pack('v', length($_)) . $_ } @tiers);
    my $zone_data = join('', map { pack('v', length($_)) . $_ } @zones);
    my $netp_data = join('', map { pack('v', length($_)) . $_ } @netps);
    my $scope_buf = $tier_data . $zone_data . $netp_data
        . pack('C', $max_r) . pack('V', $vpc_q) . pack('C', $mem_t)
        . 'amin.zcap.v1';
    my $scope_hash = "\x00" x 32;
    for my $c (split //, $scope_buf) { $scope_hash ^.= ($c x int(32 / length($c) + 1)); }
    $scope_hash = substr($scope_hash, 0, 32);
    my $bytes = $sig . $vk . $scope_hash . pack('Q<', $ts)
        . pack('v', scalar @tiers) . pack('v', scalar @zones) . pack('v', scalar @netps)
        . pack('C', $max_r) . pack('V', $vpc_q) . pack('C', $mem_t)
        . pack('v', length($tenant)) . $tenant
        . $tier_data . $zone_data . $netp_data;
    require MIME::Base64;
    return MIME::Base64::encode_base64($bytes, '');
}

sub make_zcap_token (%o) {
    return zcap_can_sign() ? zcap_signed_token(%o) : zcap_structural_token(%o);
}

1;
