#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use Cwd        qw(abs_path);
use File::Temp qw(tempdir);
use lib dirname(__FILE__) . '/../perl-lib';

my $BCTOOL = abs_path(dirname(__FILE__) . '/../rust/target/debug/bctool');
unless (-x $BCTOOL) {
    skip_all "bctool binary not compiled; run `cargo build -p bitcache` first at ./rust";
}

require IPC::Run;
require Amin::Machine::MachineSpec;

sub bctool (@argv) {
    my ($in, $out, $err) = ('', '', '');
    my @rest = @argv;
    if (ref($argv[-1]) && ref($argv[-1]) eq 'SCALAR') { $in = ${ pop @argv } }
    my $h = IPC::Run::harness([$BCTOOL, @argv], \$in, \$out, \$err, debug => 0);
    IPC::Run::start($h); IPC::Run::finish($h);
    my $rc = $? >> 8;
    return ($rc, $out, $err);
}

sub parse_kv ($out) {
    my %kv;
    for my $ln (split /\n/, $out) {
        my ($k, $v) = split /\t/, $ln, 2;
        $kv{$k} = $v if defined $v;
    }
    return %kv;
}

my $BUNDLED_SPEC = abs_path(dirname(__FILE__)
    . '/../perl-lib/Amin/Machine/machine_spec.xml');
ok(-f $BUNDLED_SPEC, "bundled machine_spec.xml exists");

my $tmp  = tempdir(CLEANUP => 1);
my $slab = "$tmp/m.slab";
my $sk   = "$tmp/test.sk";

# ── 1. Put the bundled machine spec into the slab ──────────────────────────
open(my $fh, '<:raw', $BUNDLED_SPEC) or die "open $BUNDLED_SPEC: $!";
local $/;
my $spec_xml = <$fh>;
close $fh;

my ($rc, $out, $err) = bctool('put', '--slab', $slab, \$spec_xml);
is($rc, 0, 'put machine_spec.xml rc=0') or diag "stderr=$err";
my %kv = parse_kv($out);
my $hash = $kv{hash};
ok(defined $hash && length($hash) == 64, 'got 64-hex blake3 hash')
    or diag "out=$out";

# ── 2. Generate signing key + sign the object ──────────────────────────────
($rc, $out, $err) = bctool('genkey', '--name', 'test-signer', '--sk', $sk);
is($rc, 0, 'genkey rc=0') or diag "stderr=$err";
%kv = parse_kv($out);
my $vk = $kv{vk};
ok(defined $vk && length($vk) > 0, 'got VK from genkey');

($rc, $out, $err) = bctool('sign',
    '--slab', $slab, '--hash', $hash,
    '--name', 'test-signer', '--sk', $sk);
is($rc, 0, 'sign rc=0') or diag "stderr=$err";
%kv = parse_kv($out);
my $sig = $kv{sig};
my $ts  = $kv{timestamp};
ok(defined $sig && length($sig) > 0, 'got signature');
ok(defined $ts  && length($ts)  > 0, 'got timestamp');

# ═══════════════════════════════════════════════════════════════════════════
# Acceptance 1: Happy path — fetch + verify → allow-list populated
# ═══════════════════════════════════════════════════════════════════════════
subtest 'Happy path: bc_hash + valid signature → allow-list resolved' => sub {
    my $ms = Amin::Machine::MachineSpec->new(
        bc_hash      => $hash,
        slab_path    => $slab,
        bctool_path  => $BCTOOL,
        signer_name  => 'test-signer',
        signer_ts    => $ts,
        signer_vk    => $vk,
        signer_sig   => $sig,
    );
    my $spec = $ms->spec;
    ok(exists $spec->{allowed}{'Amin::Command::Echo'},
        'Echo filter present in Bitcache-loaded allow-list')
        or diag "allowed keys: " . join(',', sort keys $spec->{allowed}->%*);
    is($spec->{handler}{class}, 'Amin::Handler::Writer',
        'handler resolved from Bitcache spec');
    is($spec->{log}{class}, 'Amin::Log::Standard',
        'log resolved from Bitcache spec');
    is($spec->{generator}{class}, 'XML::LibXML::SAX',
        'generator resolved from Bitcache spec');
};

# ═══════════════════════════════════════════════════════════════════════════
# Acceptance 2: Tampered hash → fail-closed (deny-all, empty allowed)
# ═══════════════════════════════════════════════════════════════════════════
subtest 'Tamper hash → fail-closed deny-all' => sub {
    my $bad = $hash;
    substr($bad, 0, 1) = ($bad =~ /^[0-7]/) ? 'f' : '0';
    isnt($bad, $hash, 'hash actually mutated');
    my $ms = Amin::Machine::MachineSpec->new(
        bc_hash      => $bad,
        slab_path    => $slab,
        bctool_path  => $BCTOOL,
        signer_name  => 'test-signer',
        signer_ts    => $ts,
        signer_vk    => $vk,
        signer_sig   => $sig,
    );
    my $spec = $ms->spec;
    is(scalar keys $spec->{allowed}->%*, 0,
        'tampered hash → empty allow-list (deny-all)');
    ok(!exists $spec->{allowed}{'Amin::Command::Echo'},
        'Echo not allowed after hash tamper');
};

# ═══════════════════════════════════════════════════════════════════════════
# Acceptance 3: Tampered signature → fail-closed (deny-all)
# ═══════════════════════════════════════════════════════════════════════════
subtest 'Tamper signature → fail-closed deny-all' => sub {
    my $bad = $sig;
    substr($bad, 10, 1) = ($bad =~ /^.{10}[A-Z]/) ? 'a' : 'A';
    isnt($bad, $sig, 'signature actually mutated');
    my $ms = Amin::Machine::MachineSpec->new(
        bc_hash      => $hash,
        slab_path    => $slab,
        bctool_path  => $BCTOOL,
        signer_name  => 'test-signer',
        signer_ts    => $ts,
        signer_vk    => $vk,
        signer_sig   => $bad,
    );
    my $spec = $ms->spec;
    is(scalar keys $spec->{allowed}->%*, 0,
        'tampered sig → empty allow-list (deny-all)');
};

# ═══════════════════════════════════════════════════════════════════════════
# Acceptance 4: bc_hash set but signature params absent → fail-closed
# ═══════════════════════════════════════════════════════════════════════════
subtest 'Unsigned Bitcache spec → fail-closed deny-all' => sub {
    my $ms = Amin::Machine::MachineSpec->new(
        bc_hash      => $hash,
        slab_path    => $slab,
        bctool_path  => $BCTOOL,
    );
    my $spec = $ms->spec;
    is(scalar keys $spec->{allowed}->%*, 0,
        'missing signature params → deny-all');
};

# ═══════════════════════════════════════════════════════════════════════════
# Acceptance 5: No bc_hash → disk fallback works (bundled spec)
# ═══════════════════════════════════════════════════════════════════════════
subtest 'No bc_hash → disk fallback to bundled spec' => sub {
    my $ms = Amin::Machine::MachineSpec->new(
        bctool_path => $BCTOOL,
    );
    my $spec = $ms->spec;
    ok(exists $spec->{allowed}{'Amin::Command::Echo'},
        'Echo present via disk fallback');
    is($spec->{handler}{class}, 'Amin::Handler::Writer',
        'handler resolved from disk spec');
};

# ═══════════════════════════════════════════════════════════════════════════
# Acceptance 6: trust_anchor_dir VK resolution (sha256(name).vk)
# ═══════════════════════════════════════════════════════════════════════════
subtest 'trust_anchor_dir VK resolution by signer name' => sub {
    require Digest::SHA;
    require MIME::Base64;
    my $ta = "$tmp/trust";
    mkdir $ta or die "mkdir $ta: $!";
    my $vk_file = "$ta/" . Digest::SHA::sha256_hex('test-signer') . '.vk';
    open(my $vfh, '>:raw', $vk_file) or die "open $vk_file: $!";
    print $vfh MIME::Base64::decode_base64($vk);
    close $vfh;

    my $ms = Amin::Machine::MachineSpec->new(
        bc_hash         => $hash,
        slab_path       => $slab,
        bctool_path     => $BCTOOL,
        signer_name     => 'test-signer',
        signer_ts       => $ts,
        signer_sig      => $sig,
        trust_anchor_dir=> $ta,
    );
    my $spec = $ms->spec;
    ok(exists $spec->{allowed}{'Amin::Command::Echo'},
        'VK resolved from trust_anchor_dir → allow-list populated');
};

done_testing;
