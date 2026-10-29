#!/usr/bin/env perl
# The off-heap store adapter.
#
# This exists because a prefork worker pool gives every forked worker its own
# copy of any in-process hash: request A lands on worker 1, request B on
# worker 2, and B has never seen A's write.  So the adapter has to satisfy two
# things — the same get/set/delete contract as Amin::AXA::Store, and real
# visibility of one process's writes to another process.
#
# It also has to survive the handle-DBD::SQLite explicitly warns about: a
# connection opened before fork must not be reused after it.
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use File::Temp qw(tempdir);
use Path::Tiny qw(path);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::AXA::Store;
use Amin::AXA::Store::SQLite;

my $tmp  = tempdir(CLEANUP => 1);
my $db   = "$tmp/axa.sqlite";
my $have = eval { require DBI; require DBD::SQLite; 1 };
plan skip_all => "DBD::SQLite not installed: $@" unless $have;

# ── contract: same behaviour as the in-memory adapter ───────────────────
my $mem = Amin::AXA::Store->new;
my $sql = Amin::AXA::Store::SQLite->new(path => $db);

is($sql->get('missing'), undef, 'get() on an unknown key returns undef');
is($mem->get('missing'), undef, '  (same as the in-memory adapter)');

$sql->set('s1', { csrf => 'tok', cart => { 'sku-1' => 2 } });
$mem->set('s1', { csrf => 'tok', cart => { 'sku-1' => 2 } });
is($sql->get('s1')->{cart}{'sku-1'}, $mem->get('s1')->{cart}{'sku-1'},
   'set/get round-trips a nested record');
is($sql->get('s1')->{csrf}, 'tok', 'sibling keys survive serialisation');

$sql->set('s2', { csrf => 't2', cart => {} });
is([ sort $sql->session_ids ], [ 's1', 's2' ], 'session_ids lists every key');

$sql->set('s1', { csrf => 'tok', cart => { 'sku-9' => 5 } });
is($sql->get('s1')->{cart}{'sku-9'}, 5, 'set() overwrites an existing record');
is($sql->get('s1')->{cart}{'sku-1'}, undef, '  and the old value is gone, not merged');

$mem->update('s1', sub ($rec) {
    $rec->{cart}{'sku-9'} = ($rec->{cart}{'sku-9'} // 0) + 1;
    return $rec;
});
is($mem->get('s1')->{cart}{'sku-9'}, 1, 'in-memory update applies the callback');
is($mem->update('absent', sub ($rec) { return undef }), undef,
   'update returning undef does not create a key');
is($mem->get('absent'), undef, '  and the key is still absent');

$sql->delete('s2');
is([ $sql->session_ids ], [ 's1' ], 'delete() removes the record');
ok(!defined $sql->get('s2'), '  and it reads back as undef');

# unicode must survive the round trip (sqlite_unicode => 1)
$sql->set('u', { csrf => 'café ☕', cart => {} });
is($sql->get('u')->{csrf}, 'café ☕', 'unicode values survive serialisation');

# ── isolation: separate sids never bleed into each other ────────────────
$sql->set('a', { csrf => 'x', cart => { 'sku-1' => 1 } });
$sql->set('b', { csrf => 'y', cart => {} });
is($sql->get('b')->{cart}{''} // 0, 0, 'one session cannot see another session\'s cart');
ok(!exists $sql->get('b')->{cart}{'sku-1'}, '  (sku-1 is absent from session b)');

# ── the property that makes prefork viable: cross-process visibility ────
my $pid = fork();
die "fork failed: $!" unless defined $pid;
if ($pid == 0) {
    # a worker: its OWN handle, exactly as Starman's workers get
    my $w = Amin::AXA::Store::SQLite->new(path => $db);
    my $r = $w->get('a');
    $r->{cart}{'sku-77'} = 3;
    $w->set('a', $r);
    $w->disconnect;
    exit 0;
}
waitpid $pid, 0;
is($sql->get('a')->{cart}{'sku-77'}, 3, "a forked worker's write is visible to the parent");
is($sql->get('a')->{cart}{'sku-1'}, 1, '  and the pre-existing cart entry survived');

# ── DBD::SQLite warns a pre-fork handle must not be reused after fork ───
# The adapter re-opens on a pid change instead, so this must not corrupt.
my $stale_pid = fork();
die "fork failed: $!" unless defined $stale_pid;
if ($stale_pid == 0) {
    # reuse the PARENT's $sql object — the inherited handle
    my $r = $sql->get('a');
    $r->{cart}{'sku-88'} = 9;
    $sql->set('a', $r);
    $sql->disconnect;
    exit 0;
}
waitpid $stale_pid, 0;
is($sql->get('a')->{cart}{'sku-88'}, 9, 'an inherited handle reconnects instead of corrupting');
ok(defined $sql->get('a')->{csrf}, '  and the record is still readable');

# ── concurrent writers: WAL + busy_timeout must not error ───────────────
my @workers;
for my $n (1 .. 4) {
    my $p = fork();
    die "fork: $!" unless defined $p;
    if ($p == 0) {
        my $w = Amin::AXA::Store::SQLite->new(path => $db);
        for my $i (1 .. 25) {
            my $r = $w->get('a') // { csrf => 'x', cart => {} };
            $r->{cart}{"w$n"} = $i;
            $w->set('a', $r);
        }
        $w->disconnect;
        exit 0;
    }
    push @workers, $p;
}
waitpid $_, 0 for @workers;
my $after = $sql->get('a');
ok(defined $after && defined $after->{csrf}, '4 concurrent writers did not corrupt the record');
is(scalar(keys %{$after->{cart}}), scalar(keys %{$sql->get('a')->{cart}}),
   'cart reads back consistently after concurrent writes');

# ── update() does not drop increments under concurrent writers ──────────
# The lost-update bug: each worker get()s, adds one, set()s.  Without a
# transaction around both, the later set() replaces the earlier cart.
# This is the property Shop cart mutations rely on.
$sql->set('ctr', { n => 0 });
my @kids;
for (1 .. 4) {
    my $p = fork();
    die "fork: $!" unless defined $p;
    if ($p == 0) {
        my $w = Amin::AXA::Store::SQLite->new(path => $db);
        my $failed = !eval {
            for (1 .. 20) {
                $w->update('ctr', sub ($rec) {
                    $rec //= { n => 0 };
                    $rec->{n} = ($rec->{n} // 0) + 1;
                    return $rec;
                });
            }
            1;
        };
        warn $@ if $failed;
        $w->disconnect;
        exit($failed ? 1 : 0);
    }
    push @kids, $p;
}
my $kids_failed = 0;
for my $p (@kids) {
    waitpid $p, 0;
    $kids_failed++ if $?;
}
is($kids_failed, 0, 'concurrent update() calls all committed');
is($sql->get('ctr')->{n}, 80, 'no increment was lost to a raced write');

# ── a corrupt row is an invalid session, not an exception ───────────────
$sql->set('corrupt', { csrf => 'ok', cart => {} });
$sql->dbh->do('UPDATE axa_session SET record = ? WHERE sid = ?', undef, '{', 'corrupt');
my $warns = 0;
{
    local $SIG{__WARN__} = sub {
        $warns++ if $_[0] =~ /unreadable session record/;
    };
    my $got = eval { $sql->get('corrupt') };
    ok(!$@, 'corrupt record does not throw') or diag($@);
    is($got, undef, '  and it reads as an invalid session');
    $sql->dbh->do('UPDATE axa_session SET record = ? WHERE sid = ?', undef, '[]', 'corrupt');
    is($sql->get('corrupt'), undef, 'a non-hash record is invalid too');
}
is($warns, 2, 'each bad read is reported');
is($sql->get('s1')->{csrf}, 'tok', 'a bad row does not affect other sessions');

$sql->disconnect;
ok(!-e "$db-journal", 'no rollback journal left behind (WAL is active)');

done_testing;
