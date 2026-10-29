package Amin::AXA::Store::SQLite;
use v5.38; use warnings; use utf8;
use Class::Tiny {
    path => sub { 'axa-store.sqlite' },
    _dbh => undef,
    _pid => undef,
};
use DBI;
use JSON::PP ();

# The off-heap adapter behind the same get/set/delete/session_ids interface
# as Amin::AXA::Store (plan §4.7).  This is what makes a prefork worker pool
# viable: an in-process hash gives every forked worker its own cart, so a
# second request lands on a worker that has never seen the first one's writes.
#
# Fork safety is the whole design point.  A DBD::SQLite handle opened in the
# parent must not be reused after fork — its docs warn it can corrupt the
# database — so the connection is opened lazily and re-opened whenever the
# process id changes.  Starman's master loads the app before forking; each
# worker then gets its own handle on first use.
#
# SQLite is a single-writer database even in WAL mode, so: WAL for readers
# alongside the one writer, a busy_timeout so a contending worker waits
# instead of failing immediately, and synchronous=FULL so an acknowledged
# cart survives a crash.  update() is a short BEGIN IMMEDIATE around the
# read-modify-write; set() stays a single-statement upsert.

use constant TABLE => 'axa_session';

sub dbh ($self) {
    my $pid = $$;
    if (!$self->{_dbh} || ($self->{_pid} // -1) != $pid) {
        my $dbh = DBI->connect(
            "dbi:SQLite:dbname=$self->{path}", '', '',
            {
                RaiseError        => 1,
                PrintError        => 0,
                AutoCommit        => 1,
                sqlite_unicode    => 1,
                # BEGIN IMMEDIATE up front: a read-then-write cart update
                # would otherwise upgrade a lock mid-transaction and risk
                # SQLITE_BUSY after the fact.
                sqlite_use_immediate_transaction => 1,
            },
        ) or die "axa: cannot open session db '$self->{path}': $DBI::errstr\n";
        $dbh->do('PRAGMA journal_mode = WAL');
        $dbh->do('PRAGMA busy_timeout = 5000');
        $dbh->do('PRAGMA synchronous = FULL');
        $self->_ensure_schema($dbh);
        $self->{_dbh} = $dbh;
        $self->{_pid} = $pid;
    }
    return $self->{_dbh};
}

sub _ensure_schema ($self, $dbh) {
    $dbh->do(qq{
        CREATE TABLE IF NOT EXISTS } . TABLE . q{ (
            sid        TEXT PRIMARY KEY,
            record     TEXT NOT NULL,
            updated_at TEXT NOT NULL DEFAULT (datetime('now'))
        )
    });
    return;
}

sub get ($self, $key) {
    return undef unless defined $key;
    my ($json) = $self->dbh->selectrow_array(
        'SELECT record FROM ' . TABLE . ' WHERE sid = ?', undef, $key);
    return undef unless defined $json;
    # A torn or hand-edited row must not 500 the request.  Undef is the
    # same answer as a missing session: the caller mints a new one.
    my $rec = eval { JSON::PP::decode_json($json) };
    if ($@ || ref($rec) ne 'HASH') {
        warn "[axa] unreadable session record; treating it as invalid\n";
        return undef;
    }
    return $rec;
}

# Read-modify-write as one write transaction.  Two workers that each
# get(), edit, and set() will otherwise both read the old cart and the
# later set() will drop the earlier one.  BEGIN IMMEDIATE (see connect)
# takes the reserved lock up front, so the loser waits on busy_timeout
# and then reads the winner's commit.
sub update ($self, $key, $code) {
    die "axa: store key required\n" unless defined $key && length $key;
    my $dbh = $self->dbh;
    $dbh->begin_work;
    my $next;
    my $ok = eval {
        my $rec = $self->get($key);
        $next = $code->($rec);
        $self->set($key, $next) if defined $next;
        $dbh->commit;
        1;
    };
    unless ($ok) {
        my $err = $@ || "axa: store update failed\n";
        eval { $dbh->rollback } if !$dbh->{AutoCommit};
        die $err;
    }
    return $next;
}

sub set ($self, $key, $value) {
    die "axa: store key required\n" unless defined $key && length $key;
    my $json = JSON::PP::encode_json($value // {});
    $self->dbh->do(
        'INSERT INTO ' . TABLE . ' (sid, record, updated_at)
             VALUES (?,?,datetime(\'now\'))
         ON CONFLICT(sid) DO UPDATE SET
             record     = excluded.record,
             updated_at = excluded.updated_at',
        undef, $key, $json);
    return $value;
}

sub delete ($self, $key) {
    return unless defined $key;
    $self->dbh->do('DELETE FROM ' . TABLE . ' WHERE sid = ?', undef, $key);
    return;
}

sub session_ids ($self) {
    my $sth = $self->dbh->prepare('SELECT sid FROM ' . TABLE);
    $sth->execute;
    my @ids;
    while (my ($sid) = $sth->fetchrow_array) { push @ids, $sid }
    return @ids;
}

# Close explicitly so tests and shutdown do not depend on DESTROY timing.
sub disconnect ($self) {
    if ($self->{_dbh}) {
        local $@;
        eval { $self->{_dbh}->disconnect };
        $self->{_dbh} = undef;
        $self->{_pid} = undef;
    }
    return;
}

sub DESTROY ($self) { $self->disconnect }

1;
