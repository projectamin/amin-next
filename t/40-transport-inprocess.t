use v5.38; use warnings; use strict; use utf8;
use Test2::V0;

use lib 'perl-lib';

use Amin::Mesh::Transport::InProcess;

# ── TR-4.1: single-peer dispatch → SpawnHandle → poll_stream returns valid stream ──
{
    my $tr = Amin::Mesh::Transport::InProcess->new;
    my @h = $tr->dispatch_spawn_remote(['peer-a-001'], '<test bsax bytes here', {});
    is(scalar(@h), 1, 't40 TR-4.1: single dispatch returns 1 SpawnHandle');
    my $h = $h[0];
    ok($h && ref($h) =~ /SpawnHandle/, 't40 TR-4.1: handle isa SpawnHandle');
    is($h->peer_id, 'peer-a-001', 't40 TR-4.1: handle peer_id matches dispatched id');
    ok($h->can('poll_stream'), 't40 TR-4.1: handle can poll_stream');
    ok($h->can('cancel'),      't40 TR-4.1: handle can cancel');
    ok(defined $h->child_pid,  't40 TR-4.1: handle child_pid present');
    ok(defined $h->rx_pipe,         't40 TR-4.1: handle rx_pipe open');

    # loop waiting for child to write (up to 2s)
    my $deadline = time + 2;
    my $buf = '';
    while (time <= $deadline) {
        my $b = $h->poll_stream(8192);
        if (defined $b && length($b)) { $buf .= $b; last if index($buf, 'exit_kind="ok"') >= 0; }
        select(undef, undef, undef, 0.01);
    }
    like($buf, qr{<amin:result[^>]*kind="running"},
        't40 TR-4.1: stream contains <result kind=running> from child pipe');
    like($buf, qr{<amin:status[^>]*exit_kind="ok"},
        't40 TR-4.1: stream contains <status exit_kind=ok terminal success');
    like($buf, qr{peer="peer-a-001"},
        't40 TR-4.1: stream contains correct peer attribute in result');

    is($tr->dispatch_count, 1, 't40 TR-4.1: transport dispatch_count == 1');
    is($tr->last_dispatched, ['peer-a-001'], 't40 TR-4.1: last_dispatched matches ids');
}

# ── TR-4.2: 3-handle parallel dispatch ──
{
    my $tr = Amin::Mesh::Transport::InProcess->new;
    my @ids = (qw(node-aaa node-bbb node-ccc));
    my @h = $tr->dispatch_spawn_remote(\@ids, 'bsax-bytes-xyz',
        { simulated_delay => { 'node-bbb' => 50 } });
    is(scalar(@h), 3, 't40 TR-4.2: 3 dispatch returns 3 handles');
    is($tr->dispatch_count, 3, 't40 TR-4.2: dispatch_count == 3');
    is($tr->last_dispatched, \@ids, 't40 TR-4.2: last_dispatched all 3 ids');

    my @pids = map { $_->child_pid } @h;
    is(scalar(grep { $_ > 0 } @pids), 3, 't40 TR-4.2: 3 distinct child pids present');

    # cancel second and third handles → mark cancelled
    my $ok1 = $h[1]->cancel;
    my $ok2 = $h[2]->cancel;
    ok($ok1, 't40 TR-4.2: cancel handle 1 returns truthy');
    ok($ok2, 't40 TR-4.2: cancel handle 2 returns truthy');
    # idempotent: second cancel returns nothing but must not die
    eval { $h[1]->cancel; 1 };
    is($@, '', 't40 TR-4.2: idempotent cancel (2nd call does not die');
    # poll_stream on cancelled handles → undef
    is($h[1]->poll_stream, undef, 't40 TR-4.2: cancelled handle poll_stream returns undef');
    is($h[2]->poll_stream, undef, 't40 TR-4.2: cancelled handle poll_stream returns undef');

    # first handle still alive, wait for its stream
    my $deadline = time + 2;
    my $buf = '';
    while (time <= $deadline) {
        my $b = $h[0]->poll_stream(4096);
        if (defined $b && length($b)) { $buf .= $b; last if index($buf, '<amin:status') >= 0; }
        select(undef, undef, undef, 0.01);
    }
    like($buf, qr/node-aaa/, 't40 TR-4.2: live node-aaa stream in remaining handle');

    # clean up remaining handle
    $h[0]->cancel;
    is($h[0]->poll_stream, undef, 't40 TR-4.2: cleanup cancel handle 0 -> cancelled');
    # clean up zombie children via waitpid (shouldn't be any but safe)
    { local $?; waitpid($_, 0) for grep { defined } @pids; }
}

done_testing;
