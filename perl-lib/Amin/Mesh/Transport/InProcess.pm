package Amin::Mesh::Transport;
use v5.38; use warnings; use utf8; use experimental 'signatures';

sub dispatch_spawn_remote ($self, $peer_ids, $bsax_bytes, $context = {}) { ... }

package Amin::Mesh::Transport::InProcess;
use v5.38; use warnings; use utf8; use experimental 'signatures';

use Class::Tiny qw(cancel_count dispatch_count last_dispatched),
{ _handles  => sub { +[] } };

use POSIX ();

sub dispatch_spawn_remote ($self, $peer_ids, $bsax_bytes, $context = {}) {
    $self->{dispatch_count} = ($self->{dispatch_count} // 0) + scalar(@$peer_ids);
    $self->{last_dispatched} = [@$peer_ids];
    my @handles;
    for my $pid (@$peer_ids) {
        push @handles, _spawn_handle($pid, $bsax_bytes, $context);
    }
    $self->{_handles} = \@handles;
    return @handles;
}

sub _spawn_handle ($peer_id, $bsax_bytes, $context) {
    pipe(my $rx, my $tx) or die "pipe: $!";
    binmode $_ for ($rx, $tx);
    my $delay_ms = $context->{simulated_delay}{$peer_id} // 0;
    my $extra    = $context->{extra_mark}{$peer_id}   // '';
    my $rc       = $context->{exit_rc}{$peer_id}       // 0;
    my $kind     = $rc == 0 ? 'ok' : 'nonzero';
    my $child_pid = fork() // die "fork: $!";
    if ($child_pid == 0) {
        close $rx;
        if ($delay_ms > 0) {
            require Time::HiRes;
            Time::HiRes::usleep($delay_ms * 1000);
        }
        (my $bsax_out = $bsax_bytes // '') =~ s/&/&amp;/g; $bsax_out =~ s/</&lt;/g; $bsax_out =~ s/>/&gt;/g;
        my $peer_attr = _safe_peer_attr($peer_id);
        my $out = '';
        $out .= qq{<?xml version="1.0"?>\n}
             .  qq{<amin:root xmlns:amin="http://projectamin.org/ns/2026/">}
             .  qq{<amin:result kind="running" id="s" peer="}._xml_esc($peer_attr).qq{">}
             .  qq{<amin:stream channel="pid">4242</amin:stream>}
             .  qq{<amin:stream channel="spawn">$bsax_out</amin:stream>}
             .  qq{<amin:stream channel="out">hello $extra</amin:stream>}
             .  qq{<amin:status rc="$rc" exit_kind="$kind"></amin:status>}
             .  qq{</amin:result>}
             .  qq{</amin:root>};
        syswrite($tx, $out);
        close $tx;
        POSIX::_exit(0);
    }
    close $tx;
    return Amin::Mesh::Transport::SpawnHandle->new(
        peer_id   => $peer_id,
        rx_pipe   => $rx,
        child_pid => $child_pid,
    );
}

sub _xml_esc ($s) {
    $s //= '';
    $s =~ s/&/&amp;/g; $s =~ s/</&lt;/g; $s =~ s/"/&quot;/g;
    return $s;
}

sub _safe_peer_attr ($peer_id) {
    # Binary node_ids (32-byte blake3 hashes, raw bytes) must be hex-encoded
    # to stay valid UTF-8 for XML::LibXML::SAX parse on reinject.  ASCII test
    # ids like "node-aaa" stay human-readable (matches t/40 assertions).
    if (defined $peer_id && length($peer_id) > 0) {
        if ($peer_id =~ /[^\x20-\x7E]/) {
            return unpack('H*', $peer_id);
        }
    }
    return $peer_id // '';
}

1;

package Amin::Mesh::Transport::SpawnHandle;
use v5.38; use warnings; use utf8; use experimental 'signatures';

use Class::Tiny qw(peer_id rx_pipe child_pid _cancelled);

sub poll_stream ($self, $max = 4096) {
    return undef if $self->{_cancelled};
    my $fh = $self->rx_pipe or return undef;
    my $rin = '';
    vec($rin, fileno($fh), 1) = 1;
    my $nfound = select($rin, undef, undef, 0);
    return '' if $nfound == 0;
    my $bytes_read = sysread($fh, my $buf, $max);
    return undef if !defined $bytes_read || $bytes_read == 0;
    return $buf;
}

sub cancel ($self) {
    return if $self->{_cancelled}++;
    if (my $pid = $self->child_pid) {
        kill 'TERM' => $pid;
        waitpid $pid, 0;
    }
    if (my $fh = $self->rx_pipe) { close $fh }
    return 1;
}

1;
