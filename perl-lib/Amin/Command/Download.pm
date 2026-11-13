package Amin::Command::Download;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Command::Pass';

use Amin::Util::Fold qw(_vals);

sub name { q{download} }

# The port of the legacy Amin::Download element into the 3.0 command model.
# A download is NOT a subprocess, so this filter overrides on_command_close
# (the hook Pass uses to call execute) and performs the fetch in-process; the
# argv plan exists only so dry-run renders what would be fetched.
#
# Params (legacy contract, unchanged):
#     uri   the location to fetch — may repeat, tried in order
#     alt   an alternate location, tried after the uris (may repeat)
#     file  the local path to write; if it already exists the fetch is
#           skipped, so a completed download is never repeated
sub build_argv ($self) {
    my ($uri)  = _vals($self->params, "uri");
    my ($file) = _vals($self->params, "file");
    return () unless defined $uri && length $uri;
    my @alt = _vals($self->params, "alt");
    return ("download", $uri, (map {"alt=$_"} @alt), "file=" . ($file // ''));
}

sub on_command_close ($self) {
    my @uri = _vals($self->params, "uri");
    my ($file) = _vals($self->params, "file");
    my @plan = $self->build_argv or return;

    my $log  = $self->Log;
    my $mode = $self->Mode // 'render';

    if ($mode =~ /render|dryrun/) {
        $log && $log->info('[dry-run] ' . join(' ', @plan));
        $self->_result_start(dryrun => \@plan);
        $self->_result_status_and_close(kind => 'dryrun', rc => 0, exit_kind => 'ok');
        return;
    }

    $self->_result_start(running => \@plan);

    if (!defined $file || !length $file) {
        $self->_on_failure($log, '[download] no file param');
        $self->_result_status_and_close(kind => 'error', rc => 2, exit_kind => 'error');
        return;
    }

    if (-e $file) {
        $log && $log->success("[download] $file already exists");
        $self->_result_status_and_close(kind => 'success', rc => 0, exit_kind => 'ok');
        return;
    }

    require HTTP::Tiny;
    my $ua = HTTP::Tiny->new(max_redirect => 5);
    my @try = (@uri, _vals($self->params, "alt"));

    my ($fetched, $err);
    for my $u (@try) {
        my $res = eval { $ua->mirror($u, $file) };
        if ($@)                    { $err = "$u: $@" }
        elsif ($res->{success})    { $fetched = $u; last }
        else                       { $err = "$u: $res->{status} $res->{reason}" }
        # a failed fetch leaves nothing usable behind — clear it so the next
        # alternate (or a later run) starts from a clean target
        unlink $file if -e $file;
        $log && $log->error("[download] $err; trying an alternate");
    }

    if (defined $fetched) {
        $log && $log->success("[download] $fetched -> $file");
        $self->_result_status_and_close(kind => 'success', rc => 0, exit_kind => 'ok');
    } else {
        $self->_on_failure($log, "[download] no uri available: $err");
        $self->_result_status_and_close(kind => 'error', rc => 1, exit_kind => 'error');
    }
    return;
}

1;

=head1 NAME

Amin::Command::Download - in-process fetch command for the build catalog.

=head1 DESCRIPTION

The 3.0 command-model port of the legacy C<Amin::Download> element.  Any
download needs a C<uri> (what to fetch) and a C<file> (where to write it);
optional C<alt> params give alternate locations tried when the earlier ones
fail.  A C<file> that already exists is left untouched (a completed download
is never repeated — delete a corrupted one to force a refetch).

The fetch is done in-process over HTTP::Tiny, not by spawning curl/wget, so
this filter overrides C<on_command_close> instead of C<build_argv>/execute.

=head1 XML

    <amin:command name="download">
      <amin:param name="uri">https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz</amin:param>
      <amin:param name="alt">https://mirror.example/pub/gnu/make/make-4.4.1.tar.gz</amin:param>
      <amin:param name="file">/var/tmp/adistro/src/make-4.4.1.tar.gz</amin:param>
    </amin:command>

=cut
