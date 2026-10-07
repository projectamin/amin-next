package Amin::Elt;
use v5.38; use warnings; use utf8;
use experimental qw(signatures for_list);
use parent 'XML::SAX::Base';

use IPC::Run  qw(harness start finish);
use Amin     qw(NS);

use Class::Tiny qw(name element Handler Log Mode),
{ _cap => 0, _matched_name => undef, attrs => {}, params => [], flags => [],
  env => {}, dir => undef, _buf => '' };

sub start_element ($self, $el) {
    if (_mine($el) && _named($el, $self->name)) {
        @{$self}{qw(_cap _matched_name attrs params flags env dir _buf)} =
            (1, $el->{Attributes}{'{}name'}{Value} // $self->name // undef,
             $el->{Attributes}, [], [], {}, undef, '');
    } elsif ($self->{_cap} && _mine($el)) {
        my $name = $el->{Attributes}{'{}name'}{Value} // '';
        $self->{_last_child_name}{$el->{LocalName}} = $name;
        if ($el->{LocalName} eq 'shell') {
            my %sa;
            for my $kv (values $el->{Attributes}->%*) {
                next unless length($kv->{LocalName} // '');
                $sa{$kv->{LocalName}} = $kv->{Value};
            }
            $self->{_last_shell_attrs} = \%sa;
        }
    }
    return $self->SUPER::start_element($el);
}

sub characters ($self, $d) { $self->{_buf} .= $d->{Data} // '' if $self->{_cap};
    return $self->SUPER::characters($d); }

sub end_element ($self, $el) {
    my ($ns, $ln) = ($el->{NamespaceURI}//'', $el->{LocalName});

    if ($self->{_cap} && $ns eq NS()) {
        my $text = _trim($self->{_buf});
        my $cap_name = $self->{_last_child_name}{$ln} // '';

        for my $case (['param',  $self->{params}],
                      ['flag',   $self->{flags}]) {
            my ($tag, $list) = @$case;
            if ($ln eq $tag) { push @$list, $cap_name ? { $cap_name => $text } : $text;
                $self->{_buf}='';
                return $self->SUPER::end_element($el); }
        }

        if ($ln eq 'shell') {
            my $attrs = $self->{_last_shell_attrs} // {};
            while (my ($k, $v) = each %$attrs) {
                if    ($k eq 'dir')        { $self->{dir} = $v }
                elsif ($k =~ /^env_(.+)/)  { $self->{env}{$1} = $v }
                elsif ($k eq 'env')        {
                    my ($ek, $ev) = split /=/, $v, 2;
                    $self->{env}{$ek} = $ev if defined $ev;
                }
            }
            $self->{_buf} = '';
            return $self->SUPER::end_element($el);
        }

        if (_mine($el) && defined($self->{_matched_name})
            && (!defined($self->name) || $self->{_matched_name} eq $self->name)) {
            $self->execute;
            $self->{_cap} = 0; $self->{_matched_name} = undef;
            %{$self->{_last_child_name} //= {}} = ();
            return $self->SUPER::end_element($el);
        }
    }
    return $self->SUPER::end_element($el);
}

sub execute ($self) {
    my @cmd = $self->build_argv or return;

    if (($self->Mode // 'render') =~ /render|dryrun/) {
        $self->Log && $self->Log->info('[dry-run] ' . _q(@cmd));
        $self->_emit(dryrun => \@cmd, 0);
        return;
    }

    my $h = $self->Handler;
    $h && $self->_emit_start('running', \@cmd);

    my ($in, $out, $err) = ('', '', '');
    my $on_out = sub ($data, $sv) {
        length $data or return;
        $self->Log && $self->Log->info('[out] ' . _chomp($data));
        $h && $self->_stream(out => $data);
        $$sv .= $data;
    };
    my $on_err = sub ($data, $sv) {
        length $data or return;
        $self->Log && $self->Log->error('[err] ' . _chomp($data));
        $h && $self->_stream(err => $data);
        $$sv .= $data;
    };
    my $out_filter = _line_filter(\$out, $on_out);
    my $err_filter = _line_filter(\$err, $on_err);

    my $hrns = harness \@cmd, \$in, $out_filter, $err_filter,
        init => sub {
            $self->{_pid} = $$;
            chdir $self->{dir} if $self->{dir};
            while (my ($k,$v) = each $self->{env}->%*) { $ENV{$k} = $v }
        }, debug => 0;

    require Time::HiRes;
    my $t0 = [Time::HiRes::gettimeofday()];
    $self->{_pid}       = undef;
    $self->{_duration}  = undef;
    $self->{_exit_kind} = '';
    eval {
        start $hrns;
        if (ref $hrns && $hrns->{KIDS} && @{$hrns->{KIDS}}) {
            $self->{_pid} = $hrns->{KIDS}[0]{PID} if $hrns->{KIDS}[0]{PID};
        }
        finish $hrns;
    };
    $self->{_duration} = Time::HiRes::tv_interval($t0);
    my $rc = $? >> 8;
    my $ok = !$@ && $rc == 0;
    if    ($@)                     { $self->{_exit_kind} = 'exception' }
    elsif ($? & 127)               { $self->{_exit_kind} = 'signal'    }
    elsif ($rc != 0)                 { $self->{_exit_kind} = 'nonzero'   }
    else                             { $self->{_exit_kind} = 'ok'        }

    if ($self->Log) {
        my $msg = sprintf '[%s rc=%d] %s', $ok ? 'ok' : 'fail', $rc, _q(@cmd);
        $ok ? $self->Log->success($msg) : $self->Log->error($msg);
    }

    $h && $self->_emit_end($ok ? 'success' : 'error', $rc, \@cmd, $out, $err);
}

sub build_argv ($self) { () }

sub _mine ($e) { ($e->{NamespaceURI}//'') eq NS() }
sub _named ($e,$n) { !defined $n || ($e->{Attributes}{'{}name'}{Value}//'') eq $n }
sub _trim ($s)  { $s =~ s/^\s+|\s+$//gr }
sub _chomp ($s) { local $_ = $s; s/\s+\z//r }

sub _q (@s) {
    require String::ShellQuote;
    join ' ', map String::ShellQuote::shell_quote($_), @s;
}

sub _attrs ($hash) { +{ map {;
    "{}" . $_ => { Name => $_, LocalName => $_, Prefix => 'amin',
                   NamespaceURI => NS(), Value => defined $hash->{$_} ? "$hash->{$_}" : '' }
} keys %$hash } }

sub _line_filter ($sv, $cb) {
    my $buf = '';
    sub ($data, @) {
        if (!defined $data) {
            if (length $buf) { $cb->($buf, $sv); $buf = '' }
            return ();
        }
        $buf .= $data;
        while ((my $i = index $buf, "\n") >= 0) {
            my $line = substr $buf, 0, $i+1, '';
            $cb->($line, $sv);
        }
        return ();
    };
}

sub _emit_start ($self, $kind, $argv) {
    my $h = $self->Handler or return;
    $h->start_element({
        NamespaceURI => NS(), LocalName => 'result', Name => 'amin:result',
        Prefix => 'amin', Attributes => _attrs({ kind => $kind, rc => '' }) });
    $self->_stream(argv => _q(@$argv));
}

sub _stream ($self, $channel, $data) {
    my $h = $self->Handler or return;
    $h->start_element({
        NamespaceURI => NS(), LocalName => 'stream', Name => 'amin:stream',
        Prefix => 'amin', Attributes => _attrs({ channel => $channel }) });
    $h->characters({ Data => $data }) if length $data;
    $h->end_element({
        NamespaceURI => NS(), LocalName => 'stream', Name => 'amin:stream',
        Prefix => 'amin' });
}

sub _emit_end ($self, $kind, $rc, $argv, $out, $err) {
    my $h = $self->Handler or return;
    my %meta = ( kind => $kind, rc => $rc );
    $meta{pid}       = $self->{_pid}       if defined $self->{_pid};
    $meta{duration}  = sprintf('%.3f', $self->{_duration}) if defined $self->{_duration};
    $meta{exit_kind} = $self->{_exit_kind} if length($self->{_exit_kind} // '');
    $h->start_element({
        NamespaceURI => NS(), LocalName => 'status', Name => 'amin:status',
        Prefix => 'amin', Attributes => _attrs(\%meta) });
    $h->end_element({
        NamespaceURI => NS(), LocalName => 'status', Name => 'amin:status',
        Prefix => 'amin' });
    $h->end_element({
        NamespaceURI => NS(), LocalName => 'result', Name => 'amin:result',
        Prefix => 'amin' });
}

sub _emit ($self, $kind, $argv, $rc, $out='', $err='') {
    $self->_emit_start($kind, $argv);
    $self->_emit_end($kind, $rc, $argv, $out, $err);
}

1;
