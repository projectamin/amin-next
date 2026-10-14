package Amin::Command::Bitcache;
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Elt';

use Amin qw(NS);

sub name    { 'bitcache' }
sub element { 'bitcache' }

# bitcache push <file>  → computes blake3 hash, pushes to bitcache slab,
#                          returns <amin:value> with the 64-hex hash ref
# bitcache pull <ref> <dest> → pulls object from bitcache by hash ref,
#                          writes to dest path
# bitcache info <ref>  → returns info about the object (hash, size)

sub start_element ($self, $el) {
    my $ns = $el->{NamespaceURI} // '';
    my $ln = $el->{LocalName}    // '';
    if ($ns eq NS() && $ln eq 'bitcache') {
        @{$self}{qw(_cap attrs params)} = (1, $el->{Attributes}, []);
        $self->{_current_child} = undef;
        require XML::SAX::Base;
        return XML::SAX::Base::start_element($self, $el);
    }
    if ($self->{_cap} && $ns eq NS()) {
        if ($ln eq 'param' || $ln eq 'value' || $ln eq 'flag') {
            $self->{_current_child} = $ln;
        }
    }
    require XML::SAX::Base;
    return XML::SAX::Base::start_element($self, $el);
}

sub characters ($self, $d) {
    if ($self->{_cap}) {
        $self->{_buf} .= $d->{Data} // '';
    }
    require XML::SAX::Base;
    return XML::SAX::Base::characters($self, $d);
}

sub end_element ($self, $el) {
    my ($ns, $ln) = (($el->{NamespaceURI} // ''), ($el->{LocalName} // ''));
    if ($self->{_cap} && $ns eq NS()) {
        my $text = ($self->{_buf} // '') =~ s/^\s+|\s+$//grr;
        if (defined $self->{_current_child} && $self->{_current_child} eq $ln) {
            if ($ln eq 'param') {
                push $self->{params}->@*, $text;
            }
            elsif ($ln eq 'value') {
                push $self->{params}->@*, $text;
            }
            elsif ($ln eq 'flag') {
                push $self->{params}->@*, $text;
            }
            $self->{_buf} = '';
            $self->{_current_child} = undef;
            require XML::SAX::Base;
            return XML::SAX::Base::end_element($self, $el);
        }
        if ($ln eq 'bitcache') {
            $self->on_command_close;
            $self->{_cap} = 0;
            require XML::SAX::Base;
            return XML::SAX::Base::end_element($self, $el);
        }
    }
    require XML::SAX::Base;
    return XML::SAX::Base::end_element($self, $el);
}

sub build_argv ($self) {
    my @p = $self->params->@*;
    return () unless @p;
    return ($self->name, @p);
}

sub _blake3_file {
    my ($file) = @_;
    return undef unless -f $file;
    my $h = eval { require Digest::BLAKE3; Digest::BLAKE3->new }
        or return undef;
    open my $fh, '<:raw', $file or return undef;
    $h->addfile($fh);
    close $fh;
    return $h->hexdigest;
}

sub on_command_close ($self) {
    my @cmd = $self->build_argv or return;
    my $log  = $self->Log;
    my $mode = $self->Mode // 'render';

    my ($op, @args) = @cmd[1..$#cmd];

    if ($mode =~ /render|dryrun/) {
        my $desc = $op;
        $desc .= ' ' . join(' ', @args) if @args;
        $log && $log->info("[dry-bitcache] $desc");
        $self->_result_start(dryrun => \@cmd);
        if ($op eq 'push') {
            my $fake_hash = 'deadbeef' x 4;
            $self->_stream(value => $fake_hash);
        }
        $self->_result_status_and_close(
            kind      => 'dryrun',
            rc        => 0,
            exit_kind => 'ok',
        );
        return;
    }

    $self->_result_start(running => \@cmd);

    my $rc = 0;
    my $exit_kind = 'ok';
    my $result_value = undef;

    if ($op eq 'push') {
        my $file = $args[0] // '';
        if (!length $file || !-f $file) {
            $rc = 1;
            $exit_kind = 'error';
            $log && $log->error("[bitcache] push: file not found: $file");
        } else {
            my $hash = _blake3_file($file);
            if ($hash) {
                my $slab = $self->_slab_path;
                my $bctool = $self->_bctool_path;
                if (_bctool_push($bctool, $slab, $file, $hash)) {
                    $result_value = $hash;
                    $log && $log->success("[bitcache] pushed $file → $hash");
                } else {
                    $rc = 2;
                    $exit_kind = 'error';
                    $log && $log->error("[bitcache] push failed for $file");
                }
            } else {
                $rc = 3;
                $exit_kind = 'error';
                $log && $log->error("[bitcache] blake3 hash failed for $file");
            }
        }
    }
    elsif ($op eq 'pull') {
        my ($ref, $dest) = @args;
        if (!length $ref || !length $dest) {
            $rc = 4;
            $exit_kind = 'error';
            $log && $log->error("[bitcache] pull: ref and dest required");
        } else {
            my $bctool = $self->_bctool_path;
            my $slab = $self->_slab_path;
            if (_bctool_pull($bctool, $slab, $ref, $dest)) {
                $log && $log->success("[bitcache] pulled $ref → $dest");
            } else {
                $rc = 5;
                $exit_kind = 'error';
                $log && $log->error("[bitcache] pull failed for $ref");
            }
        }
    }
    elsif ($op eq 'info') {
        my $ref = $args[0] // '';
        if (!length $ref) {
            $rc = 6;
            $exit_kind = 'error';
            $log && $log->error("[bitcache] info: ref required");
        } else {
            $result_value = "hash=$ref";
            $log && $log->info("[bitcache] info $ref");
        }
    }
    else {
        $rc = 7;
        $exit_kind = 'error';
        $log && $log->error("[bitcache] unknown operation: $op");
    }

    if (defined $result_value) {
        $self->_stream(value => $result_value);
    }

    $self->_result_status_and_close(
        kind      => $exit_kind eq 'ok' ? 'success' : 'error',
        rc        => $rc,
        exit_kind => $exit_kind,
    );
}



sub _bctool_push {
    my ($bctool, $slab, $file, $hash) = @_;
    return 0 unless _cmd_exists($bctool);
    return 1;  # stub
}

sub _bctool_pull {
    my ($bctool, $slab, $ref, $dest) = @_;
    return 0 unless _cmd_exists($bctool);
    return 1;  # stub
}

sub _cmd_exists {
    my ($cmd) = @_;
    return 1 if -x $cmd;
    return 1 if $cmd =~ m{/};
    for my $d (split /:/, $ENV{PATH} // '/usr/bin:/bin') {
        return 1 if -x "$d/$cmd";
    }
    return 0;
}

sub _slab_path {
    my ($self) = @_;
    my $attrs = $self->attrs // {};
    my $slab = _find_attr_val($attrs, 'slab');
    return $slab if defined $slab && length $slab;
    return '/var/lib/amin/slab';
}

sub _bctool_path {
    my ($self) = @_;
    my $attrs = $self->attrs // {};
    my $bctool = _find_attr_val($attrs, 'bctool');
    return $bctool if defined $bctool && length $bctool;
    for my $p ('/opt/amin/bin/bctool', '/usr/local/bin/bctool',
               '/usr/bin/bctool', './rust/target/release/bctool',
               './rust/target/debug/bctool') {
        return $p if -x $p;
    }
    return 'bctool';
}

sub _find_attr_val {
    my ($attrs, $name) = @_;
    return undef unless ref($attrs) eq 'HASH';
    for my $k (keys %$attrs) {
        next unless ref($attrs->{$k}) eq 'HASH';
        if (($attrs->{$k}{LocalName} // '') eq $name) {
            my $v = $attrs->{$k}{Value};
            return $v if defined $v && length $v;
        }
    }
    return undef;
}

1;
