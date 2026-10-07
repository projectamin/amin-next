package Amin::Cond::OS;
use v5.38; use warnings; use utf8;
use experimental qw(signatures for_list);
use parent 'XML::SAX::Base';

use Amin qw(NS);
use Class::Tiny qw(Log), { _bypass_lvl => 0, _name => undef };

my %MAP = (
    linux   => 'linux',   freebsd => 'freebsd', openbsd => 'openbsd',
    darwin  => 'darwin',  ios     => 'ios',     illumos => 'solaris',
    netbsd  => 'netbsd', android => 'android',
    posix   => sub () { 1 },
);
sub _resolve_os {
    my $env = $ENV{AMIN_OSTYPE};
    if (length($env) && exists $MAP{$env} && !ref($MAP{$env})) { return $env }
    my $o = $^O; $o =~ s/gnu//;
    (grep { !ref($MAP{$_}) && $MAP{$_} eq $o } keys %MAP)[0] // 'posix';
}
sub _this_os ($self) {
    $self->{_this_os} //= _resolve_os();
}

sub _is_os_tag ($el) {
    ($el->{NamespaceURI}//'') eq NS() && exists $MAP{$el->{LocalName}}
}

sub start_element ($self, $el) {
    my $lvl = \($self->{_bypass_lvl});
    if (!$$lvl && _is_os_tag($el)) {
        my $branch = $el->{LocalName};
        my $this_os = $self->_this_os;
        my $ok = ref($MAP{$branch}) eq 'CODE' ? $MAP{$branch}->()
                                              : ($MAP{$branch}//'') eq $this_os;
        unless ($ok) {
            $$lvl = 1; $self->{_name} = $branch;
            $self->Log && $self->Log->info("[cond os] $branch: BYPASS");
            return;
        }
        $self->Log && $self->Log->info("[cond os] $branch: ENTER (os=$this_os)");
        return $self->SUPER::start_element($el);
    } elsif ($$lvl && _is_os_tag($el)) {
        $$lvl++;
        return;
    }
    return $$lvl ? () : $self->SUPER::start_element($el);
}

sub end_element ($self, $el) {
    my $lvl = \($self->{_bypass_lvl});
    if ($$lvl && _is_os_tag($el)) {
        $$lvl--;
        $self->{_name} = undef unless $$lvl;
        return;
    }
    return $$lvl ? () : $self->SUPER::end_element($el);
}

for my $m (qw(characters processing_command comment ignorable_whitespace)) {
    no strict 'refs';
    *$m = sub ($self, @a) {
        return () if $self->{_bypass_lvl};
        my $sup = "SUPER::$m"; $self->$sup(@a);
    };
}

1;
