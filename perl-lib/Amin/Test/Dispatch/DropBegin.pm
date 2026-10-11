package Amin::Test::Dispatch::DropBegin;

# Amin::Test::Dispatch::DropBegin — t/19 subtest 1 helper.
# Drops any start/end element whose LocalName matches $self->drop_local_name
# (default 'drop-me').  Filter-local $drop_count tracks how many times we
# suppressed an element; test asserts drop_count == 2 as stress guard.
use v5.38; use warnings; use utf8; use experimental 'signatures';
use parent 'Amin::Test::Handler';

use Class::Tiny qw(drop_local_name drop_count);

sub BUILD ($self, @) {
    $self->{drop_local_name} //= 'drop-me';
    $self->{drop_count} = 0;
    $self->label("DropBegin(local=$self->{drop_local_name})");
}

sub start_element ($self, $el) {
    my $ln = $el->{LocalName} // '';
    if ($ln eq $self->drop_local_name) {
        $self->{drop_count}++;
        return;
    }
    return $self->SUPER::start_element($el);
}

sub end_element ($self, $el) {
    my $ln = $el->{LocalName} // '';
    return if $ln eq $self->drop_local_name;
    return $self->SUPER::end_element($el);
}

1;
