#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Command::Mkdir;
use Amin::Command::Echo;
use Amin::Command::Remove;

my %class = (
    Mkdir  => Amin::Command::Mkdir->new,
    Echo   => Amin::Command::Echo->new,
    Remove => Amin::Command::Remove->new,
);

my $m = $class{Mkdir};
$m->{params} = [{ target => '/a' }, { target => '/b/c' }];
$m->{flags}  = ['p', { mode => '0755' }];
is([$m->build_argv],
   [qw(mkdir -p --mode=0755 /a /b/c)],
   'Mkdir: 2 targets + -p (short) + --mode=0755 (long valued)');
$m->{params} = []; $m->{flags} = [];
is([$m->build_argv], [], 'Mkdir: no targets → empty argv');

my $e = $class{Echo};
$e->{params} = [{ text => 'hi' }, { text => 'world' }, 'rawtext'];
$e->{flags}  = ['e', 'n'];
is([$e->build_argv],
   [qw(echo -en hi world rawtext)],
   'Echo: combines named:text + raw params + e/n into one invocation');

my $r = $class{Remove};
$r->{params} = [{ target => '/tmp/x' }, { target => '/var/tmp/y' }];
$r->{flags}  = ['r', 'f'];
is([$r->build_argv],
   [qw(rm -rf /tmp/x /var/tmp/y)],
   'Remove: short flags r+f become -rf concatenated');
$r->{flags} = [{ recursive => undef }, { force => undef }, { verbose => undef },
               { not_in_allowed => 1 }];
is([$r->build_argv],
   ['rm', '--recursive', '--force', '/tmp/x', '/var/tmp/y'],
   'Remove: allowed long names kept; verbose/not_in_allowed dropped');
$r->{flags} = ['v', { recursive => undef }];
is([$r->build_argv],
   ['rm', '-v', '--recursive', '/tmp/x', '/var/tmp/y'],
   'Remove: short v flag IS allowed; becomes -v concatenated in short group');

is($class{Mkdir}->name,    'mkdir',  'Mkdir filter name');
is($class{Echo}->name,     'echo',   'Echo filter name');
is($class{Remove}->name,   'remove', 'Remove filter name');
is($class{Mkdir}->element, 'command','all 3 declare element=command');

done_testing;
