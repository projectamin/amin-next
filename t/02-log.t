#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Log::Standard;

my $l = Amin::Log::Standard->new(stderr => 0, color => 0);
is($l->error_count, 0, 'initial errors == 0');
is($l->warn_count,  0, 'initial warns  == 0');

$l->info('one');
is($l->error_count, 0, 'info does not bump errors');
is($l->warn_count,  0, 'info does not bump warns');

$l->success('ok-msg');
is($l->error_count, 0, 'success does not bump errors');

$l->warn('warn-msg');
is($l->warn_count,  1, 'warn bumps warn_count');
is($l->error_count, 0, 'warn does not bump errors');

$l->error('err-msg');
is($l->error_count, 1, 'error bumps error_count exactly once');
$l->error('err-2'); $l->error('err-3');
is($l->error_count, 3, 'error counter linear');

my $with_err = Amin::Log::Standard->new(stderr => 1, color => 0);
open(my $olderr, '>&', *STDERR) or die;
close STDERR; open(STDERR, '>', \my $devnull) or die;
my $got = $with_err->info('chain-test');
close STDERR; open(STDERR, '>&', $olderr) or die;
is(ref($got), 'Amin::Log::Standard', 'level methods return logger instance (chainable)');

open(my $olderr2, '>&', *STDERR) or die;
close STDERR; open(STDERR, '>', \my $buf) or die;
my $silent = Amin::Log::Standard->new(stderr => 0, color => 0);
$silent->info('A'); $silent->warn('B'); $silent->error('C'); $silent->success('D');
close STDERR; open(STDERR, '>&', $olderr2) or die;
is($buf // '', '', 'stderr=0 → nothing printed regardless of level');

done_testing;
