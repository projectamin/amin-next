#!/usr/bin/env perl
use v5.38; use warnings; use utf8;
use Test2::V0;
use File::Basename qw(dirname);
use lib dirname(__FILE__) . '/../perl-lib';

use Amin::Util::Fold qw(_vals _flags);

is(
    [_vals([{ target => '/tmp/a' }, { target => '/tmp/b' }, 'raw-str'], 'target')],
    ['/tmp/a', '/tmp/b', 'raw-str'],
    '_vals: extracts named values AND keeps bare strings (pass-through for raw params)'
);
is([_vals([], 'target')], [], '_vals empty list → empty');
is(
    [_vals([{ not_used => 'x' }, { other => 'y' }], 'target')],
    [],
    '_vals: HASHes without the key → dropped entirely from list (not even empty slot)'
);
is(
    [_vals([{ target => undef }, { target => 'ok' }], 'target')],
    ['ok'],
    '_vals drops undef-valued entries'
);

is(
    [_flags([qw(r f v)], ['r','f','v'])],
    ['-rfv'],
    'boolean short flags joined in single-dash group');

is(
    [_flags([qw(m p mode)], ['p', { mode => '0750' }])],
    ['-p', "--mode=0750"],
    'long name mode → --mode=V; short name p grouped');
is(
    [_flags(['m'], [{ m => '0750' }])],
    ['-m0750'],
    'short char m with value → "-m<value>" concatenated');

is(
    [_flags([qw(recursive dry-run)], [{ recursive => undef }, { 'dry-run' => 1 }])],
    ['--recursive', '--dry-run=1'],
    'long boolean → --X; long valued → --X=V');

is(
    [_flags([qw(r f)], ['r', { mode => '0700' }, { verbose => undef }, { 'chroot' => '/mnt' }])],
    ['-r'],
    '_flags drops names NOT in allowed-list (no mode/verbose/chroot appear, only r)');

is([_flags([], [])], [], '_flags no flags → empty list');

done_testing;
