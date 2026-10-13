package Amin::Util::MOTD;
use v5.38; use warnings; use utf8; use experimental 'signatures';

use Amin::Util::DahutQuotes;

sub random ($self = undef) {
    return Amin::Util::DahutQuotes->random_quote;
}

sub random_quote ($self = undef) {
    return Amin::Util::DahutQuotes->random_quote;
}

sub quotes ($self = undef) {
    return Amin::Util::DahutQuotes->all_quotes;
}

1;
