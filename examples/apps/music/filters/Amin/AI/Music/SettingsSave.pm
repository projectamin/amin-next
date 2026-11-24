package Amin::AI::Music::SettingsSave;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use parent 'Amin::AI::Music::Effect';
use Amin::AI::Music::Store;

# <mu:settings-save provider= api= base= music= key= remove_key=/> — write
# provider.xml.  The key is an input to this element only: neither the result
# nor the page request carries it.
sub apply ($self, $a) { Amin::AI::Music::Store->save_provider(%$a) }
sub panel_on_error ($self) { 'settings' }

1;
