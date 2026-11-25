package Amin::AI::Music::SettingsSave;
use v5.38;
use warnings;
use utf8;
use experimental 'signatures';
use parent 'Amin::AI::Music::Effect';
use Amin::AI::Music::Store;
use Amin::AI::Music::Catalog;

# <mu:settings-save provider= key= remove_key=/> — write provider.xml, then ask
# the machine to discover the provider's music models and cache them.  The key
# is an input to this element only: neither the result nor the page request
# carries it, and a discovery error is redacted before it becomes a notice.
sub apply ($self, $a) {
    my $saved = Amin::AI::Music::Store->save_provider(%$a);
    return $saved if $saved->{err};

    my $key = Amin::AI::Music::Store->key;
    my $res = Amin::AI::Music::Catalog->refresh(Amin::AI::Music::Store->provider);
    if ($res->{err}) {
        return { ok => 1, notice => 'Saved provider.xml — model discovery failed: '
            . _redact($res->{err}, $key) };
    }
    my $n = $res->{count} // 0;
    return { ok => 1, notice => 'Saved provider.xml. Found '
        . $n . ' music model' . ($n == 1 ? '' : 's') . '.' };
}

sub _redact ($s, $key) {
    $s //= '';
    $s =~ s/\Q$key\E/[key]/g if length $key;
    $s =~ s/\s+/ /g;
    return $s;
}

sub panel_on_error ($self) { 'settings' }

1;
