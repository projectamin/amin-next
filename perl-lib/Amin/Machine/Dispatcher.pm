package Amin::Machine::Dispatcher;
use v5.38; use warnings; use utf8;
use experimental 'signatures';
use parent 'XML::SAX::Base';

use Amin qw(NS);
use Class::Tiny qw(Handler Log Mode), { chain => undef };

our %FILTERS;
our %RUNTIME_ALLOWED;
my $CATALOG_FROZEN = 0;

INIT { $CATALOG_FROZEN = 1 }

sub register ($pkg, $class, %meta) {
    my $pos = delete($meta{position}) // 'middle';
    push $FILTERS{$pos}->@*, { class => $class, meta => \%meta };
    $RUNTIME_ALLOWED{$class} = 1 if $CATALOG_FROZEN;
}

BEGIN {
    require Amin::Auth::ZCap;       __PACKAGE__->register('Amin::Auth::ZCap',
        element => undef,   namespace => NS(),                        position => 'begin');
    require Amin::Command::Pass;
    my @COMMANDS = (
        ["Amin::Command::Addr2line" => "addr2line"],
        ["Amin::Command::Ar" => "ar"],
        ["Amin::Command::As" => "as"],
        ["Amin::Command::Autoconf" => "autoconf"],
        ["Amin::Command::Automake" => "automake"],
        ["Amin::Command::Autoreconf" => "autoreconf"],
        ["Amin::Command::Awk" => "awk"],
        ["Amin::Command::Basename" => "basename"],
        ["Amin::Command::Bash" => "bash"],
        ["Amin::Command::Bc" => "bc"],
        ["Amin::Command::Bison" => "bison"],
        ["Amin::Command::Blkid" => "blkid"],
        ["Amin::Command::Brotli" => "brotli"],
        ["Amin::Command::Bunzip2" => "bunzip2"],
        ["Amin::Command::Bzcat" => "bzcat"],
        ["Amin::Command::Bzip2" => "bzip2"],
        ["Amin::Command::Cal" => "cal"],
        ["Amin::Command::Cargo" => "cargo"],
        ["Amin::Command::Cat" => "cat"],
        ["Amin::Command::Cc" => "cc"],
        ["Amin::Command::Cfdisk" => "cfdisk"],
        ["Amin::Command::Cfilt" => "c++filt"],
        ["Amin::Command::Check" => "check"],
        ["Amin::Command::Chgrp" => "chgrp"],
        ["Amin::Command::Chmod" => "chmod"],
        ["Amin::Command::Chown" => "chown"],
        ["Amin::Command::Chroot" => "chroot"],
        ["Amin::Command::Clang" => "clang"],
        ["Amin::Command::Clangxx" => "clang++"],
        ["Amin::Command::Cmake" => "cmake"],
        ["Amin::Command::Cmp" => "cmp"],
        ["Amin::Command::Column" => "column"],
        ["Amin::Command::Comm" => "comm"],
        ["Amin::Command::Cp" => "cp"],
        ["Amin::Command::Cpio" => "cpio"],
        ["Amin::Command::Cryptsetup" => "cryptsetup"],
        ["Amin::Command::Csplit" => "csplit"],
        ["Amin::Command::Curl" => "curl"],
        ["Amin::Command::Cut" => "cut"],
        ["Amin::Command::Cxx" => "c++"],
        ["Amin::Command::Dash" => "dash"],
        ["Amin::Command::Date" => "date"],
        ["Amin::Command::Dc" => "dc"],
        ["Amin::Command::Dd" => "dd"],
        ["Amin::Command::Dejagnu" => "dejagnu"],
        ["Amin::Command::Depmod" => "depmod"],
        ["Amin::Command::Df" => "df"],
        ["Amin::Command::Diff" => "diff"],
        ["Amin::Command::Dig" => "dig"],
        ["Amin::Command::Dirname" => "dirname"],
        ["Amin::Command::Dmesg" => "dmesg"],
        ["Amin::Command::Du" => "du"],
        ["Amin::Command::Dumpe2fs" => "dumpe2fs"],
        ["Amin::Command::Dwz" => "dwz"],
        ["Amin::Command::Echo" => "echo"],
        ["Amin::Command::Egrep" => "egrep"],
        ["Amin::Command::Env" => "env"],
        ["Amin::Command::Expand" => "expand"],
        ["Amin::Command::Expect" => "expect"],
        ["Amin::Command::Expr" => "expr"],
        ["Amin::Command::Factor" => "factor"],
        ["Amin::Command::False" => "false"],
        ["Amin::Command::Fdisk" => "fdisk"],
        ["Amin::Command::Fgrep" => "fgrep"],
        ["Amin::Command::File" => "file"],
        ["Amin::Command::Find" => "find"],
        ["Amin::Command::Flex" => "flex"],
        ["Amin::Command::Flock" => "flock"],
        ["Amin::Command::Fmt" => "fmt"],
        ["Amin::Command::Fold" => "fold"],
        ["Amin::Command::Free" => "free"],
        ["Amin::Command::Fsck" => "fsck"],
        ["Amin::Command::FsckExt4" => "fsck.ext4"],
        ["Amin::Command::Fuser" => "fuser"],
        ["Amin::Command::GObjectIntrospection" => "gobject-introspection"],
        ["Amin::Command::Gawk" => "gawk"],
        ["Amin::Command::Gcc" => "gcc"],
        ["Amin::Command::Gdb" => "gdb"],
        ["Amin::Command::Getconf" => "getconf"],
        ["Amin::Command::Getent" => "getent"],
        ["Amin::Command::Gettext" => "gettext"],
        ["Amin::Command::Gfortran" => "gfortran"],
        ["Amin::Command::Gnat" => "gnat"],
        ["Amin::Command::Gperf" => "gperf"],
        ["Amin::Command::Grep" => "grep"],
        ["Amin::Command::Groff" => "groff"],
        ["Amin::Command::Groups" => "groups"],
        ["Amin::Command::GtkDoc" => "gtk-doc"],
        ["Amin::Command::Gunzip" => "gunzip"],
        ["Amin::Command::Gxx" => "g++"],
        ["Amin::Command::Gzip" => "gzip"],
        ["Amin::Command::Head" => "head"],
        ["Amin::Command::Help2man" => "help2man"],
        ["Amin::Command::Host" => "host"],
        ["Amin::Command::Hostname" => "hostname"],
        ["Amin::Command::Htop" => "htop"],
        ["Amin::Command::Iconv" => "iconv"],
        ["Amin::Command::Id" => "id"],
        ["Amin::Command::Info" => "info"],
        ["Amin::Command::Insmod" => "insmod"],
        ["Amin::Command::Install" => "install"],
        ["Amin::Command::InstallInfo" => "install-info"],
        ["Amin::Command::Intltool" => "intltool"],
        ["Amin::Command::Ip" => "ip"],
        ["Amin::Command::Join" => "join"],
        ["Amin::Command::Kill" => "kill"],
        ["Amin::Command::Killall" => "killall"],
        ["Amin::Command::Ld" => "ld"],
        ["Amin::Command::Lex" => "lex"],
        ["Amin::Command::Libtool" => "libtool"],
        ["Amin::Command::Link" => "link"],
        ["Amin::Command::Ln" => "ln"],
        ["Amin::Command::Locale" => "locale"],
        ["Amin::Command::Localedef" => "localedef"],
        ["Amin::Command::Logger" => "logger"],
        ["Amin::Command::Logname" => "logname"],
        ["Amin::Command::Losetup" => "losetup"],
        ["Amin::Command::Ls" => "ls"],
        ["Amin::Command::Lsblk" => "lsblk"],
        ["Amin::Command::Lsmod" => "lsmod"],
        ["Amin::Command::Lsof" => "lsof"],
        ["Amin::Command::Lspci" => "lspci"],
        ["Amin::Command::Lsusb" => "lsusb"],
        ["Amin::Command::Ltrace" => "ltrace"],
        ["Amin::Command::Lua" => "lua"],
        ["Amin::Command::Lvcreate" => "lvcreate"],
        ["Amin::Command::Lvm" => "lvm"],
        ["Amin::Command::Lz4" => "lz4"],
        ["Amin::Command::Lzma" => "lzma"],
        ["Amin::Command::Lzop" => "lzop"],
        ["Amin::Command::M4" => "m4"],
        ["Amin::Command::Make" => "make"],
        ["Amin::Command::Makeinfo" => "makeinfo"],
        ["Amin::Command::Man" => "man"],
        ["Amin::Command::Mandoc" => "mandoc"],
        ["Amin::Command::Meson" => "meson"],
        ["Amin::Command::Mkdir" => "mkdir"],
        ["Amin::Command::Mkfs" => "mkfs"],
        ["Amin::Command::MkfsBtrfs" => "mkfs.btrfs"],
        ["Amin::Command::MkfsExt4" => "mkfs.ext4"],
        ["Amin::Command::MkfsXfs" => "mkfs.xfs"],
        ["Amin::Command::Mknod" => "mknod"],
        ["Amin::Command::Mkswap" => "mkswap"],
        ["Amin::Command::Mktemp" => "mktemp"],
        ["Amin::Command::Modprobe" => "modprobe"],
        ["Amin::Command::Mount" => "mount"],
        ["Amin::Command::Mountpoint" => "mountpoint"],
        ["Amin::Command::Msgfmt" => "msgfmt"],
        ["Amin::Command::Msgmerge" => "msgmerge"],
        ["Amin::Command::Mv" => "mv"],
        ["Amin::Command::Nawk" => "nawk"],
        ["Amin::Command::Nc" => "nc"],
        ["Amin::Command::Ncat" => "ncat"],
        ["Amin::Command::Nice" => "nice"],
        ["Amin::Command::Ninja" => "ninja"],
        ["Amin::Command::Nl" => "nl"],
        ["Amin::Command::Nm" => "nm"],
        ["Amin::Command::Node" => "node"],
        ["Amin::Command::Nohup" => "nohup"],
        ["Amin::Command::Nproc" => "nproc"],
        ["Amin::Command::Objcopy" => "objcopy"],
        ["Amin::Command::Objdump" => "objdump"],
        ["Amin::Command::Od" => "od"],
        ["Amin::Command::Parted" => "parted"],
        ["Amin::Command::Paste" => "paste"],
        ["Amin::Command::Patch" => "patch"],
        ["Amin::Command::Perf" => "perf"],
        ["Amin::Command::Perl" => "perl"],
        ["Amin::Command::Pgrep" => "pgrep"],
        ["Amin::Command::Ping" => "ping"],
        ["Amin::Command::PkgConfig" => "pkg-config"],
        ["Amin::Command::Pkill" => "pkill"],
        ["Amin::Command::Pod2Man" => "pod2man"],
        ["Amin::Command::Pod2Text" => "pod2text"],
        ["Amin::Command::Pr" => "pr"],
        ["Amin::Command::Printf" => "printf"],
        ["Amin::Command::Ps" => "ps"],
        ["Amin::Command::Pvcreate" => "pvcreate"],
        ["Amin::Command::Pwd" => "pwd"],
        ["Amin::Command::Python" => "python"],
        ["Amin::Command::Python3" => "python3"],
        ["Amin::Command::Ranlib" => "ranlib"],
        ["Amin::Command::Readelf" => "readelf"],
        ["Amin::Command::Readlink" => "readlink"],
        ["Amin::Command::Realpath" => "realpath"],
        ["Amin::Command::Remove" => "remove"],
        ["Amin::Command::Rename" => "rename"],
        ["Amin::Command::Resize2fs" => "resize2fs"],
        ["Amin::Command::Rev" => "rev"],
        ["Amin::Command::Rg" => "rg"],
        ["Amin::Command::Rm" => "rm"],
        ["Amin::Command::Rmdir" => "rmdir"],
        ["Amin::Command::Rmmod" => "rmmod"],
        ["Amin::Command::Rsync" => "rsync"],
        ["Amin::Command::Ruby" => "ruby"],
        ["Amin::Command::Runuser" => "runuser"],
        ["Amin::Command::Rustc" => "rustc"],
        ["Amin::Command::Scp" => "scp"],
        ["Amin::Command::Sed" => "sed"],
        ["Amin::Command::Seq" => "seq"],
        ["Amin::Command::Setsid" => "setsid"],
        ["Amin::Command::Sfdisk" => "sfdisk"],
        ["Amin::Command::Sftp" => "sftp"],
        ["Amin::Command::Sgdisk" => "sgdisk"],
        ["Amin::Command::Sh" => "sh"],
        ["Amin::Command::Shred" => "shred"],
        ["Amin::Command::Size" => "size"],
        ["Amin::Command::Sleep" => "sleep"],
        ["Amin::Command::Sort" => "sort"],
        ["Amin::Command::Split" => "split"],
        ["Amin::Command::Ssh" => "ssh"],
        ["Amin::Command::Stat" => "stat"],
        ["Amin::Command::Strace" => "strace"],
        ["Amin::Command::Strings" => "strings"],
        ["Amin::Command::Strip" => "strip"],
        ["Amin::Command::Su" => "su"],
        ["Amin::Command::Sudo" => "sudo"],
        ["Amin::Command::Swapoff" => "swapoff"],
        ["Amin::Command::Swapon" => "swapon"],
        ["Amin::Command::Sync" => "sync"],
        ["Amin::Command::Sysctl" => "sysctl"],
        ["Amin::Command::Tac" => "tac"],
        ["Amin::Command::Tail" => "tail"],
        ["Amin::Command::Tar" => "tar"],
        ["Amin::Command::Tclsh" => "tclsh"],
        ["Amin::Command::Tee" => "tee"],
        ["Amin::Command::Test" => "test"],
        ["Amin::Command::Texinfo" => "texinfo"],
        ["Amin::Command::Time" => "time"],
        ["Amin::Command::Timeout" => "timeout"],
        ["Amin::Command::Top" => "top"],
        ["Amin::Command::Touch" => "touch"],
        ["Amin::Command::Tr" => "tr"],
        ["Amin::Command::True" => "true"],
        ["Amin::Command::Truncate" => "truncate"],
        ["Amin::Command::Tty" => "tty"],
        ["Amin::Command::Tune2fs" => "tune2fs"],
        ["Amin::Command::Udevadm" => "udevadm"],
        ["Amin::Command::Umount" => "umount"],
        ["Amin::Command::Uname" => "uname"],
        ["Amin::Command::Unexpand" => "unexpand"],
        ["Amin::Command::Uniq" => "uniq"],
        ["Amin::Command::Unlink" => "unlink"],
        ["Amin::Command::Unlzma" => "unlzma"],
        ["Amin::Command::Unxz" => "unxz"],
        ["Amin::Command::Unzip" => "unzip"],
        ["Amin::Command::Unzstd" => "unzstd"],
        ["Amin::Command::Uptime" => "uptime"],
        ["Amin::Command::Vala" => "vala"],
        ["Amin::Command::Valgrind" => "valgrind"],
        ["Amin::Command::Vgcreate" => "vgcreate"],
        ["Amin::Command::Watch" => "watch"],
        ["Amin::Command::Wc" => "wc"],
        ["Amin::Command::Wget" => "wget"],
        ["Amin::Command::Whereis" => "whereis"],
        ["Amin::Command::Which" => "which"],
        ["Amin::Command::Whoami" => "whoami"],
        ["Amin::Command::Xargs" => "xargs"],
        ["Amin::Command::Xz" => "xz"],
        ["Amin::Command::Xzcat" => "xzcat"],
        ["Amin::Command::Yacc" => "yacc"],
        ["Amin::Command::Yes" => "yes"],
        ["Amin::Command::Zcat" => "zcat"],
        ["Amin::Command::Zip" => "zip"],
        ["Amin::Command::Zsh" => "zsh"],
        ["Amin::Command::Zstd" => "zstd"],
        ["Amin::Command::Zstdcat" => "zstdcat"],

    );
    for my $c (@COMMANDS) {
        my ($pkg, $name) = @$c;
        (my $file = "$pkg.pm") =~ s{::}{/}g;
        require $file;
        __PACKAGE__->register($pkg,
            element => "command", namespace => NS(), name => $name, position => "middle");
    }

    require Amin::UCC::Sales;
    __PACKAGE__->register('Amin::UCC::Sales',
        element => 'sale',    namespace => 'http://projectamin.org/ns/ucc/1',
        position => 'middle');
    require Amin::UCC::Instruments;
    __PACKAGE__->register('Amin::UCC::Instruments',
        element => 'instrument', namespace => 'http://projectamin.org/ns/ucc/1',
        position => 'middle');
    require Amin::Command::Exec;    __PACKAGE__->register('Amin::Command::Exec',
        element => 'exec',    namespace => NS(), position => 'middle');
    require Amin::Command::Spawn;   __PACKAGE__->register('Amin::Command::Spawn',
        element => 'spawn',   namespace => NS(), position => 'middle');
    require Amin::Command::Signal;  __PACKAGE__->register('Amin::Command::Signal',
        element => 'signal',  namespace => NS(), position => 'middle');
    require Amin::Sandbox;         __PACKAGE__->register('Amin::Sandbox',
        element => 'sandbox', namespace => NS(), position => 'middle');
    require Amin::Net::Fabric;     __PACKAGE__->register('Amin::Net::Fabric',
        element => undef, namespace => NS(), position => 'middle');
    require Amin::Cond::OS;         __PACKAGE__->register('Amin::Cond::OS',
        element => undef,   namespace => NS(),                        position => 'begin');
    require Amin::Filter::Init::ProfileValidator;
    __PACKAGE__->register('Amin::Filter::Init::ProfileValidator',
        element => 'stage',   namespace => NS(),                        position => 'begin');
    require Amin::UCC::General;
    __PACKAGE__->register('Amin::UCC::General',
        element => 'transaction', namespace => 'http://projectamin.org/ns/ucc/1',
        position => 'begin');
    require Amin::UCC::Credit;
    __PACKAGE__->register('Amin::UCC::Credit',
        element => 'lc',      namespace => 'http://projectamin.org/ns/ucc/1',
        position => 'begin');
    require Amin::Schedule::Placement;
    __PACKAGE__->register('Amin::Schedule::Placement',
        element => undef,     namespace => NS(),                        position => 'begin');
    require Amin::Filter::Storage::Bitcache;
    __PACKAGE__->register('Amin::Filter::Storage::Bitcache',
        element => 'object',  namespace => 'http://projectamin.org/ns/bc/',
        position => 'middle');
    require Amin::Filter::Map::Topology;
    __PACKAGE__->register('Amin::Filter::Map::Topology',
        element => undef,   namespace => 'http://projectamin.org/ns/map/1',
        namespaces => [NS(), 'http://projectamin.org/ns/map/1'],
        position => 'late');
    require Amin::Filter::UI::SwiftUIView;
    __PACKAGE__->register('Amin::Filter::UI::SwiftUIView',
        element => undef,   namespace => 'http://projectamin.org/ns/ui/1',
        namespaces => [NS(), 'http://projectamin.org/ns/ui/1'],
        position => 'late');
    require Amin::Filter::Billing::CgroupV2;
    __PACKAGE__->register('Amin::Filter::Billing::CgroupV2',
        element => undef, namespace => NS(), position => 'end');
    require Amin::UCC::Settlement;
    __PACKAGE__->register('Amin::UCC::Settlement',
        element => undef, namespace => 'http://projectamin.org/ns/ucc/1',
        position => 'end');
}

sub new ($class, %o) {
    my $self = bless { %o }, $class;
    my $spec = _resolve_spec(\%o);
    $self->{machine_spec} = $spec;
    $self->{Handler} //= _instantiate_handler($spec->{handler});
    $self->{Log}     //= _instantiate_log($spec->{log});
    $self->{chain} = _build_chain($self->Handler, $self->Log, $self->Mode // 'render',
        $self->{late_filters_enable} // { map => 1, ui => 1 }, $spec->{allowed});
    return $self;
}

sub _resolve_spec ($o) {
    my $raw = delete $o->{machine_spec};
    my $spec;
    if ($raw && ref $raw eq 'HASH') {
        if (exists $raw->{allowed}) {
            $spec = $raw;
        } else {
            $spec = { allowed => $raw };
        }
    } else {
        require Amin::Machine::MachineSpec;
        my $ms = Amin::Machine::MachineSpec->new(
            (exists $o->{machine_spec_xml}  ? (xml  => delete $o->{machine_spec_xml})  : ()),
            (exists $o->{machine_spec_path} ? (path => delete $o->{machine_spec_path}) : ()),
        );
        $spec = $ms->spec;
    }
    if (%RUNTIME_ALLOWED) {
        $spec->{allowed} = { $spec->{allowed}->%*, %RUNTIME_ALLOWED };
    }
    return $spec;
}

sub _instantiate_handler ($h) {
    return undef unless $h && ref $h eq 'HASH' && $h->{class};
    (my $file = "$h->{class}.pm") =~ s{::}{/}g;
    eval { require $file };
    return undef if $@;
    return $h->{class}->new($h->{attrs} ? $h->{attrs}->%* : ());
}

sub _instantiate_log ($l) {
    return undef unless $l && ref $l eq 'HASH' && $l->{class};
    (my $file = "$l->{class}.pm") =~ s{::}{/}g;
    eval { require $file };
    return undef if $@;
    return $l->{class}->new($l->{attrs} ? $l->{attrs}->%* : ());
}

sub _generator_class ($g) {
    return undef unless $g && ref $g eq 'HASH' && $g->{class};
    (my $file = "$g->{class}.pm") =~ s{::}{/}g;
    eval { require $file };
    return $@ ? undef : $g->{class};
}

for my $m (qw(start_document end_document
              start_element end_element characters
              processing_command comment ignorable_whitespace)) {
    no strict 'refs';
    *$m = sub ($self, @args) { $self->{chain}->$m(@args) };
}

sub run ($pkg_or_self, %o) {
    my $mode      = $o{mode}      // 'render';
    my $late_en   = $o{late_filters_enable} // { map => 1, ui => 1 };
    my $source    = $o{source_xml}  // die "Dispatcher->run needs source_xml";
    my $spec      = _resolve_spec(\%o);
    my $Handler   = $o{Handler} // _instantiate_handler($spec->{handler})
                    // do { require Amin::Handler::Writer; Amin::Handler::Writer->new(indent => 2) };
    my $Log       = $o{Log}     // _instantiate_log($spec->{log})
                    // do { require Amin::Log::Standard; Amin::Log::Standard->new(stderr => 0) };
    my $gen_class = _generator_class($spec->{generator}) // 'XML::LibXML::SAX';
    my $self;
    if (ref($pkg_or_self)) { $self = $pkg_or_self; $self->{Mode} = $mode;
        $self->{Handler} //= $Handler; $self->{Log} //= $Log;
        $self->{machine_spec} = $spec;
        $self->{chain} = _build_chain($self->Handler, $self->Log, $mode, $late_en, $spec->{allowed});
    } else {
        $self = bless({ Mode => $mode, Handler => $Handler, Log => $Log, machine_spec => $spec }, $pkg_or_self);
        $self->{chain} = _build_chain($self->Handler, $self->Log, $mode, $late_en, $spec->{allowed});
    }
    (my $gen_file = "$gen_class.pm") =~ s{::}{/}g;
    eval { require $gen_file };
    $gen_class->new(Handler => $self)->parse_string($source);
    $self->Handler->can('output') && return $self->Handler->output;
    return;
}

sub _build_chain ($h, $l, $mode, $late_enable = {}, $allowed = undef) {
    my $head = $h;
    for my $pos (qw(end late middle begin permanent)) {
        my $filters = $FILTERS{$pos} // [];
        for my $f (reverse @$filters) {
            next if defined $allowed && !$allowed->{$f->{class}};
            next if $pos eq 'late' && (
                ($f->{class} =~ /::Map::/ && !$late_enable->{map}) ||
                ($f->{class} =~ /::UI::/  && !$late_enable->{ui}));
            $head = $f->{class}->new(
                Handler => $head, Log => $l, Mode => $mode,
                Name    => $f->{meta}{name},
                Element => $f->{meta}{element});
            $head->can('name')    && $head->name($f->{meta}{name});
            $head->can('element') && $head->element($f->{meta}{element});
        }
    }
    return $head;
}

1;
