use strict;
use inc::Devel::CheckLib;
use ExtUtils::MakeMaker;

my $DEFINES = '';
if (grep { $_ eq '--very-verbose' } @ARGV) {
    $DEFINES .= ' -DVERY_VERBOSE';
}

my $OPTIMIZE;
if (grep { $_ eq '--debugging' } @ARGV) {
    $OPTIMIZE = '-g';
}

# Check for hellish-ness
my $RUNNING_IN_HELL = $^O eq 'MSWin32';

my $CCFLAGS = $ENV{CCFLAGS} || '';
my $LDFLAGS = $ENV{LDFLAGS} || '';

if ($^O eq 'darwin') {
    $CCFLAGS .= ' -I/opt/local/include';
    $LDFLAGS .= ' -L/opt/local/lib';
}

if (! $RUNNING_IN_HELL) {
    $CCFLAGS ||= ' -I/usr/local/include';
    $LDFLAGS ||= ' -L/usr/local/lib';
}

{
    eval {
        Devel::CheckLib::assert_lib(lib => "gmp", LIBS => $LDFLAGS);
    };
    if ($@) {
        print <<EOM;

*** Whoa! libgmp was not detected! ***

Can't proceed without libgmp.
You will have to install libgmp by yourself.

EOM
        exit 0;
    }
}


# Stolen from Math::BigInt::GMP
if (($Config::Config{'osname'} eq 'darwin') &! (join (' ', @ARGV) =~ /LDDLFLAGS/))
  {
  ### reads pre-existing LDDLFLAGS for a darwin system as defined in
  ###  /System/Library/Perl/x.x.x/darwin-thread-multi-2level/Config.pm
  ###  where x.x.x is the perl version, which is 5.8.1 for MacOS X 10.3,
  ###  and appends ' -read_only_relocs suppress' 
  ### default behavior if LDDLFLAGS is defined
  push @ARGV, sprintf "LDDLFLAGS=%s -read_only_relocs suppress", $Config::Config{'lddlflags'};
  }

WriteMakefile(
    'NAME'          => 'Crypt::DH::GMP',
    'VERSION_FROM'  => 'lib/Crypt/DH/GMP.pm',
    'LIBS'          => [ split(/\s+/, $LDFLAGS), '-lgmp'],
    'OBJECT'        => '$(O_FILES)',
    'INC'           => $CCFLAGS,
    'DEFINE'        => $DEFINES,
    'OPTIMIZE'      => $OPTIMIZE,
);