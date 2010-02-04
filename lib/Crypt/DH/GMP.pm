# $Id: /mirror/coderepos/lang/perl/Crypt-DH-GMP/trunk/lib/Crypt/DH/GMP.pm 51934 2008-04-24T04:35:16.468056Z daisuke  $

package Crypt::DH::GMP;
use strict;
use warnings;
use vars qw($VERSION @ISA);
$VERSION = '0.00005';

eval {
    require XSLoader;
    XSLoader::load(__PACKAGE__, $VERSION);
    1;
} or do {
    require DynaLoader;
    push @ISA, 'DynaLoader';
    __PACKAGE__->bootstrap($VERSION);
};

sub import
{
    my $class = shift;
    if (grep { $_ eq '-compat' } @_) {
        require Crypt::DH::GMP::Compat;
    }
}

sub new
{
    my $class = shift;
    my %args  = @_;
    $class->_xs_new($args{p} || "0", $args{g} || "0", $args{priv_key} || '');
}

*compute_secret = \&compute_key;

1;

__END__

=head1 NAME

Crypt::DH::GMP - Crypt::DH Using GMP Directly

=head1 SYNOPSIS

  use Crypt::DH::GMP;

  my $dh = Crypt::DH::GMP->new(p => $p, g => $g);
  my $val = $dh->compute_secret();

  # If you want compatibility with Crypt::DH (it uses Math::BigInt)
  # then use this flag
  # You /think/ you're using Crypt::DH, but...
  use Crypt::DH::GMP qw(-compat);

  my $dh = Crypt::DH->new(p => $p, g => $g);
  my $val = $dh->compute_secret(); 

=head1 DESCRIPTION

Crypt::DH::GMP is a (somewhat) portable replacement to Crypt::DH, implemented
mostly in C.

Crypt::DH uses Math::BigInt, which is a very feature-full and fast interface
to perform high-precision math. However, with Crypt::DH, there exists several
problems:

=over 4

=item GMP/Pari libraries are almost always required

GMP and Pari are High precision math libraries which can be used from 
Math::BigInt. They are great tools, but require the installation of these
C libraries.

Crypt::DH (and in turn, Math::BigInt) works without these modules, but when
used without them, Crypt::DH is pretty much useless because of its poor
performance. This makes the underlying C libraries a requirement.

=item Crypt::DH suffers from having Math::BigInt in between GMP

Math::BigInt is (again) a god-sent for those of us who require high-precision
math from within Perl, but within the usage case that goes from
Crypt::DH, Math::BigInt, and finally to GMP|Pari, Crypt::DH suffers
dramatically in terms of performance, mainly (I assume) from the fact that
it requires several calls that round trip conversions between Perl and GMP.

=back

Based on these, I've decided that it will probably benefit a fair amount of
people by introducing a Crypt::DH compatible layer that directly works
with the C layer of gmp.

This means that we've essentially eliminated 2 call stacks worth of 
Perl method calls (which are expensive) and we also only load the
1 (Crypt::DH::GMP) module instead of 3 (Crypt::DH + Math::BigInt + Math::BigInt::GMP)

These add up to a fairly significant increase in performance.



=head1 COMPATIBILITY WITH Crypt::DH

Crypt::DH::GMP absolutely refuses to consider using anything other than
strings as its parameters and/or return values therefore if you would like
to use Math::BigInt objects as your return values, you can not use 
Crypt::DH::GMP directly. Instead, you need to be explicit about it:

  use Crypt::DH;
  use Crypt::DH::GMP qw(-compat); # must be loaded AFTER Crypt::DH

Specifying -compat invokes a very nasty hack that overwrites Crypt::DH's
symbol table -- this then forces Crypt::DH users to use Crypt::DH::GMP
instead, even if you are writing

  my $dh = Crypt::DH->new(...);
  $dh->compute_key();

=head1 BENCHMARK

By NO MEANS is this an exhaustive benchmark, but here's what I get on my
MacBook (OS X 10.5.2, 2GHz Core 2 Duo, 2GB RAM)

  daisuke@beefcake Crypt-DH-GMP$ perl -Mblib tools/benchmark.pl 
        Rate    pp   gmp
  pp  1.70/s    --  -98%
  gmp  112/s 6526%    --

I want it to run for much longer duration, but the above was all I could
get going at 1am on this particular day

=head1 METHODS

=head2 new

=head2 p

=head2 g

=head2 compute_key

=head2 compute_secret

=head2 generate_keys

=head2 pub_key

=head2 priv_key

=head2 compute_key_twoc

Computes the key, and returns a string that is byte-padded two's compliment
in binary form.

=head2 pub_key_twoc

Returns the pub_key as a string that is byte-padded two's compliment
in binary form.

=head1 AUTHOR

Daisuke Maki C<< <daisuke@endeworks.jp> >> 

=head1 LICENSE

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

See http://www.perl.com/perl/misc/Artistic.html

=cut
