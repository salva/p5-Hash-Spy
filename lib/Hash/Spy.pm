package Hash::Spy;

our $VERSION = '0.01';

use strict;
use warnings;
use 5.010;
use Carp;

require Exporter;
our @ISA = qw(Exporter);
our @EXPORT_OK = qw(spy_hash);

require XSLoader;
XSLoader::load('Hash::Spy', $VERSION);

my %cb_slot = ( add    => 1,
                change => 2,
                store  => 3,
                clear  => 4,
                empty  => 5 );

sub spy_hash (\%@) {
    my $hash = shift;
    my $spy = _hash_get_spy($hash);
    while (@_) {
        my $name = shift;
        my $slot = $cb_slot{$name}
            or croak "bad spy callback '$name'";
        my $cb = shift;
        if (defined $cb) {
            UNIVERSAL::isa($cb, 'CODE')
                    or croak "spy callback '$name' is not a CODE ref";
        }
        $spy->[$slot] = $cb;
    }
    1;
}

1;
__END__

=head1 NAME

Hash::Spy - Perl extension for blah blah blah

=head1 SYNOPSIS

  use Hash::Spy;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for Hash::Spy, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

Salvador Fandino, E<lt>salva@E<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2013 by Salvador Fandino

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.14.2 or,
at your option, any later version of Perl 5 you may have available.


=cut
