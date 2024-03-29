#!/usr/bin/perl -I../lib
#
# Copyright (c) 2005-2007 Messiah College. This program is free software.
# You can redistribute it and/or modify it under the terms of the
# GNU Public License as found at http://www.fsf.org/copyleft/gpl.html.
#
# Written by Jason Long, jlong@messiah.edu.

use strict;
use warnings;

use Mail::DKIM::Verifier;
use Getopt::Long::Descriptive;

my ($opt, $usage) = describe_options(
  "%c %o < original_email.txt",
  [ "debug-canonicalization=s" => "Output canonicalized message to file for DKIM debugging" ],
  [ "help|?" => "Show help" ],
  {show_defaults=>1},
);

if ($opt->help) {
  print $usage->text;
  exit 1;
}

my $debugfh;
if (defined $opt->debug_canonicalization)
{
	open $debugfh, ">", $opt->debug_canonicalization
		or die "Error: cannot write to ".$opt->debug_canonicalization.": $!\n";
}

# recommended, but may cause compatibility problems with old firewalls
Mail::DKIM::DNS::enable_EDNS0;

my $dkim = new Mail::DKIM::Verifier(
		Debug_Canonicalization => $debugfh,
	);
while (<STDIN>)
{
	chomp;
	s/\015$//;
	$dkim->PRINT("$_\015\012");
}
$dkim->CLOSE;

if ($debugfh)
{
	close $debugfh;
	print STDERR "wrong canonicalized message to ".$opt->debug_canonicalization."\n";
}

print "originator address: " . $dkim->message_originator->address . "\n";
foreach my $signature ($dkim->signatures)
{
	print "signature identity: " . $signature->identity . "\n";
	print "verify result: " . $signature->result_detail . "\n";
}

foreach my $policy ($dkim->policies)
{
	my $policy_name = $policy->name;
	print "$policy_name policy result: ";

	my $policy_result = $policy->apply($dkim);
	print "$policy_result\n";
}

__END__

=head1 NAME

dkimverify.pl - verifies DKIM signatures on an email message

=head1 SYNOPSIS

  dkimverify.pl [options] < signed_email.txt
    options:
      --debug-canonicalization=FILE

  dkimverify.pl --help
    to see a full description of the various options

=head1 AUTHOR

Jason Long, E<lt>jlong@messiah.eduE<gt>

Marc Bradshaw, E<lt>marc@marcbradshaw.netE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2006-2007 by Messiah College

This program is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.6 or,
at your option, any later version of Perl 5 you may have available.

=cut
