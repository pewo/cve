#!/usr/bin/perl -w

use strict;
use Getopt::Long;
use FindBin;
use lib $FindBin::Bin;
use Cve;

my($debug) = 0;
my($update) = undef;
my($dump) = undef;

GetOptions (
	"debug=i"  => \$debug,
	"update" => \$update,
	"dump" => \$dump,
) or die("Error in command line arguments\n");

unless ( $update or $dump ) {
	die "Usage $0 --dump (dump CVE db) --update (updte CVE db) --debug=1-9 (debug level)\n";
}

my($cve) = new Cve( debug => $debug );

if ( $update ) {
	$cve->update_cve_db();
}

if ( $dump ) {
	$cve->dump_cve_db();
}
