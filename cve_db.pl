#!/usr/bin/perl -w

use strict;
use Getopt::Long;
use FindBin;
use lib $FindBin::Bin;
use Cve;

my($debug) = 0;

GetOptions (
	"debug=i"  => \$debug
) or die("Error in command line arguments\n");

my($cve) = new Cve( debug => $debug );

$cve->update_cve_db();
$cve->dump_cve_db();
