#!/usr/bin/perl -w

use strict;
use Getopt::Long;
use FindBin;
use lib $FindBin::Bin;

eval {
	require Cve;
	1;
};

if ( $@ ) {
	print "Unable to load Cve module\n";
	print "On some system you need to install perl-open\n\n";
	print $@ . "\n";
	exit(1);
}

my($ID) = '$Id$';

my($debug) = 0;
my($update) = undef;
my($dump) = undef;
my($search) = undef;
my($help) = undef;
my($dbdir) = undef;

sub help() {
	print "Usage $0 --dbdir=<db dir> -d|--dump (dump CVE db) -u|--update (updte CVE db) -s|--search=text (search for CVE) --debug=1-9 (debug level)\n";
	return(0);
}

GetOptions (
	"h|help"  => \$help,
	"debug=i"  => \$debug,
	"d|dump"  => \$dump,
	"u|update" => \$update,
	"s|search=s" => \$search,
	"dbdir=s" => \$dbdir,
) or die("Error in command line arguments\n");

foreach ( @ARGV ) {
	if ( defined($search) ) {
		$search .= " ";
	}
	$search .= $_;
}

if ( $help ) {
	exit(help());
}

my($cve) = new Cve( debug => $debug, dbdir => $dbdir );

my($done) = 0;

if ( $update ) {
	$done++;
	$cve->update_cve_db();
}

if ( $dump ) {
	$done++;
	$cve->dump_cve_db();
}

if ( $search ) {
	$done++;
	$cve->search_cve_db($search);
}

unless ( $done ) {
	exit(help());
}
