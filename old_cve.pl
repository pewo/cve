#!/usr/bin/perl -w


use strict;
use Data::Dumper;
use Storable qw(lock_store lock_nstore lock_retrieve);
use Sys::Hostname;
my $host = hostname;
my $debug = 1;

sub popen($) {
	my($cmd) = shift;
	my(@res) = ();
	if ( $cmd ) {
		unless ( open(POPEN,"$cmd |") ) {
			print "$cmd: $!\n";
			return(@res);
		}
		foreach ( <POPEN> ) {
			chomp;
			push(@res,$_);
		}
		close(POPEN);
	}
	return(@res);
}

{
	my($rpm) = undef;
	sub rpm(;$) {
		my($args) = shift || "--version";
		unless ( $rpm ) {
			$rpm = "/usr/bin/rpm" if ( -x "/usr/bin/rpm" );
		}
		unless ( $rpm ) {
			die "Unable to find executable rpm binary, exiting...\n";
		}
		return ( popen("$rpm $args") );
	}
}

sub pkg_db() {
	my($cve_rpm_db) = $ENV{HOME} . "/.cve-rpm.db";
	print "cve_rpm_db: $cve_rpm_db\n";

	my(@pkg) = ();

	my(%rpmcache);
	if ( -r $cve_rpm_db ) {
		my($hashref);
		$hashref = lock_retrieve($cve_rpm_db);
		%rpmcache = %$hashref;
	}
	
	my($secs) = $rpmcache{secs} || 0;
	my($age) = time - $secs;
	if ( $age > 3600 ) {
		print "Refreshing cache, age: $age\n" if ( $debug );
		my(@pkg) = popen("rpm -qa");
		$rpmcache{secs}=time;
		$rpmcache{data}=\@pkg;
		lock_store \%rpmcache, $cve_rpm_db;
	}
	else {
		print "Using cache...age=$age\n" if ( $debug );
	}

	my($ap) = $rpmcache{data};
}

	
my(@rpmver) = rpm();
print Dumper(\@rpmver);
__END__



my($ap) = pkg_db();
my($cve_changelog_db) = $ENV{HOME} . "/.cve-changelog.db";
my(%cve);
if ( -r $cve_changelog_db ) {
	my($hashref);
	$hashref = lock_retrieve($cve_changelog_db);
	#print Dumper(\$hashref);
	%cve = %$hashref;
}

my($pkg);
foreach $pkg ( sort @$ap ) {
	my(@cve);
	if ( defined($cve{$pkg}) ) {
		#print "Using cache...\n";
		my($ap) = $cve{$pkg};
		@cve = @$ap;
	}
	else {
		my(@arr) = popen("rpm -q --changelog $pkg");
		foreach ( @arr ) {
			if ( m/(CVE-\d\d\d\d-\d+)\D/ ) {
				push(@cve,$1);
				print "Cve: $1\n";
			}
		}
		$cve{$pkg} = \@cve;
		print "Saving $cve_changelog_db\n";
		lock_nstore \%cve, $cve_changelog_db;
	}

	my($res) = undef;
	foreach ( @cve ) {
		next unless ( m/CVE/ );
		$res .= "$_ ";
	}
	if ( $res ) {
		print "$pkg: $res\n";
	}
}
	
#print Dumper(\$ap);
#$hashref = lock_retrieve('file');
