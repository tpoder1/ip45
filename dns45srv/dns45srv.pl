#!/usr/bin/perl -w

my $TTL			= 3600*4;
my $LOGFACILITY	= "daemon.info";
my $LOGNAME		= substr($0, rindex($0, "/") + 1);
my $DEBUG		= 0;
my $LOGLEVEL	= 0;
 
use strict;
use warnings;
use Net::DNS::Nameserver;
use Getopt::Std;
use POSIX qw(strftime setsid);
use Sys::Syslog qw(:standard :extended);

my %OPTS;

# log routine
sub mylog {
	my ($msg, @par) = @_;
	my $lmsg = sprintf($msg, @par);
	if ($DEBUG > 0) {
		printf "%s[%d]: %s\n", strftime("%Y-%m-%d.%H:%M:%S", localtime), $$, $lmsg;
	}
	setlogsock('unix');
	openlog("$LOGNAME\[$$\]", 'ndelay', 'user');
	syslog($LOGFACILITY, $lmsg);
}

# process daemonization
sub daemonize() {
	chdir '/' 					or die "Can't chdir to /: $!";
	open STDIN, '/dev/null' 	or die "Can't read /dev/null: $!";
	open STDOUT, '>/dev/null' 	or die "Can't write to /dev/null: $!";
	defined(my $pid = fork) 	or die "Can't fork: $!";
	exit if $pid;
	setsid() 					or	die "Can't start a new session: $!";
	open STDERR, '>&STDOUT' 	or die "Can't dup stdout: $!";
}

# change user
 sub chuser($) {
	my ($user) = @_;

	my ($login,$pass,$uid,$gid) = getpwnam($user);
	# gid must be changed before uid, at least on my computer :)
	$( = $gid;
	$) = $gid;
	$< = $uid;
	$> = $uid;

	## Check that we managed to change Group/User IDs properly...
	## Change warn to die if it's important to you
	if ( ((split(/ /,$)))[0] ne $gid) || ((split(/ /,$())[0] ne $gid) ) {
		warn "Couldn't Change Group ID!\n";
	}

	if ( ($> ne $uid) || ($< ne $uid) ) {
		mylog("Couldn't Change User ID!\n");
		die "Couldn't Change User ID!\n";
	}

	mylog("switched to user %s (uid: %d, gid: %d)", $user, $uid, $gid);

	# We don't need these anymore...
	undef($login);
	undef($pass);
	undef($uid);
	undef($gid);

	# and so the program will actually RUN at this user:
	fork and wait and exit;
}

# convert request string into ipv6 address format 
sub parse_addr($) {
	my ($query) = @_;

	# split request 	
	my (@arr) = split(/\./, $query); 

	# remove everythink after non numeric elemnt 
	foreach my $x (0 .. $#arr) {
		next if ($arr[$x] =~ /^\d{1,3}$/);

		splice(@arr, $x);
		last;
	}

	if (scalar(@arr) > 12 || scalar(@arr) < 4) {
		return undef;
	}

	my $res = "";
	my $y = 1;
	# create IPv6 address (from the end)
	for my $x (-$#arr .. 0) { 
		$x *= -1;

		$res = sprintf("%02x%s", $arr[$x], $res);
		if ($y % 2 == 0) {
			$res = sprintf(":%s", $res);
		}
		$y++;

	}

	if (scalar(@arr) % 2 == 0) {
		$res = sprintf(":%s", $res);
	} else {
		$res = sprintf("::%s", $res);
	}

	return $res;
}
 
sub reply_handler {
	my ($qname, $qclass, $qtype, $peerhost,$query,$conn) = @_;
	my ($rcode, @ans, @auth, @add);
 
	$query->print if ($DEBUG > 3);

	my $ok = 0;	
 
	#if ($qtype eq "AAAA" && $qname eq "foo.example.com" ) {
	if ($qtype eq "AAAA") {

		my $rdata = parse_addr($qname);

		if ($rdata) {
			my $rr = new Net::DNS::RR("$qname $TTL $qclass $qtype $rdata");
			push @ans, $rr;
			$rcode = "NOERROR";
			mylog("OK %s -> %s from %s \n", $qname, $rdata,  $conn->{sockhost}) if (defined($OPTS{'l'}));
			$ok = 1;
		} 
	}

	if (!$ok) {
		mylog("INVALID %s %s from %s \n", $qname, $qtype,  $conn->{sockhost})  if (defined($OPTS{'f'}));;
		$rcode = "NXDOMAIN";
	}
 
	# mark the answer as authoritive (by setting the 'aa' flag)
	return ($rcode, \@ans, \@auth, \@add, { aa => 1 });
}
 
# help
sub usage() {
	printf "$0 DNS daemon for convertin IP45 address to IPv6 AAAA records\n";
	printf "Usage:\n";
	printf " %s [ -d <debug level> ]  [ -u <username> ] [ -l ] [ -f ] \n", $0;
	printf "  -l log valid requests \n";
	printf "  -f log invalid requests \n";
	exit 1;
}


# Main body
$SIG{CHLD} = sub { wait(); };

if (!getopts("fld:u:", \%OPTS) || defined($OPTS{"?"})) {
	usage();
	exit 1;
}

my $ns = new Net::DNS::Nameserver(
	LocalPort    => 53,
	ReplyHandler => \&reply_handler,
	Verbose      => 0, 
	) || die "couldn't create nameserver object\n";


if (defined($OPTS{"d"})) {
	$DEBUG = $OPTS{"d"};
}

if (defined($OPTS{"u"})) {
	chuser($OPTS{"u"});
}

if ($DEBUG == 0) {
	daemonize();
}

$ns->main_loop;

