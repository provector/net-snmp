#!/usr/bin/perl
​
=pod
​
Read this, from something like "tcpdump -nn -# -X -r infile.pcap":
​
    1  13:19:00.934193 IP 192.168.10.100.45025 > 192.168.50.202.161:  GetRequest(28)  .1.3.6.1.2.1.1.2.0
        0x0000:  4500 0047 eabe 4000 4011 9168 c0a8 0a64  E..G..@.@..h...d
        0x0010:  c0a8 32ca afe1 00a1 0033 bec3 3029 0201  ..2......3..0)..
        0x0020:  0104 0670 7562 6c69 63a0 1c02 0460 75ee  ...public....`u.
        0x0030:  aa02 0100 0201 0030 0e30 0c06 082b 0601  .......0.0...+..
        0x0040:  0201 0102 0005 0000 0000 0000 0000 0000  ................
        0x0050:  0000 0000 0000 00                        .......
    2  13:19:00.977548 IP 192.168.50.202.161 > 192.168.10.100.45025:  GetResponse(37)  .1.3.6.1.2.1.1.2.0=.1.3.6.1.4.1.211.1.24
​
and send a UDP packet that would have the same content.
​
The timestamp is from the pcap file, not from the IP packet, so that can be ignored.
​
sleep for 1 second between packets
​
Now - omit the padding, and see what comes out.
​
=cut
​
use strict;
​
use Socket qw(:all);
use Data::Dumper;
​
my $in_packet = 0; # flag - am I adding to a packet now?
my $xcontent; # the packet content, hex-encoded octets
my ($dstip, $dstport); # where to send to
my $iplen; # (remaining) declared length of the IP packet
​
# fetch the input
while (<>) {
	my ($row, @octets) = split; # on whitespace
	my $print = pop @octets; # lose the printable bit on the end
	my $octets = join ('', @octets);
	if ($row eq '0x0000:') {
		# first line of new packet
		$in_packet = 1;
		$xcontent = $octets;
		$iplen = hex($octets[1]) - 16; # 16 raw octets on the first line
	} elsif ($row =~ /^0x....:/) {
		# continuing packet - add the bytes until $iplen is 0
		# Note - iplen counts raw octets; we are reading hex-encoded octets
		my $thislen = length($octets)/2;
		if ($iplen >= $thislen) {
			$iplen -= $thislen;
			$xcontent .= $octets;
		} elsif ($iplen) {
			$xcontent .= substr $octets, 0, $iplen*2;
			$iplen = 0;
		}
		if ($row eq '0x0010:') {
			# second line of packet - includes dest IP,por
			$dstip = pack('H*', $octets[0] . $octets[1]);
			$dstport = hex($octets[3]);
		}
	} elsif ($in_packet) {
		# packet has just ended -- send it
		$in_packet = 0;
​
		my $s;
		my $rv;
		socket($s, AF_INET, SOCK_RAW, IPPROTO_UDP) or warn "sock failed: $!";
		setsockopt($s, IPPROTO_IP, IP_HDRINCL, 1) or warn "setopt failed: $!";
​
		my $content = pack ('H*', $xcontent);
		my $dst = sockaddr_in($dstport, $dstip);
		print "Sending ", length $content, " bytes...";
		$rv = send $s, $content, '', $dst or warn "send failed: $!";
		print "...sent $rv\n";
		sleep 1;
	} else {
		# first line, odd multiple-line. Skip
	}
}
# There might be a packet ready to go, if the input did not end with a non-content line.
# Send it? Or just say "fix the input"?