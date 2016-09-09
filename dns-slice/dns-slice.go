package main

import (

	//internal
	"fmt"

	//external
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	pcapfile = kingpin.Arg("pcap_file", "pcap file to scan").String()
)

func main() {
	kingpin.Parse()

	if handle, err := pcap.OpenOffline(*pcapfile); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("udp and port 53"); err != nil {
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			if dnslayer := packet.Layer(layers.LayerTypeDNS); dnslayer != nil {
				dns, _ := dnslayer.(*layers.DNS)

				fmt.Println(string(dns.Questions[0].Name))
			}
		}
	}
}
