package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"time"
)

var (
	device        = flag.String("device", "lo", "")
	snapshotLen   = flag.Int("snapshot_len", 2048, "")
	BPFFilter     = flag.String("bpf_filter", "tcp and port 5432", "")
	queryFilter   = flag.String("query_filter", "", "not case-sensitive")
	queries       = make(map[string]query)
	slowQueryTime = flag.Int64("slow_query_time", 0, "in milliseconds")
)

type query struct {
	query string
	start time.Time
}

func main() {

	flag.Parse()

	handle, err := pcap.OpenLive(*device, int32(*snapshotLen), true, time.Second)

	defer handle.Close()

	if err != nil {

		log.Fatal(err)
	}

	handle.SetBPFFilter(*BPFFilter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var (
		ipLayer  *layers.IPv4
		tcpLayer *layers.TCP
		ok       bool
	)

	for packet := range packetSource.Packets() {

		if applicationLayer := packet.ApplicationLayer(); applicationLayer != nil {

			if ipLayer, ok = packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); !ok {

				continue
			}

			if tcpLayer, ok = packet.Layer(layers.LayerTypeTCP).(*layers.TCP); !ok {

				continue
			}

			playload := applicationLayer.Payload()

			if len(playload) < 5 {

				continue
			}

			length := _len(playload[1:5])

			if length > len(playload)-1 {

				continue
			}

			switch playload[0] {

			case 'Q', 'P':

				from := fmt.Sprintf("%s%d:%s%d\n", ipLayer.SrcIP, tcpLayer.SrcPort, ipLayer.DstIP, tcpLayer.DstPort)

				if *queryFilter == "" || bytes.Contains(bytes.ToLower(playload[5:length]), bytes.ToLower([]byte(*queryFilter))) {

					queries[from] = query{
						query: string(playload[5:length]),
						start: packet.Metadata().Timestamp,
					}
				}

			default:

				from := fmt.Sprintf("%s%d:%s%d\n", ipLayer.DstIP, tcpLayer.DstPort, ipLayer.SrcIP, tcpLayer.SrcPort)

				if query, found := queries[from]; found {

					queryTime := packet.Metadata().Timestamp.Sub(query.start)

					if *slowQueryTime == 0 || queryTime.Nanoseconds()/1000 > *slowQueryTime {

						fmt.Printf("-[ QUERY %f s]-:\n%s\n\n\n", queryTime.Seconds(), query.query)
					}

					delete(queries, from)
				}
			}
		}
	}
}

func _len(b []byte) int {

	return int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
}
