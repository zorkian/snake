/* snake - plumber
 *
 * sniffs traffic and identifies traffic streams. */

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/akrennmair/gopcap"
	"github.com/fluffle/golog/logging"
	"os"
	"os/exec"
	"strings"
	"time"
)

type IPv4Addr [4]byte
type Endpoint [6]byte
type ConnStats [6]uint64
type ConnStatsMap map[Endpoint]map[Endpoint]*ConnStats

var conns ConnStatsMap
var locals map[IPv4Addr]bool = make(map[IPv4Addr]bool)
var ports map[string]string = make(map[string]string)
var log logging.Logger = logging.InitFromFlags()
var hostname string

func main() {
	ifs, err := pcap.Findalldevs()
	if err != nil {
		log.Fatal("Failed to find devices: %s", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal("Failed to get hostname: %s", err)
	}
	log.Info("Plumber initiated on %s!", hostname)

	findListeningPorts()

	gmap := make(map[string]interface{})
	gmap["hostname"] = hostname
	gmap["locals"] = make([]string, 0)
	gmap["data"] = make(map[string]ConnStatsMap)
	gmap["ports"] = ports

	for _, ifobj := range ifs {
		if ifobj.Name == "any" {
			continue
		}

		for _, ip := range ifobj.Addresses {
			if ipfour := ip.IP.To4(); ipfour != nil {
				locals[IPv4Addr{ipfour[0], ipfour[1], ipfour[2], ipfour[3]}] = true
				gmap["locals"] = append(gmap["locals"].([]string),
					fmt.Sprintf("%d.%d.%d.%d", ipfour[0], ipfour[1], ipfour[2], ipfour[3]))
			}
		}

		iface, err := pcap.Openlive(ifobj.Name, 10000, false, 1000)
		if iface == nil || err != nil {
			if err == nil {
				err = errors.New("unknown error")
			}
			log.Fatal("Failed to open device %s: %s", ifobj.Name, err)
		}
		if err = iface.Setfilter("tcp"); err != nil {
			log.Warn("Failed to set filter on %s: %s", ifobj.Name, err)
			continue
		}

		conns = make(map[Endpoint]map[Endpoint]*ConnStats)
		until := time.Now().Add(time.Duration(10) * time.Second)
		packets := 0

		var pkt *pcap.Packet = nil
		var rv int32 = 0

		log.Info("Capturing on %s...", ifobj.Name)
	DONE:
		for rv = 0; rv >= 0; {
			for pkt, rv = iface.NextEx(); pkt != nil; pkt, rv = iface.NextEx() {
				handlePacket(pkt)

				packets++
				if time.Now().After(until) {
					break DONE
				}
			}

			// This happens a second time because we might be capturing on an
			// interface that is totally quiet, so the above loop never fires.
			if time.Now().After(until) {
				break DONE
			}
		}
		log.Info("...captured %d packets.", packets)

		// Now dump the information we have for this connection. We write it out
		// as a JSON object, as that seems simplest.
		gmap["data"].(map[string]ConnStatsMap)[ifobj.Name] = conns
	}

	// Now dump out our stats/config object ... and we're done.
	out, err := json.Marshal(gmap)
	if err != nil {
		log.Fatal("Failed to marshal: %s", err)
	}

	n, err := os.Stdout.Write(out)
	if err != nil {
		log.Fatal("Failed to write: %s", err)
	}
	if n != len(out) {
		log.Fatal("Failed to write full output buffer")
	}
}

// handlePacket takes a given packet, extracts the information we need from it,
// and then does something with that information.
func handlePacket(pkt *pcap.Packet) {
	// Extract source and destination information from the IP and TCP headers.
	var pos byte = 14
	length := uint16(pkt.Data[pos+2])<<8 + uint16(pkt.Data[pos+3])
	src := Endpoint{pkt.Data[pos+12], pkt.Data[pos+13], pkt.Data[pos+14],
		pkt.Data[pos+15], 0, 0}
	dst := Endpoint{pkt.Data[pos+16], pkt.Data[pos+17], pkt.Data[pos+18],
		pkt.Data[pos+19], 0, 0}

	pos += pkt.Data[pos] & 0x0F * 4
	src[4], src[5] = pkt.Data[pos], pkt.Data[pos+1]
	dst[4], dst[5] = pkt.Data[pos+2], pkt.Data[pos+3]

	// Determine if this is incoming or outgoing by seeing which end of the
	// pipe is local. If both are, then classify it as localhost traffic.
	offset := 0
	if src.Local() {
		if dst.Local() {
			if dst.String() < src.String() {
				src, dst = dst, src
			}
			offset = 4
		} else {
			offset = 0
		}
	} else if dst.Local() {
		src, dst = dst, src
		offset = 2
	} else {
		log.Error("Unknown packet: %s -> %s", src, dst)
		return
	}

	// Increment statistics for this connection.
	dmap, ok := conns[src]
	if !ok {
		dmap = make(map[Endpoint]*ConnStats)
		conns[src] = dmap
	}
	stats, ok := dmap[dst]
	if !ok {
		stats = &ConnStats{0, 0, 0, 0, 0, 0}
		dmap[dst] = stats
	}

	stats[offset]++
	stats[offset+1] += uint64(length)

	//log.Debug("%d bytes %v -> %v", length, src, dst)
}

func findListeningPorts() {
	cmd := exec.Command("/bin/netstat", "-n", "-l", "-t", "-p")
	output, err := cmd.Output()
	if err != nil {
		log.Fatal("Failed to netstat: %s", err)
	}

	//tcp        0      0 0.0.0.0:5666            0.0.0.0:*               LISTEN      1469/nrpe
	//0        1        2     3                     4
	//5             6
	for _, line := range strings.Split(string(output), "\n") {
		objs := strings.Fields(string(line))
		if len(objs) < 7 || objs[0] != "tcp" {
			continue
		}
		ports[objs[3]] = objs[6]
	}

}

func (self Endpoint) String() string {
	return fmt.Sprintf("%d.%d.%d.%d:%d", self[0], self[1], self[2],
		self[3], uint16(self[4])<<8+uint16(self[5]))
}

func (self Endpoint) Local() bool {
	_, ok := locals[IPv4Addr{self[0], self[1], self[2], self[3]}]
	return ok
}

func (self ConnStatsMap) MarshalJSON() ([]byte, error) {
	out := []byte{'{'}

	first1 := true
	for dst, dstmap := range self {
		if !first1 {
			out = append(out, ',')
		}
		first1 = false

		out = append(out, '"')
		out = append(out, dst.String()...)
		out = append(out, '"', ':', '{')

		first2 := true
		for src, stats := range dstmap {
			if !first2 {
				out = append(out, ',')
			}
			first2 = false

			out = append(out, '"')
			out = append(out, src.String()...)
			out = append(out, "\":"...)

			sout, err := json.Marshal(stats)
			if err != nil {
				log.Fatal("Failed to marshal stats: %s", err)
			}

			out = append(out, sout...)
		}

		out = append(out, '}')
	}

	return append(out, '}'), nil
}
