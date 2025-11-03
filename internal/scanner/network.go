package scanner

import (
	"encoding/binary"
	"errors"
	"net"
)

func expandCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, errors.New("only IPv4 subnets are supported")
	}

	maskOnes, maskBits := ipNet.Mask.Size()
	if maskBits != 32 {
		return nil, errors.New("unexpected mask size")
	}
	hostCount := 1 << (32 - maskOnes)
	results := make([]string, 0, hostCount)

	network := binary.BigEndian.Uint32(ip4)
	for i := 0; i < hostCount; i++ {
		addr := make(net.IP, 4)
		binary.BigEndian.PutUint32(addr, network+uint32(i))
		if !ipNet.Contains(addr) {
			continue
		}
		results = append(results, addr.String())
	}
	return results, nil
}
