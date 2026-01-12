package adapter

import (
	"fmt"

	"bytemomo/kraken/internal/domain"
)

// buildEtherCATArgs converts an EtherCATSlave to CLI arguments.
// Used by both CLI and Docker adapters for passing target info to external modules.
//
// Arguments generated:
//
//	--ecat-iface <interface>    Network interface name
//	--ecat-position <pos>       Slave position (0-based)
//	--ecat-station <addr>       Configured station address
//	--ecat-alias <addr>         Alias address from EEPROM
//	--ecat-vendor <id>          Vendor ID (hex with 0x prefix)
//	--ecat-product <code>       Product code (hex with 0x prefix)
//	--ecat-revision <no>        Revision number
//	--ecat-serial <no>          Serial number
func buildEtherCATArgs(slave domain.EtherCATSlave) []string {
	args := []string{
		"--ecat-iface", slave.Interface,
		"--ecat-position", fmt.Sprintf("%d", slave.Position),
	}

	if slave.StationAddr != 0 {
		args = append(args, "--ecat-station", fmt.Sprintf("%d", slave.StationAddr))
	}
	if slave.AliasAddr != 0 {
		args = append(args, "--ecat-alias", fmt.Sprintf("%d", slave.AliasAddr))
	}
	if slave.VendorID != 0 {
		args = append(args, "--ecat-vendor", fmt.Sprintf("0x%X", slave.VendorID))
	}
	if slave.ProductCode != 0 {
		args = append(args, "--ecat-product", fmt.Sprintf("0x%X", slave.ProductCode))
	}
	if slave.RevisionNo != 0 {
		args = append(args, "--ecat-revision", fmt.Sprintf("%d", slave.RevisionNo))
	}
	if slave.SerialNo != 0 {
		args = append(args, "--ecat-serial", fmt.Sprintf("%d", slave.SerialNo))
	}

	return args
}
