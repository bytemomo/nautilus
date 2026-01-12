package vendor

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"bytemomo/kraken/internal/domain"
)

//go:embed vendors.json
var vendorsJSON []byte

// Info contains vendor identification data.
type Info struct {
	ID          uint32 `json:"id"`
	Name        string `json:"name"`
	ShortName   string `json:"short_name"`
	Country     string `json:"country,omitempty"`
	Description string `json:"description,omitempty"`
}

// ProductInfo contains product identification data.
type ProductInfo struct {
	VendorID    uint32 `json:"vendor_id"`
	ProductCode uint32 `json:"product_code"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category,omitempty"`
}

// Database holds the vendor and product lookup tables.
type Database struct {
	vendors  map[uint32]Info
	products map[uint64]ProductInfo // key = (vendorID << 32) | productCode
}

var (
	db     *Database
	dbOnce sync.Once
)

// DB returns the singleton vendor database instance.
func DB() *Database {
	dbOnce.Do(func() {
		db = &Database{
			vendors:  make(map[uint32]Info),
			products: make(map[uint64]ProductInfo),
		}
		db.load()
	})
	return db
}

func (d *Database) load() {
	var data struct {
		Vendors  []Info        `json:"vendors"`
		Products []ProductInfo `json:"products"`
	}

	if err := json.Unmarshal(vendorsJSON, &data); err != nil {
		return
	}

	for _, v := range data.Vendors {
		d.vendors[v.ID] = v
	}

	for _, p := range data.Products {
		key := (uint64(p.VendorID) << 32) | uint64(p.ProductCode)
		d.products[key] = p
	}
}

// LookupVendor returns vendor info for the given ID.
func (d *Database) LookupVendor(vendorID uint32) (Info, bool) {
	v, ok := d.vendors[vendorID]
	return v, ok
}

// LookupProduct returns product info for the given vendor and product code.
func (d *Database) LookupProduct(vendorID, productCode uint32) (ProductInfo, bool) {
	key := (uint64(vendorID) << 32) | uint64(productCode)
	p, ok := d.products[key]
	return p, ok
}

// VendorName returns the vendor name or empty string if unknown.
func (d *Database) VendorName(vendorID uint32) string {
	if v, ok := d.vendors[vendorID]; ok {
		return v.ShortName
	}
	return ""
}

// Lookup is a convenience function using the global database.
func Lookup(vendorID uint32) (Info, bool) {
	return DB().LookupVendor(vendorID)
}

// LookupName returns the short vendor name or empty string.
func LookupName(vendorID uint32) string {
	return DB().VendorName(vendorID)
}

// ToTags generates domain tags from vendor/product info.
func ToTags(slave domain.EtherCATSlave) []domain.Tag {
	var tags []domain.Tag

	if slave.VendorID != 0 {
		tags = append(tags, domain.Tag(fmt.Sprintf("vendor:0x%08x", slave.VendorID)))

		if name := LookupName(slave.VendorID); name != "" {
			tags = append(tags, domain.Tag(fmt.Sprintf("vendor:%s", strings.ToLower(name))))
		}

		if v, ok := Lookup(slave.VendorID); ok && v.Country != "" {
			tags = append(tags, domain.Tag(fmt.Sprintf("vendor_country:%s", strings.ToLower(v.Country))))
		}
	}

	if slave.ProductCode != 0 {
		tags = append(tags, domain.Tag(fmt.Sprintf("product:0x%08x", slave.ProductCode)))

		if p, ok := DB().LookupProduct(slave.VendorID, slave.ProductCode); ok {
			if p.Category != "" {
				tags = append(tags, domain.Tag(fmt.Sprintf("category:%s", strings.ToLower(p.Category))))
			}
		}
	}

	return tags
}
