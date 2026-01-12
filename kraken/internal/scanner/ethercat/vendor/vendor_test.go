package vendor

import (
	"testing"

	"bytemomo/kraken/internal/domain"
)

func TestLookupVendor(t *testing.T) {
	db := DB()

	// Beckhoff
	v, ok := db.LookupVendor(2)
	if !ok {
		t.Fatal("expected to find Beckhoff (vendor ID 2)")
	}
	if v.ShortName != "Beckhoff" {
		t.Errorf("expected short name 'Beckhoff', got %q", v.ShortName)
	}
	if v.Country != "DE" {
		t.Errorf("expected country 'DE', got %q", v.Country)
	}

	// Omron
	v, ok = db.LookupVendor(34)
	if !ok {
		t.Fatal("expected to find Omron (vendor ID 34)")
	}
	if v.ShortName != "Omron" {
		t.Errorf("expected short name 'Omron', got %q", v.ShortName)
	}

	// Unknown vendor
	_, ok = db.LookupVendor(99999)
	if ok {
		t.Error("expected not to find unknown vendor")
	}
}

func TestLookupProduct(t *testing.T) {
	db := DB()

	// Beckhoff EK1100
	p, ok := db.LookupProduct(2, 131474)
	if !ok {
		t.Fatal("expected to find Beckhoff EK1100")
	}
	if p.Name != "EK1100" {
		t.Errorf("expected name 'EK1100', got %q", p.Name)
	}
	if p.Category != "coupler" {
		t.Errorf("expected category 'coupler', got %q", p.Category)
	}

	// Unknown product
	_, ok = db.LookupProduct(2, 999999)
	if ok {
		t.Error("expected not to find unknown product")
	}
}

func TestLookupName(t *testing.T) {
	name := LookupName(2)
	if name != "Beckhoff" {
		t.Errorf("expected 'Beckhoff', got %q", name)
	}

	name = LookupName(99999)
	if name != "" {
		t.Errorf("expected empty string for unknown vendor, got %q", name)
	}
}

func TestToTags(t *testing.T) {
	slave := domain.EtherCATSlave{
		VendorID:    2,
		ProductCode: 131474,
	}

	tags := ToTags(slave)

	tagSet := make(map[domain.Tag]bool)
	for _, tag := range tags {
		tagSet[tag] = true
	}

	if !tagSet["vendor:0x00000002"] {
		t.Error("expected vendor:0x00000002 tag")
	}
	if !tagSet["vendor:beckhoff"] {
		t.Error("expected vendor:beckhoff tag")
	}
	if !tagSet["vendor_country:de"] {
		t.Error("expected vendor_country:de tag")
	}
	if !tagSet["product:0x00020192"] {
		t.Error("expected product:0x00020192 tag")
	}
	if !tagSet["category:coupler"] {
		t.Error("expected category:coupler tag")
	}
}
