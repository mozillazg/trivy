package utils

import (
	"sort"
	"time"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
)

func GetAllAdvisories(vs dbTypes.VulnSrc, pkgName string, eolDates map[string]time.Time) []dbTypes.Advisory {
	var ads []dbTypes.Advisory
	var versions []string
	for v := range eolDates {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool {
		return eolDates[versions[i]].After(eolDates[versions[j]])
	})

	for _, v := range versions {
		as, _ := vs.Get(v, pkgName)
		ads = append(ads, as...)
	}

	dup := map[string]bool{}
	var advisories []dbTypes.Advisory
	for _, s := range ads {
		if !dup[s.VulnerabilityID] {
			advisories = append(advisories, s)
			dup[s.VulnerabilityID] = true
		}
	}

	return advisories
}
