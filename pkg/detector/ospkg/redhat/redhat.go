package redhat

import (
	"strings"
	"time"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat"
	ospkgutils "github.com/aquasecurity/trivy/pkg/detector/ospkg/utils"

	"github.com/aquasecurity/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
	version "github.com/knqyf263/go-rpm-version"
)

var (
	redhatEOLDates = map[string]time.Time{
		"4": time.Date(2017, 5, 31, 23, 59, 59, 0, time.UTC),
		"5": time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC),
		"6": time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
		// N/A
		"7": time.Date(3000, 1, 1, 23, 59, 59, 0, time.UTC),
		"8": time.Date(3000, 1, 1, 23, 59, 59, 0, time.UTC),
	}
	centosEOLDates = map[string]time.Time{
		"3": time.Date(2010, 10, 31, 23, 59, 59, 0, time.UTC),
		"4": time.Date(2012, 2, 29, 23, 59, 59, 0, time.UTC),
		"5": time.Date(2017, 3, 31, 23, 59, 59, 0, time.UTC),
		"6": time.Date(2020, 11, 30, 23, 59, 59, 0, time.UTC),
		"7": time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
		// N/A
		"8": time.Date(3000, 6, 30, 23, 59, 59, 0, time.UTC),
	}
)

type Scanner struct {
	vs dbTypes.VulnSrc
}

func NewScanner() *Scanner {
	return &Scanner{
		vs: redhat.NewVulnSrc(),
	}
}

func (s *Scanner) Detect(osVer string, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting RHEL/CentOS vulnerabilities...")
	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}
	log.Logger.Debugf("redhat: os version: %s", osVer)
	log.Logger.Debugf("redhat: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		// For Red Hat Security Data API containing only source package names
		// advisories, err := s.vs.Get(osVer, pkg.SrcName)
		// if err != nil {
		// 	return nil, xerrors.Errorf("failed to get Red Hat advisories: %w", err)
		// }
		advisories := ospkgutils.GetAllAdvisories(s.vs, pkg.SrcName, redhatEOLDates)

		installed := utils.FormatVersion(pkg)
		installedVersion := version.NewVersion(installed)

		for _, adv := range advisories {
			if adv.FixedVersion != "" {
				continue
			}
			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
				Layer:            pkg.Layer,
			}
			vulns = append(vulns, vuln)
		}

		// For Red Hat OVAL containing only binary package names
		// advisories, err = s.vs.Get(osVer, pkg.Name)
		// if err != nil {
		// 	return nil, xerrors.Errorf("failed to get Red Hat advisories: %w", err)
		// }
		advisories = ospkgutils.GetAllAdvisories(s.vs, pkg.Name, redhatEOLDates)

		for _, adv := range advisories {
			fixedVersion := version.NewVersion(adv.FixedVersion)
			if installedVersion.LessThan(fixedVersion) {
				vuln := types.DetectedVulnerability{
					VulnerabilityID:  adv.VulnerabilityID,
					PkgName:          pkg.Name,
					InstalledVersion: installed,
					FixedVersion:     fixedVersion.String(),
					Layer:            pkg.Layer,
				}
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}

func (s *Scanner) IsSupportedVersion(osFamily, osVer string) bool {
	now := time.Now()
	return s.isSupportedVersion(now, osFamily, osVer)
}

func (s *Scanner) isSupportedVersion(now time.Time, osFamily, osVer string) bool {
	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}

	var eolDate time.Time
	var ok bool
	if osFamily == os.RedHat {
		eolDate, ok = redhatEOLDates[osVer]
	} else if osFamily == os.CentOS {
		eolDate, ok = centosEOLDates[osVer]
	}
	if !ok {
		log.Logger.Warnf("This OS version is not on the EOL list: %s %s", osFamily, osVer)
		return false
	}
	return now.Before(eolDate)
}
