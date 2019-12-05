package scanner

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/google/wire"

	"github.com/aquasecurity/trivy/pkg/report"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/extractor"
	rpcLibDetector "github.com/aquasecurity/trivy/internal/rpc/client/library"
	libDetector "github.com/aquasecurity/trivy/pkg/detector/library"
	"github.com/aquasecurity/trivy/pkg/scanner/library"
	libScanner "github.com/aquasecurity/trivy/pkg/scanner/library"
	"github.com/aquasecurity/trivy/pkg/scanner/ospkg"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/xerrors"
)

var StandaloneSet = wire.NewSet(
	libDetector.SuperSet,
	libScanner.NewScanner,
	NewScanner,
)

var ClientSet = wire.NewSet(
	rpcLibDetector.SuperSet,
	libScanner.NewScanner,
	NewScanner,
)

type Scanner struct {
	libScanner library.Scanner
}

func NewScanner(libScanner library.Scanner) Scanner {
	return Scanner{libScanner: libScanner}
}

func (s Scanner) ScanImage(imageName, filePath string, scanOptions types.ScanOptions) (report.Results, error) {
	results := report.Results{}
	ctx := context.Background()

	var target string
	var files extractor.FileMap
	if imageName != "" {
		target = imageName
		dockerOption, err := types.GetDockerOption()
		if err != nil {
			return nil, xerrors.Errorf("failed to get docker option: %w", err)
		}

		dockerOption.Timeout = scanOptions.Timeout
		files, err = analyzer.Analyze(ctx, imageName, dockerOption)
		if err != nil {
			return nil, xerrors.Errorf("failed to analyze image: %w", err)
		}
	} else if filePath != "" {
		target = filePath
		rc, err := openStream(filePath)
		if err != nil {
			return nil, xerrors.Errorf("failed to open stream: %w", err)
		}

		files, err = analyzer.AnalyzeFile(ctx, rc)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, xerrors.New("image name or image file must be specified")
	}

	if utils.StringInSlice("os", scanOptions.VulnType) {
		scanner, err := ospkg.NewScanner(scanOptions.RemoteURL, scanOptions.Token, files)
		if err != nil && err != ospkg.ErrUnsupportedOS {
			return nil, xerrors.Errorf("failed to create an OS scanner: %w", err)
		}
		if err == nil {
			osFamily, osVersion, osVulns, err := scanner.Scan()
			if err != nil {
				return nil, xerrors.Errorf("failed to scan the image: %w", err)
			}
			imageDetail := fmt.Sprintf("%s (%s %s)", target, osFamily, osVersion)
			results = append(results, report.Result{
				FileName:        imageDetail,
				Vulnerabilities: osVulns,
			})

		}
	}

	if utils.StringInSlice("library", scanOptions.VulnType) {
		libVulns, err := s.libScanner.Scan(files)
		if err != nil {
			return nil, xerrors.Errorf("failed to scan libraries: %w", err)
		}

		var libResults report.Results
		for path, vulns := range libVulns {
			libResults = append(libResults, report.Result{
				FileName:        path,
				Vulnerabilities: vulns,
			})
		}
		sort.Slice(libResults, func(i, j int) bool {
			return libResults[i].FileName < libResults[j].FileName
		})
		results = append(results, libResults...)
	}

	return results, nil
}

func (s Scanner) ScanFile(f *os.File) (report.Results, error) {
	vulns, err := s.libScanner.ScanFile(f)
	if err != nil {
		return nil, xerrors.Errorf("failed to scan libraries in file: %w", err)
	}
	results := report.Results{
		{FileName: f.Name(), Vulnerabilities: vulns},
	}
	return results, nil
}

func openStream(path string) (*os.File, error) {
	if path == "-" {
		if terminal.IsTerminal(0) {
			flag.Usage()
			os.Exit(64)
		} else {
			return os.Stdin, nil
		}
	}
	return os.Open(path)
}
