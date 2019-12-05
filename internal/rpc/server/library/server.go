package library

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/detector/library"

	"github.com/google/wire"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/internal/rpc"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/vulnerability"
	proto "github.com/aquasecurity/trivy/rpc/detector"
)

var SuperSet = wire.NewSet(
	library.SuperSet,
	vulnerability.SuperSet,
	wire.Bind(new(vulnerability.Operation), new(vulnerability.Client)),
	NewServer,
)

type Server struct {
	detector   library.DetectorOperation
	vulnClient vulnerability.Operation
}

func NewServer(detector library.DetectorOperation, vulnClient vulnerability.Operation) *Server {
	return &Server{detector: detector, vulnClient: vulnClient}
}

func (s *Server) Detect(ctx context.Context, req *proto.LibDetectRequest) (res *proto.DetectResponse, err error) {
	vulns, err := s.detector.Detect(req.FilePath, rpc.ConvertFromRpcLibraries(req.Libraries))
	if err != nil {
		log.Logger.Warn(err)
		return nil, xerrors.Errorf("failed to detect library vulnerabilities: %w", err)
	}

	s.vulnClient.FillInfo(vulns, false)

	return &proto.DetectResponse{Vulnerabilities: rpc.ConvertToRpcVulns(vulns)}, nil
}
