package main

import (
	"context"
	"io"

	"github.com/openctemio/openctem/api/internal/app/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// letterContext is the attachment context of an authorization letter's
// file (RFC-065 §13): the generic attachment routes show it only to its
// uploader and administrators, and never delete it.
const letterContext = "authorization_letter"

// letterFiles keeps authorization letter files in the attachment storage
// (scope.LetterFileStore).
type letterFiles struct {
	svc *integration.AttachmentService
}

func (f letterFiles) Store(ctx context.Context, tenantID, uploadedBy shared.ID, filename, contentType string, size int64, r io.Reader) (shared.ID, error) {
	att, err := f.svc.Upload(ctx, integration.UploadInput{
		TenantID: tenantID.String(), Filename: filename, ContentType: contentType, Size: size,
		Reader: r, UploadedBy: uploadedBy.String(), ContextType: letterContext,
	})
	if err != nil {
		return shared.ID{}, err
	}
	return att.ID(), nil
}

func (f letterFiles) Open(ctx context.Context, tenantID, attachmentID shared.ID) (io.ReadCloser, string, string, error) {
	return f.svc.Download(ctx, tenantID.String(), attachmentID.String())
}
