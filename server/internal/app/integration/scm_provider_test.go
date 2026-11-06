package integration

import (
	"testing"

	"github.com/openctemio/openctem/api/internal/infra/scm"
	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
)

// The integration and SCM-factory vocabularies differ for Azure DevOps. Every
// SCM provider the integration domain accepts must map to one the factory can
// build, or that integration fails every test/sync with "unsupported provider".
func TestToSCMProvider_EverySCMProviderHasAFactoryClient(t *testing.T) {
	f := scm.NewClientFactory()
	for _, p := range []integrationdom.Provider{
		integrationdom.ProviderGitHub,
		integrationdom.ProviderGitLab,
		integrationdom.ProviderBitbucket,
		integrationdom.ProviderAzureDevOps,
	} {
		if _, err := f.CreateClient(scm.Config{Provider: toSCMProvider(p), AccessToken: "t"}); err != nil {
			t.Errorf("%s: factory cannot build a client: %v", p, err)
		}
	}
	if got := toSCMProvider(integrationdom.ProviderAzureDevOps); got != scm.ProviderAzure {
		t.Errorf("azure_devops must map to %q, got %q", scm.ProviderAzure, got)
	}
}
