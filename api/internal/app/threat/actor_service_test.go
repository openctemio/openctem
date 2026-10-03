package threat

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/threatactor"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// actorRepoStub keeps the actor Create was given.
type actorRepoStub struct {
	threatactor.Repository
	created *threatactor.ThreatActor
}

func (r *actorRepoStub) Create(_ context.Context, a *threatactor.ThreatActor) error {
	r.created = a
	return nil
}

func TestCreateActor_KeepsAliasesAndTags(t *testing.T) {
	repo := &actorRepoStub{}
	svc := NewActorService(repo, logger.NewNop())

	actor, err := svc.CreateActor(context.Background(), CreateActorInput{
		TenantID:  shared.NewID().String(),
		Name:      "FIN7",
		ActorType: "cybercrime",
		Aliases:   []string{"Carbanak", "Navigator Group"},
		Tags:      []string{"pos", "phishing"},
	})
	require.NoError(t, err)

	assert.Equal(t, []string{"Carbanak", "Navigator Group"}, actor.Aliases())
	assert.Equal(t, []string{"pos", "phishing"}, actor.Tags())
	require.NotNil(t, repo.created)
	assert.Equal(t, actor.Aliases(), repo.created.Aliases())
	assert.Equal(t, actor.Tags(), repo.created.Tags())
}
