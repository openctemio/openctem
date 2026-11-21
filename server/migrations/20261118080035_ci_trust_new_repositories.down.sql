-- ci_trust_new_repositories (down)
DELETE FROM event_types WHERE id = 'ci.new_repository_group';
DROP TABLE IF EXISTS ci_trust_new_repositories;
