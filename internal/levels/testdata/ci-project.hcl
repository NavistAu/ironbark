# ci-project: the repo level, plus level metadata for discovery
path "vs/data/pipelines/{{identity.entity.aliases.auth_jwt_1a2b3c.metadata.org}}/{{identity.entity.aliases.auth_jwt_1a2b3c.metadata.repo}}/+" { capabilities = ["read"] }
path "vs/metadata/pipelines/{{identity.entity.aliases.auth_jwt_1a2b3c.metadata.org}}/{{identity.entity.aliases.auth_jwt_1a2b3c.metadata.repo}}/" { capabilities = ["list"] }
path "vs/metadata/pipelines/{{identity.entity.aliases.auth_jwt_1a2b3c.metadata.org}}/{{identity.entity.aliases.auth_jwt_1a2b3c.metadata.repo}}/+/" { capabilities = ["read"] }
