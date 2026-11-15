# ci-env: the environment level
path "vs/data/pipelines/{{identity.entity.aliases.auth_jwt_1a2b3c.metadata.org}}/{{identity.entity.aliases.auth_jwt_1a2b3c.metadata.repo}}/{{identity.entity.aliases.auth_jwt_1a2b3c.metadata.env}}/+" { capabilities = ["read"] }
path "vs/metadata/pipelines/{{identity.entity.aliases.auth_jwt_1a2b3c.metadata.org}}/{{identity.entity.aliases.auth_jwt_1a2b3c.metadata.repo}}/{{identity.entity.aliases.auth_jwt_1a2b3c.metadata.env}}/" { capabilities = ["list"] }
path "vs/metadata/pipelines/{{identity.entity.aliases.auth_jwt_1a2b3c.metadata.org}}/{{identity.entity.aliases.auth_jwt_1a2b3c.metadata.repo}}/{{identity.entity.aliases.auth_jwt_1a2b3c.metadata.env}}/+" { capabilities = ["read"] }
