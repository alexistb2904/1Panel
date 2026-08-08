package rbac

const (
	RoleAdministrator   = "administrator"
	RoleDeveloper       = "developer"
	RoleSecurityAdvisor = "security_advisor"
	RoleUser            = "user"
	RoleVisitor         = "visitor"
)

type RoleDefinition struct {
	Key         string
	Name        string
	Description string
	Sort        int
	Permissions []string
}

// Built-in non-admin roles intentionally contain only capabilities that have a
// concrete Core+Agent enforcement path in Community RBAC. Unclassified or
// deliberately admin-only legacy permissions remain in the catalog for future
// implementation, but are not advertised through a role until their server-side
// execution boundary is project-confined and its ownership lifecycle is
// synchronously observable.
var DefaultRoleDefinitions = []RoleDefinition{
	{
		Key: RoleAdministrator, Name: "Administrator",
		Description: "Full platform administration. This role is equivalent to trusted infrastructure administrator access.",
		Sort: 10, Permissions: AllPermissionCodes(),
	},
	{
		Key: RoleDeveloper, Name: "Developer",
		Description: "Autonomous application developer on assigned projects without global host or access-control privileges.",
		Sort: 20,
		Permissions: []string{
			"project.view",
			"website.view", "website.create", "website.update", "website.delete",
			"website.domain.view", "website.domain.manage",
			"website.files.read", "website.files.write", "website.files.delete",
			"website.logs.view",
			"website.runtime.view", "website.runtime.restart",
			"website.config.view", "website.config.edit",
			"website.ssl.view",
			"database.view", "database.create", "database.update", "database.delete", "database.credentials.rotate",
			"runtime.view", "runtime.edit", "runtime.start", "runtime.stop", "runtime.restart",
			"docker.container.view", "docker.container.create", "docker.container.edit", "docker.container.delete",
			"docker.container.start", "docker.container.stop", "docker.container.restart", "docker.container.logs", "docker.container.stats", "docker.container.exec",
			"docker.compose.view", "docker.compose.edit", "docker.compose.deploy", "docker.compose.stop", "docker.compose.delete",
		},
	},
	{
		Key: RoleSecurityAdvisor, Name: "Security Advisor",
		Description: "Cross-cutting security visibility over explicitly implemented RBAC surfaces, without destructive administration rights or application secret access.",
		Sort: 30,
		Permissions: []string{
			"access.user.view", "access.role.view", "audit.view", "audit.export",
			"project.view",
			"website.view", "website.domain.view", "website.logs.view", "website.runtime.view", "website.config.view", "website.ssl.view",
			"database.view", "runtime.view",
			"docker.container.view", "docker.container.logs", "docker.container.stats",
			"docker.compose.view",
		},
	},
	{
		Key: RoleUser, Name: "User",
		Description: "Operational user on assigned sites: can work with site files and inspect the application without infrastructure administration rights.",
		Sort: 40,
		Permissions: []string{
			"project.view",
			"website.view", "website.domain.view",
			"website.files.read", "website.files.write", "website.files.delete",
			"website.logs.view", "website.runtime.view", "website.ssl.view",
		},
	},
	{
		Key: RoleVisitor, Name: "Visitor",
		Description: "Read-only overview of explicitly assigned projects and sites, with no file, secret or administrative access.",
		Sort: 50,
		Permissions: []string{"project.view", "website.view", "website.runtime.view"},
	},
}
