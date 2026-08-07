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

var DefaultRoleDefinitions = []RoleDefinition{
	{
		Key:         RoleAdministrator,
		Name:        "Administrator",
		Description: "Full platform administration. This role is equivalent to trusted infrastructure administrator access.",
		Sort:        10,
		Permissions: AllPermissionCodes(),
	},
	{
		Key:         RoleDeveloper,
		Name:        "Developer",
		Description: "Autonomous application developer on assigned projects without global host or access-control privileges.",
		Sort:        20,
		Permissions: []string{
			"dashboard.view", "monitoring.view", "project.view", "project.update",
			"website.view", "website.create", "website.update", "website.delete",
			"website.domain.view", "website.domain.manage",
			"website.files.read", "website.files.write", "website.files.delete",
			"website.logs.view", "website.logs.download",
			"website.runtime.view", "website.runtime.restart", "website.runtime.manage",
			"website.config.view", "website.config.edit",
			"website.ssl.view", "website.ssl.manage",
			"website.ftp.view", "website.ftp.manage",
			"website.backup.view", "website.backup.create", "website.backup.download", "website.backup.restore", "website.backup.delete",
			"website.env.view", "website.env.edit", "website.env.secrets.view", "website.shell",
			"database.view", "database.create", "database.update", "database.delete",
			"database.query.read", "database.query.write",
			"database.credentials.view", "database.credentials.rotate",
			"database.backup.view", "database.backup.create", "database.backup.download", "database.backup.restore", "database.backup.delete",
			"runtime.view", "runtime.create", "runtime.edit", "runtime.delete",
			"runtime.start", "runtime.stop", "runtime.restart", "runtime.logs.view",
			"runtime.env.view", "runtime.env.edit", "runtime.env.secrets.view", "runtime.deploy", "runtime.command.edit",
			"cron.view", "cron.create", "cron.edit", "cron.run", "cron.delete",
			"certificate.view", "certificate.manage",
			"docker.container.view", "docker.container.create", "docker.container.edit", "docker.container.delete",
			"docker.container.start", "docker.container.stop", "docker.container.restart", "docker.container.logs", "docker.container.stats", "docker.container.exec",
			"docker.compose.view", "docker.compose.create", "docker.compose.edit", "docker.compose.deploy", "docker.compose.stop", "docker.compose.delete", "docker.compose.logs",
			"docker.compose.env.view", "docker.compose.env.edit", "docker.compose.secrets.view",
			"docker.image.view", "docker.image.pull", "docker.image.build",
			"docker.volume.view", "docker.network.view", "docker.registry.view",
		},
	},
	{
		Key:         RoleSecurityAdvisor,
		Name:        "Security Advisor",
		Description: "Cross-cutting security visibility and audit access without routine destructive administration rights.",
		Sort:        30,
		Permissions: []string{
			"dashboard.view", "monitoring.view", "node.view", "settings.view",
			"access.user.view", "access.role.view",
			"audit.view", "audit.export", "loginlog.view", "security.view", "firewall.view",
			"project.view",
			"website.view", "website.domain.view", "website.logs.view", "website.runtime.view", "website.config.view", "website.ssl.view", "website.backup.view",
			"database.view", "database.backup.view",
			"runtime.view", "runtime.logs.view", "runtime.env.view",
			"certificate.view",
			"docker.container.view", "docker.container.logs", "docker.container.stats",
			"docker.compose.view", "docker.compose.logs", "docker.compose.env.view",
			"docker.image.view", "docker.volume.view", "docker.network.view", "docker.registry.view",
		},
	},
	{
		Key:         RoleUser,
		Name:        "User",
		Description: "Operational user on assigned sites: can work with site files and inspect the application without infrastructure administration rights.",
		Sort:        40,
		Permissions: []string{
			"dashboard.view", "project.view",
			"website.view", "website.domain.view",
			"website.files.read", "website.files.write", "website.files.delete",
			"website.logs.view", "website.runtime.view", "website.ssl.view", "website.ftp.view",
			"website.backup.view", "website.backup.create",
		},
	},
	{
		Key:         RoleVisitor,
		Name:        "Visitor",
		Description: "Read-only overview of explicitly assigned projects and sites, with no file, secret or administrative access.",
		Sort:        50,
		Permissions: []string{
			"dashboard.view", "monitoring.view", "project.view", "website.view", "website.runtime.view",
		},
	},
}
