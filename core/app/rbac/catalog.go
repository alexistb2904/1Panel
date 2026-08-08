package rbac

const (
	RiskLow      = "low"
	RiskMedium   = "medium"
	RiskHigh     = "high"
	RiskCritical = "critical"
)

type PermissionDefinition struct {
	Code         string
	ResourceType string
	Feature      string
	Action       string
	RiskLevel    string
	Description  string
}

func permission(code, resourceType, feature, action, risk, description string) PermissionDefinition {
	return PermissionDefinition{Code: code, ResourceType: resourceType, Feature: feature, Action: action, RiskLevel: risk, Description: description}
}

// PermissionCatalog is deliberately capability-oriented. UI tabs are derived
// from these permissions; hiding a tab is never considered an authorization
// boundary on its own.
var PermissionCatalog = []PermissionDefinition{
	permission("dashboard.view", "dashboard", "overview", "view", RiskLow, "View dashboard summaries"),
	permission("monitoring.view", "monitoring", "metrics", "view", RiskLow, "View host and application metrics"),
	permission("node.view", "node", "overview", "view", RiskLow, "View nodes"),
	permission("node.manage", "node", "configuration", "manage", RiskCritical, "Manage node configuration and lifecycle"),
	permission("settings.view", "settings", "configuration", "view", RiskMedium, "View system settings"),
	permission("settings.manage", "settings", "configuration", "manage", RiskCritical, "Modify system settings"),
	permission("access.user.view", "access", "users", "view", RiskMedium, "View users"),
	permission("access.user.manage", "access", "users", "manage", RiskCritical, "Create, modify, disable and delete users"),
	permission("access.role.view", "access", "roles", "view", RiskMedium, "View roles and permissions"),
	permission("access.role.manage", "access", "roles", "manage", RiskCritical, "Modify roles and access bindings"),
	permission("audit.view", "audit", "operations", "view", RiskMedium, "View operation audit logs"),
	permission("audit.export", "audit", "operations", "export", RiskMedium, "Export operation audit logs"),
	permission("loginlog.view", "audit", "login", "view", RiskMedium, "View authentication logs"),
	permission("security.view", "security", "overview", "view", RiskMedium, "View security configuration and posture"),
	permission("security.session.revoke", "security", "sessions", "revoke", RiskHigh, "Revoke user sessions"),
	permission("firewall.view", "firewall", "rules", "view", RiskMedium, "View firewall rules"),
	permission("firewall.manage", "firewall", "rules", "manage", RiskCritical, "Modify firewall rules"),
	permission("terminal.host", "terminal", "host", "open", RiskCritical, "Open an unrestricted host terminal"),

	permission("project.view", "project", "overview", "view", RiskLow, "View assigned projects"),
	permission("project.create", "project", "lifecycle", "create", RiskHigh, "Create projects"),
	permission("project.update", "project", "lifecycle", "update", RiskMedium, "Update project metadata"),
	permission("project.delete", "project", "lifecycle", "delete", RiskHigh, "Delete projects"),
	permission("project.resource.manage", "project", "resources", "manage", RiskHigh, "Attach and detach resources from a project"),
	permission("project.access.manage", "project", "access", "manage", RiskCritical, "Manage project access bindings"),

	permission("website.view", "website", "overview", "view", RiskLow, "View websites"),
	permission("website.create", "website", "lifecycle", "create", RiskMedium, "Create websites"),
	permission("website.update", "website", "lifecycle", "update", RiskMedium, "Update website configuration"),
	permission("website.delete", "website", "lifecycle", "delete", RiskHigh, "Delete websites"),
	permission("website.domain.view", "website", "domain", "view", RiskLow, "View website domains"),
	permission("website.domain.manage", "website", "domain", "manage", RiskMedium, "Manage website domains and redirects"),
	permission("website.files.read", "website", "files", "read", RiskMedium, "Read files within the website root"),
	permission("website.files.write", "website", "files", "write", RiskHigh, "Create and modify files within the website root"),
	permission("website.files.delete", "website", "files", "delete", RiskHigh, "Delete files within the website root"),
	permission("website.logs.view", "website", "logs", "view", RiskMedium, "View website logs"),
	permission("website.logs.download", "website", "logs", "download", RiskMedium, "Download website logs"),
	permission("website.runtime.view", "website", "runtime", "view", RiskLow, "View website runtime information"),
	permission("website.runtime.restart", "website", "runtime", "restart", RiskMedium, "Restart the website runtime"),
	permission("website.runtime.manage", "website", "runtime", "manage", RiskHigh, "Change website runtime configuration"),
	permission("website.config.view", "website", "configuration", "view", RiskMedium, "View web server configuration"),
	permission("website.config.edit", "website", "configuration", "edit", RiskHigh, "Edit web server configuration"),
	permission("website.ssl.view", "website", "ssl", "view", RiskLow, "View certificate metadata"),
	permission("website.ssl.manage", "website", "ssl", "manage", RiskHigh, "Issue, replace and configure certificates"),
	permission("website.ssl.private_key_export", "website", "ssl", "private_key_export", RiskCritical, "Export website TLS private keys"),
	permission("website.ftp.view", "website", "ftp", "view", RiskMedium, "View website FTP/SFTP access configuration"),
	permission("website.ftp.manage", "website", "ftp", "manage", RiskHigh, "Manage website FTP/SFTP accounts"),
	permission("website.backup.view", "website", "backup", "view", RiskLow, "View website backups"),
	permission("website.backup.create", "website", "backup", "create", RiskMedium, "Create website backups"),
	permission("website.backup.download", "website", "backup", "download", RiskHigh, "Download website backups"),
	permission("website.backup.restore", "website", "backup", "restore", RiskHigh, "Restore website backups"),
	permission("website.backup.delete", "website", "backup", "delete", RiskHigh, "Delete website backups"),
	permission("website.env.view", "website", "environment", "view", RiskMedium, "View non-secret environment configuration"),
	permission("website.env.edit", "website", "environment", "edit", RiskHigh, "Modify environment configuration"),
	permission("website.env.secrets.view", "website", "environment", "secrets_view", RiskHigh, "Reveal website environment secrets"),
	permission("website.shell", "website", "shell", "open", RiskHigh, "Open a shell constrained to the website account"),

	permission("database.view", "database", "overview", "view", RiskLow, "View databases"),
	permission("database.create", "database", "lifecycle", "create", RiskMedium, "Create databases"),
	permission("database.update", "database", "lifecycle", "update", RiskMedium, "Update database settings"),
	permission("database.delete", "database", "lifecycle", "delete", RiskHigh, "Delete databases"),
	permission("database.query.read", "database", "query", "read", RiskMedium, "Execute read-only database queries"),
	permission("database.query.write", "database", "query", "write", RiskHigh, "Execute write database queries"),
	permission("database.query.admin", "database", "query", "admin", RiskCritical, "Execute privileged database administration queries"),
	permission("database.credentials.view", "database", "credentials", "view", RiskHigh, "Reveal database credentials"),
	permission("database.credentials.rotate", "database", "credentials", "rotate", RiskHigh, "Rotate database credentials"),
	permission("database.backup.view", "database", "backup", "view", RiskLow, "View database backups"),
	permission("database.backup.create", "database", "backup", "create", RiskMedium, "Create database backups"),
	permission("database.backup.download", "database", "backup", "download", RiskHigh, "Download database backups"),
	permission("database.backup.restore", "database", "backup", "restore", RiskHigh, "Restore database backups"),
	permission("database.backup.delete", "database", "backup", "delete", RiskHigh, "Delete database backups"),

	permission("runtime.view", "runtime", "overview", "view", RiskLow, "View application runtimes"),
	permission("runtime.create", "runtime", "lifecycle", "create", RiskMedium, "Create application runtimes"),
	permission("runtime.edit", "runtime", "lifecycle", "edit", RiskHigh, "Edit application runtime configuration"),
	permission("runtime.delete", "runtime", "lifecycle", "delete", RiskHigh, "Delete application runtimes"),
	permission("runtime.start", "runtime", "process", "start", RiskMedium, "Start an application runtime"),
	permission("runtime.stop", "runtime", "process", "stop", RiskMedium, "Stop an application runtime"),
	permission("runtime.restart", "runtime", "process", "restart", RiskMedium, "Restart an application runtime"),
	permission("runtime.logs.view", "runtime", "logs", "view", RiskMedium, "View runtime logs"),
	permission("runtime.env.view", "runtime", "environment", "view", RiskMedium, "View non-secret runtime environment configuration"),
	permission("runtime.env.edit", "runtime", "environment", "edit", RiskHigh, "Modify runtime environment configuration"),
	permission("runtime.env.secrets.view", "runtime", "environment", "secrets_view", RiskHigh, "Reveal runtime environment secrets"),
	permission("runtime.deploy", "runtime", "deployment", "deploy", RiskHigh, "Deploy application runtime changes"),
	permission("runtime.command.edit", "runtime", "process", "command_edit", RiskHigh, "Edit runtime start/build commands"),

	permission("cron.view", "cron", "jobs", "view", RiskLow, "View project cron jobs"),
	permission("cron.create", "cron", "jobs", "create", RiskHigh, "Create project cron jobs"),
	permission("cron.edit", "cron", "jobs", "edit", RiskHigh, "Edit project cron jobs"),
	permission("cron.run", "cron", "jobs", "run", RiskHigh, "Run project cron jobs immediately"),
	permission("cron.delete", "cron", "jobs", "delete", RiskHigh, "Delete project cron jobs"),
	permission("cron.system.manage", "cron", "system", "manage", RiskCritical, "Manage host-level cron jobs"),

	permission("certificate.view", "certificate", "metadata", "view", RiskLow, "View certificate metadata"),
	permission("certificate.manage", "certificate", "lifecycle", "manage", RiskHigh, "Manage certificates"),
	permission("certificate.private_key_export", "certificate", "secret", "export", RiskCritical, "Export certificate private keys"),
	permission("backup.destination.manage", "backup", "destination", "manage", RiskCritical, "Manage global backup destinations and credentials"),

	permission("docker.container.view", "container", "overview", "view", RiskLow, "View assigned containers"),
	permission("docker.container.create", "container", "lifecycle", "create", RiskHigh, "Create containers subject to project policy"),
	permission("docker.container.edit", "container", "lifecycle", "edit", RiskHigh, "Edit containers subject to project policy"),
	permission("docker.container.delete", "container", "lifecycle", "delete", RiskHigh, "Delete assigned containers"),
	permission("docker.container.start", "container", "process", "start", RiskMedium, "Start assigned containers"),
	permission("docker.container.stop", "container", "process", "stop", RiskMedium, "Stop assigned containers"),
	permission("docker.container.restart", "container", "process", "restart", RiskMedium, "Restart assigned containers"),
	permission("docker.container.logs", "container", "logs", "view", RiskMedium, "View assigned container logs"),
	permission("docker.container.stats", "container", "metrics", "view", RiskLow, "View assigned container metrics"),
	permission("docker.container.exec", "container", "shell", "exec", RiskHigh, "Execute commands inside assigned containers"),
	permission("docker.compose.view", "compose", "overview", "view", RiskLow, "View assigned Compose projects"),
	permission("docker.compose.create", "compose", "lifecycle", "create", RiskHigh, "Create Compose projects subject to project policy"),
	permission("docker.compose.edit", "compose", "configuration", "edit", RiskHigh, "Edit Compose projects subject to project policy"),
	permission("docker.compose.deploy", "compose", "deployment", "deploy", RiskHigh, "Deploy assigned Compose projects"),
	permission("docker.compose.stop", "compose", "process", "stop", RiskMedium, "Stop assigned Compose projects"),
	permission("docker.compose.delete", "compose", "lifecycle", "delete", RiskHigh, "Delete assigned Compose projects"),
	permission("docker.compose.logs", "compose", "logs", "view", RiskMedium, "View assigned Compose logs"),
	permission("docker.compose.env.view", "compose", "environment", "view", RiskMedium, "View non-secret Compose environment"),
	permission("docker.compose.env.edit", "compose", "environment", "edit", RiskHigh, "Modify Compose environment"),
	permission("docker.compose.secrets.view", "compose", "environment", "secrets_view", RiskHigh, "Reveal Compose secrets"),
	permission("docker.image.view", "image", "overview", "view", RiskLow, "View Docker images"),
	permission("docker.image.pull", "image", "lifecycle", "pull", RiskMedium, "Pull Docker images"),
	permission("docker.image.build", "image", "lifecycle", "build", RiskHigh, "Build Docker images"),
	permission("docker.image.delete", "image", "lifecycle", "delete", RiskHigh, "Delete Docker images"),
	permission("docker.volume.view", "volume", "overview", "view", RiskLow, "View Docker volumes"),
	permission("docker.volume.manage", "volume", "lifecycle", "manage", RiskCritical, "Create or delete Docker volumes"),
	permission("docker.network.view", "network", "overview", "view", RiskLow, "View Docker networks"),
	permission("docker.network.manage", "network", "lifecycle", "manage", RiskCritical, "Create or delete Docker networks"),
	permission("docker.registry.view", "registry", "configuration", "view", RiskMedium, "View registry configuration without secrets"),
	permission("docker.registry.manage", "registry", "configuration", "manage", RiskCritical, "Manage Docker registries and credentials"),
	permission("docker.system.prune", "docker", "system", "prune", RiskCritical, "Prune Docker resources globally"),
	permission("docker.system.configure", "docker", "system", "configure", RiskCritical, "Configure the Docker engine"),
}

func AllPermissionCodes() []string {
	codes := make([]string, 0, len(PermissionCatalog))
	for _, item := range PermissionCatalog {
		codes = append(codes, item.Code)
	}
	return codes
}
