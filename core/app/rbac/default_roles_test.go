package rbac

import "testing"

func TestDefaultRoleDefinitionsReferenceKnownPermissions(t *testing.T) {
	known := make(map[string]struct{}, len(PermissionCatalog))
	for _, permission := range PermissionCatalog {
		known[permission.Code] = struct{}{}
	}
	for _, role := range DefaultRoleDefinitions {
		for _, code := range role.Permissions {
			if _, ok := known[code]; !ok {
				t.Fatalf("role %s references unknown permission %s", role.Key, code)
			}
		}
	}
}

func TestAdministratorGetsEntireCatalog(t *testing.T) {
	role := findRole(t, RoleAdministrator)
	if len(role.Permissions) != len(PermissionCatalog) {
		t.Fatalf("administrator has %d permissions, catalog has %d", len(role.Permissions), len(PermissionCatalog))
	}
}

func TestDeveloperIsAutonomousButNotPlatformAdmin(t *testing.T) {
	role := findRole(t, RoleDeveloper)
	mustHave(t, role, "website.create", "website.delete", "database.create", "database.delete", "runtime.deploy", "docker.compose.edit", "docker.container.exec")
	mustNotHave(t, role, "terminal.host", "settings.manage", "node.manage", "access.user.manage", "access.role.manage", "firewall.manage", "docker.system.configure", "docker.registry.manage")
}

func TestSecurityAdvisorIsNonDestructiveByDefault(t *testing.T) {
	role := findRole(t, RoleSecurityAdvisor)
	mustHave(t, role, "security.view", "audit.view", "loginlog.view", "firewall.view", "access.user.view", "access.role.view")
	mustNotHave(t, role, "firewall.manage", "access.user.manage", "access.role.manage", "terminal.host", "website.files.write", "database.query.write", "docker.container.exec")
}

func TestUserAndVisitorSeparation(t *testing.T) {
	user := findRole(t, RoleUser)
	visitor := findRole(t, RoleVisitor)
	mustHave(t, user, "website.files.read", "website.files.write", "website.files.delete", "website.backup.create")
	mustNotHave(t, visitor, "website.files.read", "website.files.write", "website.logs.view", "website.backup.create")
}

func findRole(t *testing.T, key string) RoleDefinition {
	t.Helper()
	for _, role := range DefaultRoleDefinitions {
		if role.Key == key {
			return role
		}
	}
	t.Fatalf("role %s not found", key)
	return RoleDefinition{}
}

func mustHave(t *testing.T, role RoleDefinition, codes ...string) {
	t.Helper()
	set := make(map[string]struct{}, len(role.Permissions))
	for _, code := range role.Permissions {
		set[code] = struct{}{}
	}
	for _, code := range codes {
		if _, ok := set[code]; !ok {
			t.Errorf("role %s should contain %s", role.Key, code)
		}
	}
}

func mustNotHave(t *testing.T, role RoleDefinition, codes ...string) {
	t.Helper()
	set := make(map[string]struct{}, len(role.Permissions))
	for _, code := range role.Permissions {
		set[code] = struct{}{}
	}
	for _, code := range codes {
		if _, ok := set[code]; ok {
			t.Errorf("role %s must not contain %s", role.Key, code)
		}
	}
}
