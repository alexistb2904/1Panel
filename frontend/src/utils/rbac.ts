import { getUserInfo } from '@/api/modules/auth';
import { getEnterpriseUserInfo } from '@/extensions/xpack';
import type { RouteMeta } from 'vue-router';
import { GlobalStore } from '@/store';

export type PermissionMetaValue = string | string[];

type RouteAccessMeta = {
    adminOnly?: boolean;
    protectedRoleOnly?: boolean;
    permission?: PermissionMetaValue;
};

type RouteAccessTarget = {
    matched: Array<{
        meta?: RouteMeta & RouteAccessMeta;
    }>;
};

// Upstream Community UI still uses a legacy underscore vocabulary in many
// routes/buttons. Keep the compatibility translation in one place so the UI
// mirrors the new backend capability model without duplicating authorization.
const legacyPermissionAliases: Record<string, string[]> = {
    website_view: ['website.view'],
    website_manage: ['website.create', 'website.update', 'website.delete'],
    website_cert_view: ['website.ssl.view'],
    website_cert_manage: ['website.ssl.manage'],
    website_runtime_view: ['runtime.view'],
    website_runtime_manage: ['runtime.create', 'runtime.edit', 'runtime.start', 'runtime.stop', 'runtime.restart'],
    database_view: ['database.view'],
    database_manage: ['database.create', 'database.update', 'database.delete', 'database.credentials.rotate'],
    container_view: ['docker.container.view', 'docker.compose.view'],
    container_manage: [
        'docker.container.create',
        'docker.container.edit',
        'docker.container.start',
        'docker.container.stop',
        'docker.container.restart',
        'docker.compose.create',
        'docker.compose.edit',
        'docker.compose.deploy',
    ],
    file_view: ['website.files.read'],
    file_manage: ['website.files.write', 'website.files.delete'],
    log_operation_view: ['audit.view'],
    setting_view: ['settings.view'],
    setting_manage: ['settings.manage'],
};

export const syncAuthInfo = async (currentNode?: string) => {
    const globalStore = GlobalStore();
    const storeCurrentNode = globalStore.currentNode;
    if (!globalStore.isEnterprise) {
        const res = await getUserInfo();
        globalStore.setAuthInfo({
            isAdmin: res.data.role === 'ADMIN',
            permissions: res.data.permissions || [],
            masterOnlyPermissions: res.data.masterOnlyPermissions || [],
            nodeRoles: res.data.nodeRoles || [],
        });
        return res.data;
    }
    const res = await getEnterpriseUserInfo(currentNode ?? storeCurrentNode);
    globalStore.setAuthInfo({
        isAdmin: res.data.role === 'ADMIN',
        permissions: res.data.permissions || [],
        masterOnlyPermissions: res.data.masterOnlyPermissions || [],
        nodeRoles: res.data.nodeRoles || [],
    });
    return res.data;
};

export const hasPermission = (permission: string) => {
    const store = GlobalStore();
    if (store.hasPermission(permission)) {
        return true;
    }
    const aliases = legacyPermissionAliases[permission] || [];
    return aliases.some((capability) => store.hasPermission(capability));
};

export const hasPermissionMetaAccess = (permission?: PermissionMetaValue) => {
    if (!permission) {
        return true;
    }
    if (Array.isArray(permission)) {
        const permissions = permission.filter(Boolean);
        return permissions.length === 0 || permissions.some((item) => hasPermission(item));
    }
    return hasPermission(permission);
};

export const hasRouteRoleAccess = (meta?: RouteMeta & RouteAccessMeta) => {
    const globalStore = GlobalStore();

    if (!meta) {
        return true;
    }
    if (globalStore.isAdmin) {
        return true;
    }
    if (meta.adminOnly && !globalStore.isAdmin) {
        return false;
    }
    if (meta.protectedRoleOnly) {
        return globalStore.isNodeAdmin;
    }
    return true;
};

export const hasRoutePermissionAccess = (route: RouteAccessTarget) => {
    return route.matched.every((record) => hasPermissionMetaAccess(record.meta?.permission));
};

export const hasRouteAccess = (route: RouteAccessTarget) => {
    return route.matched.every((record) => hasRouteRoleAccess(record.meta)) && hasRoutePermissionAccess(route);
};
