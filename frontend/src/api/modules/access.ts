import http from '@/api';
import { AccessControl } from '@/api/interface/access';

export const listAccessUsers = () => http.get<AccessControl.User[]>('/core/access/users');
export const createAccessUser = (params: {
    username: string;
    displayName?: string;
    email?: string;
    password: string;
    requireMFA: boolean;
    bindings: AccessControl.BindingInput[];
}) => http.post('/core/access/users', params);
export const updateAccessUser = (params: { id: number; displayName?: string; email?: string; requireMFA: boolean }) =>
    http.post('/core/access/users/update', params);
export const updateAccessUserStatus = (params: { id: number; status: 'active' | 'disabled' }) =>
    http.post('/core/access/users/status', params);
export const resetAccessUserPassword = (params: { id: number; password: string }) =>
    http.post('/core/access/users/password', params);
export const replaceAccessUserBindings = (params: { id: number; bindings: AccessControl.BindingInput[] }) =>
    http.post('/core/access/users/bindings', params);

export const listAccessRoles = () => http.get<AccessControl.Role[]>('/core/access/roles');
export const listAccessProjects = () => http.get<AccessControl.Project[]>('/core/access/projects');
export const listMyAccessProjects = () => http.get<AccessControl.Project[]>('/core/access/me/projects');
export const createAccessProject = (params: { name: string; slug: string; description?: string; rootPath?: string }) =>
    http.post('/core/access/projects', params);
export const updateAccessProject = (params: {
    id: number;
    name: string;
    slug: string;
    description?: string;
    status: 'active' | 'archived';
}) => http.post('/core/access/projects/update', params);
export const replaceAccessProjectResources = (params: { id: number; resources: AccessControl.ProjectResource[] }) =>
    http.post('/core/access/projects/resources', params);
export const updateAccessProjectRoot = (params: { id: number; nodeId: number; rootPath: string; enabled?: boolean }) =>
    http.post('/core/access/projects/security/root', params);

export const listAccessNodes = () => http.get<AccessControl.Node[]>('/core/access/nodes');
export const createAccessNode = (params: { externalKey: string; name: string }) => http.post('/core/access/nodes', params);
export const updateAccessNode = (params: { id: number; externalKey: string; name: string; status: 'active' | 'disabled' }) =>
    http.post('/core/access/nodes/update', params);

export const listServiceAccounts = () => http.get<AccessControl.ServiceAccount[]>('/core/access/service-accounts');
export const createServiceAccount = (params: {
    name: string;
    ipWhiteList?: string;
    expiresAt?: string | null;
    bindings: AccessControl.BindingInput[];
}) => http.post<AccessControl.ServiceAccountToken>('/core/access/service-accounts', params);
export const updateServiceAccount = (params: {
    id: number;
    name: string;
    ipWhiteList?: string;
    expiresAt?: string | null;
    status: 'active' | 'disabled';
    bindings: AccessControl.BindingInput[];
}) => http.post('/core/access/service-accounts/update', params);
export const rotateServiceAccount = (id: number) =>
    http.post<AccessControl.ServiceAccountToken>('/core/access/service-accounts/rotate', { id });

export const searchAccessAudit = (params: {
    page: number;
    pageSize: number;
    decision?: string;
    subjectType?: string;
    action?: string;
    resourceType?: string;
    info?: string;
}) => http.post<AccessControl.Page<AccessControl.AuditEvent>>('/core/access/audit/search', params);
