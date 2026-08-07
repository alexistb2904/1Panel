export namespace AccessControl {
    export interface BindingInput {
        roleKey: string;
        scopeType: 'global' | 'node' | 'project';
        scopeId: string;
        resourceType?: string;
        nodeId?: number;
    }

    export interface Binding extends BindingInput {
        id: number;
        roleId: number;
        roleName: string;
    }

    export interface User {
        id: number;
        username: string;
        displayName: string;
        email: string;
        status: 'active' | 'disabled';
        authSource: string;
        requireMFA: boolean;
        mfaEnabled: boolean;
        lastLoginAt?: string;
        createdAt: string;
        bindings: Binding[];
    }

    export interface Permission {
        code: string;
        resourceType: string;
        feature: string;
        action: string;
        riskLevel: 'low' | 'medium' | 'high' | 'critical';
        description: string;
    }

    export interface Role {
        id: number;
        key: string;
        name: string;
        description: string;
        isSystem: boolean;
        sort: number;
        permissions: Permission[];
    }

    export interface ProjectResource {
        nodeId: number;
        resourceType: string;
        resourceId: string;
    }

    export interface ProjectNode {
        nodeId: number;
        rootPath: string;
    }

    export interface Project {
        id: number;
        name: string;
        slug: string;
        description: string;
        rootPath: string;
        status: 'active' | 'archived';
        createdAt: string;
        resources: ProjectResource[];
        nodes: ProjectNode[];
    }

    export interface Node {
        id: number;
        externalKey: string;
        name: string;
        status: 'active' | 'disabled';
        createdAt: string;
    }

    export interface ServiceAccount {
        id: number;
        userId: number;
        name: string;
        keyId: string;
        ipWhiteList: string;
        status: 'active' | 'disabled';
        expiresAt?: string;
        lastUsedAt?: string;
        createdAt: string;
        bindings: Binding[];
    }

    export interface ServiceAccountToken {
        id: number;
        keyId: string;
        token: string;
    }

    export interface AuditEvent {
        id: number;
        subjectType: string;
        subjectId: number;
        subjectName: string;
        action: string;
        decision: 'allow' | 'deny';
        resourceType: string;
        resourceId: string;
        nodeId: number;
        projectId: number;
        method: string;
        path: string;
        remoteIp: string;
        reason: string;
        metadata: string;
        createdAt: string;
    }

    export interface Page<T> {
        total: number;
        items: T[];
    }
}
