import type { AxiosRequestConfig, InternalAxiosRequestConfig } from 'axios';
import http from '@/api';
import { GlobalStore } from '@/store';

const scopedProjectPaths = new Set([
    '/websites',
    '/databases',
    '/databases/pg',
    '/databases/mongodb',
    '/runtimes',
    '/runtimes/update',
    '/runtimes/php/container/update',
    '/containers',
    '/containers/compose',
]);

const storageKey = (node: string) => `rbac-active-project:${node || 'local'}`;

export const getActiveProjectID = (node?: string): number => {
    const currentNode = node || GlobalStore().currentNode || 'local';
    const raw = localStorage.getItem(storageKey(currentNode));
    const value = Number(raw || 0);
    return Number.isFinite(value) && value > 0 ? value : 0;
};

export const setActiveProjectID = (projectID: number, node?: string) => {
    const currentNode = node || GlobalStore().currentNode || 'local';
    if (!projectID) {
        localStorage.removeItem(storageKey(currentNode));
        return;
    }
    localStorage.setItem(storageKey(currentNode), String(projectID));
};

export const installProjectScopeInterceptor = () => {
    http.service.interceptors.request.use((config: AxiosRequestConfig) => {
        const method = (config.method || 'get').toUpperCase();
        if (method !== 'POST' || !config.url || !scopedProjectPaths.has(config.url)) {
            return config as InternalAxiosRequestConfig;
        }
        const projectID = getActiveProjectID();
        if (!projectID) {
            return config as InternalAxiosRequestConfig;
        }
        if (config.data && typeof config.data === 'object' && !Array.isArray(config.data)) {
            const data = config.data as Record<string, unknown>;
            if (!data.projectID && !data.projectId) {
                data.projectID = projectID;
            }
        }
        return config as InternalAxiosRequestConfig;
    });
};
