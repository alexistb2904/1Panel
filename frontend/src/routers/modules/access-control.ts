import { Layout } from '@/routers/constant';

const accessControlRouter = {
    sort: 90,
    path: '/access-control',
    name: 'Access-Control-Menu',
    component: Layout,
    redirect: '/access-control',
    meta: {
        icon: 'p-setting',
        title: 'Access Control',
        permission: ['access.user.view', 'access.role.view', 'project.view', 'node.view', 'audit.view'],
    },
    children: [
        {
            path: '/access-control',
            name: 'AccessControl',
            component: () => import('@/views/access-control/index.vue'),
            meta: {
                icon: 'p-setting',
                title: 'Access Control',
                permission: ['access.user.view', 'access.role.view', 'project.view', 'node.view', 'audit.view'],
            },
        },
    ],
};

export default accessControlRouter;
