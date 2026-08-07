import { Layout } from '@/routers/constant';

const containerRouter = {
    sort: 6,
    path: '/containers',
    name: 'Container-Menu',
    component: Layout,
    redirect: '/containers/container',
    meta: {
        icon: 'p-docker1',
        title: 'menu.container',
        permission: ['docker.container.view', 'docker.compose.view'],
    },
    children: [
        {
            path: '/containers',
            name: 'Container',
            redirect: '/containers/container',
            component: () => import('@/views/container/index.vue'),
            meta: {},
            children: [
                {
                    path: 'dashboard',
                    name: 'ContainerDashboard',
                    component: () => import('@/views/container/dashboard/index.vue'),
                    props: true,
                    hidden: true,
                    meta: {
                        activeMenu: '/containers',
                        parent: 'menu.container',
                        title: 'menu.home',
                        permission: 'settings.manage',
                    },
                },
                {
                    path: 'container',
                    name: 'ContainerItem',
                    component: () => import('@/views/container/container/index.vue'),
                    props: true,
                    hidden: true,
                    meta: {
                        activeMenu: '/containers',
                        parent: 'menu.container',
                        title: 'menu.container',
                        permission: 'docker.container.view',
                    },
                },
                {
                    path: 'container/operate',
                    name: 'ContainerCreate',
                    component: () => import('@/views/container/container/operate/index.vue'),
                    props: true,
                    hidden: true,
                    meta: {
                        activeMenu: '/containers',
                        ignoreTab: true,
                        permission: ['docker.container.create', 'docker.container.edit'],
                    },
                },
                {
                    path: 'image',
                    name: 'Image',
                    component: () => import('@/views/container/image/index.vue'),
                    hidden: true,
                    meta: {
                        activeMenu: '/containers',
                        parent: 'menu.container',
                        title: 'container.image',
                        permission: 'settings.manage',
                    },
                },
                {
                    path: 'network',
                    name: 'Network',
                    component: () => import('@/views/container/network/index.vue'),
                    hidden: true,
                    meta: {
                        activeMenu: '/containers',
                        parent: 'menu.container',
                        title: 'container.network',
                        permission: 'settings.manage',
                    },
                },
                {
                    path: 'volume',
                    name: 'Volume',
                    component: () => import('@/views/container/volume/index.vue'),
                    hidden: true,
                    meta: {
                        activeMenu: '/containers',
                        parent: 'menu.container',
                        title: 'container.volume',
                        permission: 'settings.manage',
                    },
                },
                {
                    path: 'repo',
                    name: 'Repo',
                    component: () => import('@/views/container/repo/index.vue'),
                    hidden: true,
                    meta: {
                        activeMenu: '/containers',
                        parent: 'menu.container',
                        title: 'container.repo',
                        permission: 'settings.manage',
                    },
                },
                {
                    path: 'compose',
                    name: 'Compose',
                    component: () => import('@/views/container/compose/index.vue'),
                    hidden: true,
                    meta: {
                        activeMenu: '/containers',
                        parent: 'menu.container',
                        title: 'container.compose',
                        permission: 'docker.compose.view',
                    },
                },
                {
                    path: 'template',
                    name: 'ComposeTemplate',
                    component: () => import('@/views/container/template/index.vue'),
                    hidden: true,
                    meta: {
                        activeMenu: '/containers',
                        parent: 'menu.container',
                        title: 'container.composeTemplate',
                        permission: 'settings.manage',
                    },
                },
                {
                    path: 'setting',
                    name: 'ContainerSetting',
                    component: () => import('@/views/container/setting/index.vue'),
                    hidden: true,
                    meta: {
                        activeMenu: '/containers',
                        parent: 'menu.container',
                        title: 'container.setting',
                        permission: 'settings.manage',
                    },
                },
            ],
        },
    ],
};

export default containerRouter;