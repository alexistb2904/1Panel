<template>
    <RbacProjectScope />
    <router-view v-slot="{ Component, route }" :key="key">
        <transition appear name="fade-transform" mode="out-in">
            <keep-alive :include="include">
                <component :is="Component" :key="route.path"></component>
            </keep-alive>
        </transition>
    </router-view>
</template>

<script setup lang="ts">
import cacheRouter from '@/routers/cache-router';
import RbacProjectScope from '@/components/rbac-project-scope/index.vue';
import { computed } from 'vue';

const key = computed(() => Math.random());
const include = computed(() => props.keepAlive || cacheRouter);
const props = defineProps({
    keepAlive: {
        type: Object,
        required: false,
    },
});
</script>
