<template>
    <div v-if="visible" class="rbac-project-scope">
        <div class="scope-copy">
            <span class="scope-label">Projet actif</span>
            <span class="scope-hint">Seuls les projets attachés au nœud courant sont proposés.</span>
        </div>
        <el-select
            v-model="selectedProjectID"
            class="scope-select"
            placeholder="Sélectionner un projet"
            filterable
            @change="persistSelection"
        >
            <el-option v-for="project in activeProjects" :key="project.id" :label="project.name" :value="project.id">
                <span>{{ project.name }}</span>
                <span class="scope-slug">{{ project.slug }}</span>
            </el-option>
        </el-select>
    </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { GlobalStore } from '@/store';
import { listMyAccessProjects } from '@/api/modules/access';
import type { AccessControl } from '@/api/interface/access';
import { getActiveProjectID, setActiveProjectID } from '@/utils/project-scope';

const globalStore = GlobalStore();
const projects = ref<AccessControl.Project[]>([]);
const selectedProjectID = ref<number>(0);
const loading = ref(false);

const canonicalCurrentNode = computed(() => {
    const raw = String(globalStore.currentNode || '').trim();
    let value = raw;
    try { value = decodeURIComponent(raw); } catch { value = raw; }
    value = value.trim();
    if (!value || value === 'undefined' || value === '0' || value === 'master') return 'local';
    return value;
});
const supportsCurrentNode = (project: AccessControl.Project) =>
    (project.nodes || []).some((node) => canonicalCurrentNode.value === 'local' ? node.nodeId === 0 : node.externalKey === canonicalCurrentNode.value);
const activeProjects = computed(() => projects.value.filter((project) => project.status === 'active' && supportsCurrentNode(project)));
const visible = computed(() => !globalStore.isAdmin && activeProjects.value.length > 1);

const persistSelection = (value: number) => {
    selectedProjectID.value = value || 0;
    setActiveProjectID(selectedProjectID.value, globalStore.currentNode);
};

const loadProjects = async () => {
    if (!globalStore.isLogin || globalStore.isAdmin || loading.value) return;
    loading.value = true;
    try {
        const res = await listMyAccessProjects();
        projects.value = res.data || [];
        const active = activeProjects.value;
        const stored = getActiveProjectID(globalStore.currentNode);
        if (active.some((project) => project.id === stored)) {
            selectedProjectID.value = stored;
            return;
        }
        if (active.length === 1) {
            persistSelection(active[0].id);
            return;
        }
        selectedProjectID.value = 0;
        setActiveProjectID(0, globalStore.currentNode);
    } finally {
        loading.value = false;
    }
};

watch(() => globalStore.currentNode, () => loadProjects());
watch(() => globalStore.isLogin, (loggedIn) => { if (loggedIn) loadProjects(); });
onMounted(loadProjects);
</script>

<style scoped>
.rbac-project-scope { display: flex; align-items: center; justify-content: space-between; gap: 16px; margin: 12px 20px 0; padding: 10px 14px; border: 1px solid var(--el-border-color-lighter); border-radius: 8px; background: var(--el-fill-color-extra-light); }
.scope-copy { min-width: 0; display: flex; align-items: baseline; gap: 10px; }
.scope-label { font-weight: 600; white-space: nowrap; }
.scope-hint, .scope-slug { color: var(--el-text-color-secondary); font-size: 12px; }
.scope-select { width: 280px; max-width: 42vw; }
.scope-slug { float: right; margin-left: 18px; }
@media (max-width: 768px) {
    .rbac-project-scope { align-items: stretch; flex-direction: column; margin: 8px 10px 0; }
    .scope-copy { flex-direction: column; gap: 2px; }
    .scope-select { width: 100%; max-width: none; }
}
</style>
