<template>
    <div class="ac-page">
        <div class="ac-header">
            <div>
                <h2>Access Control</h2>
                <p>Utilisateurs, projets, comptes de service, nœuds et journal des décisions RBAC.</p>
            </div>
            <el-button :icon="Refresh" @click="refreshCurrentTab">Actualiser</el-button>
        </div>

        <el-tabs v-model="activeTab" @tab-change="refreshCurrentTab">
            <el-tab-pane v-if="can('access.user.view')" label="Utilisateurs" name="users">
                <div class="toolbar">
                    <el-input v-model="userFilter" clearable placeholder="Filtrer les utilisateurs" class="search" />
                    <el-button v-if="can('access.user.manage')" type="primary" @click="openCreateUser">Nouvel utilisateur</el-button>
                </div>
                <el-table :data="filteredUsers" v-loading="loading.users" stripe>
                    <el-table-column prop="displayName" label="Nom" min-width="180">
                        <template #default="scope">
                            <div class="primary-cell">{{ scope.row.displayName || scope.row.username }}</div>
                            <div class="secondary-cell">{{ scope.row.username }} · {{ scope.row.email || '—' }}</div>
                        </template>
                    </el-table-column>
                    <el-table-column label="Accès" min-width="260">
                        <template #default="scope">
                            <el-tag v-for="binding in scope.row.bindings" :key="binding.id" class="tag-gap" size="small">
                                {{ binding.roleName }} · {{ bindingLabel(binding) }}
                            </el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column label="MFA" width="130">
                        <template #default="scope">
                            <el-tag :type="scope.row.mfaEnabled ? 'success' : scope.row.requireMFA ? 'warning' : 'info'" size="small">
                                {{ scope.row.mfaEnabled ? 'Activé' : scope.row.requireMFA ? 'Requis' : 'Optionnel' }}
                            </el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column label="Statut" width="120">
                        <template #default="scope">
                            <el-tag :type="scope.row.status === 'active' ? 'success' : 'danger'" size="small">{{ scope.row.status }}</el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column v-if="can('access.user.manage')" label="Actions" width="240" fixed="right">
                        <template #default="scope">
                            <el-button link type="primary" @click="openEditUser(scope.row)">Modifier</el-button>
                            <el-button link @click="openBindings(scope.row)">Accès</el-button>
                            <el-button link @click="resetPassword(scope.row)">Mot de passe</el-button>
                            <el-button
                                link
                                :type="scope.row.status === 'active' ? 'danger' : 'success'"
                                @click="toggleUser(scope.row)"
                            >
                                {{ scope.row.status === 'active' ? 'Désactiver' : 'Activer' }}
                            </el-button>
                        </template>
                    </el-table-column>
                </el-table>
            </el-tab-pane>

            <el-tab-pane v-if="can('access.role.view')" label="Rôles" name="roles">
                <el-row :gutter="16">
                    <el-col v-for="role in roles" :key="role.id" :xs="24" :sm="12" :lg="8">
                        <el-card class="role-card" shadow="never">
                            <template #header>
                                <div class="card-title">
                                    <span>{{ role.name }}</span>
                                    <el-tag size="small">{{ role.permissions.length }} permissions</el-tag>
                                </div>
                            </template>
                            <p class="role-description">{{ role.description }}</p>
                            <div class="permission-list">
                                <el-tag
                                    v-for="permission in role.permissions.slice(0, 12)"
                                    :key="permission.code"
                                    :type="riskTag(permission.riskLevel)"
                                    size="small"
                                    class="tag-gap"
                                >
                                    {{ permission.code }}
                                </el-tag>
                                <el-button v-if="role.permissions.length > 12" link @click="showRole(role)">
                                    +{{ role.permissions.length - 12 }} autres
                                </el-button>
                            </div>
                        </el-card>
                    </el-col>
                </el-row>
            </el-tab-pane>

            <el-tab-pane v-if="can('project.view')" label="Projets" name="projects">
                <div class="toolbar">
                    <div class="toolbar-note">Le <code>rootPath</code> définit la frontière filesystem pour File Manager, Runtime et Docker.</div>
                    <el-button v-if="can('project.create')" type="primary" @click="openCreateProject">Nouveau projet</el-button>
                </div>
                <el-table :data="projects" v-loading="loading.projects" stripe>
                    <el-table-column prop="name" label="Projet" min-width="180">
                        <template #default="scope">
                            <div class="primary-cell">{{ scope.row.name }}</div>
                            <div class="secondary-cell">{{ scope.row.slug }}</div>
                        </template>
                    </el-table-column>
                    <el-table-column prop="rootPath" label="Racine filesystem" min-width="260">
                        <template #default="scope"><code>{{ scope.row.rootPath || 'Non définie' }}</code></template>
                    </el-table-column>
                    <el-table-column label="Ressources" min-width="320">
                        <template #default="scope">
                            <el-tag v-for="resource in scope.row.resources.slice(0, 6)" :key="resourceKey(resource)" size="small" class="tag-gap">
                                {{ resource.resourceType }} · {{ resource.resourceId }}
                            </el-tag>
                            <span v-if="scope.row.resources.length > 6" class="secondary-cell">+{{ scope.row.resources.length - 6 }}</span>
                        </template>
                    </el-table-column>
                    <el-table-column label="Statut" width="120">
                        <template #default="scope">
                            <el-tag :type="scope.row.status === 'active' ? 'success' : 'info'" size="small">{{ scope.row.status }}</el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column label="Actions" width="260" fixed="right">
                        <template #default="scope">
                            <el-button v-if="can('project.update')" link type="primary" @click="openEditProject(scope.row)">Modifier</el-button>
                            <el-button v-if="can('project.resource.manage')" link @click="openProjectResources(scope.row)">Ressources</el-button>
                            <el-button v-if="isAdmin" link @click="openRootPath(scope.row)">Racine</el-button>
                        </template>
                    </el-table-column>
                </el-table>
            </el-tab-pane>

            <el-tab-pane v-if="can('access.user.view')" label="Comptes de service" name="service-accounts">
                <div class="toolbar">
                    <div class="toolbar-note">Tokens Bearer limités par les mêmes rôles/scopes que les utilisateurs. Aucun rôle Administrateur n’est autorisé.</div>
                    <el-button v-if="can('access.user.manage')" type="primary" @click="openCreateServiceAccount">Nouveau compte de service</el-button>
                </div>
                <el-table :data="serviceAccounts" v-loading="loading.serviceAccounts" stripe>
                    <el-table-column prop="name" label="Nom" min-width="180" />
                    <el-table-column prop="keyId" label="Key ID" width="170"><template #default="scope"><code>{{ scope.row.keyId }}</code></template></el-table-column>
                    <el-table-column label="Scopes" min-width="260">
                        <template #default="scope">
                            <el-tag v-for="binding in scope.row.bindings" :key="binding.id" size="small" class="tag-gap">{{ binding.roleName }} · {{ bindingLabel(binding) }}</el-tag>
                        </template>
                    </el-table-column>
                    <el-table-column label="Restriction IP" min-width="180"><template #default="scope">{{ scope.row.ipWhiteList || 'Toutes' }}</template></el-table-column>
                    <el-table-column label="Dernière utilisation" width="170"><template #default="scope">{{ formatDate(scope.row.lastUsedAt) }}</template></el-table-column>
                    <el-table-column label="Statut" width="110"><template #default="scope"><el-tag :type="scope.row.status === 'active' ? 'success' : 'danger'" size="small">{{ scope.row.status }}</el-tag></template></el-table-column>
                    <el-table-column v-if="can('access.user.manage')" label="Actions" width="180" fixed="right">
                        <template #default="scope">
                            <el-button link type="primary" @click="openEditServiceAccount(scope.row)">Modifier</el-button>
                            <el-button link type="warning" @click="rotateToken(scope.row)">Rotation</el-button>
                        </template>
                    </el-table-column>
                </el-table>
            </el-tab-pane>

            <el-tab-pane v-if="can('node.view')" label="Nœuds" name="nodes">
                <div class="toolbar">
                    <div class="toolbar-note">L’External Key doit correspondre au sélecteur <code>CurrentNode/operateNode</code> utilisé par le provider multi-node.</div>
                    <el-button v-if="can('node.manage')" type="primary" @click="openCreateNode">Enregistrer un nœud</el-button>
                </div>
                <el-table :data="nodes" v-loading="loading.nodes" stripe>
                    <el-table-column prop="name" label="Nom" />
                    <el-table-column prop="externalKey" label="External Key"><template #default="scope"><code>{{ scope.row.externalKey }}</code></template></el-table-column>
                    <el-table-column label="RBAC Node ID" width="140"><template #default="scope">{{ scope.row.id }}</template></el-table-column>
                    <el-table-column label="Statut" width="120"><template #default="scope"><el-tag :type="scope.row.status === 'active' ? 'success' : 'danger'" size="small">{{ scope.row.status }}</el-tag></template></el-table-column>
                    <el-table-column v-if="can('node.manage')" label="Actions" width="120"><template #default="scope"><el-button link type="primary" @click="openEditNode(scope.row)">Modifier</el-button></template></el-table-column>
                </el-table>
            </el-tab-pane>

            <el-tab-pane v-if="can('audit.view')" label="Audit" name="audit">
                <div class="toolbar audit-toolbar">
                    <el-select v-model="auditFilters.decision" clearable placeholder="Décision" class="small-filter"><el-option label="Allow" value="allow" /><el-option label="Deny" value="deny" /></el-select>
                    <el-input v-model="auditFilters.action" clearable placeholder="Action" class="small-filter" />
                    <el-input v-model="auditFilters.info" clearable placeholder="Utilisateur, ressource, chemin…" class="search" @keyup.enter="loadAudit" />
                    <el-button type="primary" @click="loadAudit">Rechercher</el-button>
                </div>
                <el-table :data="audit.items" v-loading="loading.audit" stripe>
                    <el-table-column label="Date" width="170"><template #default="scope">{{ formatDate(scope.row.createdAt) }}</template></el-table-column>
                    <el-table-column label="Décision" width="100"><template #default="scope"><el-tag :type="scope.row.decision === 'allow' ? 'success' : 'danger'" size="small">{{ scope.row.decision }}</el-tag></template></el-table-column>
                    <el-table-column label="Sujet" min-width="150"><template #default="scope"><div>{{ scope.row.subjectName || `#${scope.row.subjectId}` }}</div><div class="secondary-cell">{{ scope.row.subjectType }}</div></template></el-table-column>
                    <el-table-column prop="action" label="Action" min-width="210" />
                    <el-table-column label="Ressource" min-width="220"><template #default="scope"><div>{{ scope.row.resourceType || '—' }}</div><code class="secondary-cell">{{ scope.row.resourceId }}</code></template></el-table-column>
                    <el-table-column prop="path" label="Endpoint" min-width="260" />
                    <el-table-column prop="reason" label="Raison" min-width="240" />
                    <el-table-column prop="remoteIp" label="IP" width="140" />
                </el-table>
                <div class="pagination"><el-pagination v-model:current-page="auditPage" :page-size="auditPageSize" :total="audit.total" layout="prev, pager, next, total" @current-change="loadAudit" /></div>
            </el-tab-pane>
        </el-tabs>

        <el-dialog v-model="userDialog.open" :title="userDialog.mode === 'create' ? 'Nouvel utilisateur' : 'Modifier utilisateur'" width="620px">
            <el-form label-position="top">
                <el-form-item v-if="userDialog.mode === 'create'" label="Identifiant"><el-input v-model="userForm.username" autocomplete="off" /></el-form-item>
                <el-form-item label="Nom affiché"><el-input v-model="userForm.displayName" /></el-form-item>
                <el-form-item label="E-mail"><el-input v-model="userForm.email" /></el-form-item>
                <el-form-item v-if="userDialog.mode === 'create'" label="Mot de passe initial"><el-input v-model="userForm.password" type="password" show-password autocomplete="new-password" /><div class="form-help">12 caractères minimum.</div></el-form-item>
                <el-form-item label="MFA obligatoire"><el-switch v-model="userForm.requireMFA" /></el-form-item>
                <template v-if="userDialog.mode === 'create'">
                    <el-divider>Accès initial</el-divider>
                    <BindingEditor v-model="userForm.bindings" :roles="roles" :projects="projects" :nodes="nodes" />
                </template>
            </el-form>
            <template #footer><el-button @click="userDialog.open = false">Annuler</el-button><el-button type="primary" @click="saveUser">Enregistrer</el-button></template>
        </el-dialog>

        <el-dialog v-model="bindingDialog.open" title="Rôles et périmètres" width="760px">
            <BindingEditor v-model="bindingDialog.bindings" :roles="roles" :projects="projects" :nodes="nodes" />
            <template #footer><el-button @click="bindingDialog.open = false">Annuler</el-button><el-button type="primary" @click="saveBindings">Enregistrer</el-button></template>
        </el-dialog>

        <el-dialog v-model="projectDialog.open" :title="projectDialog.mode === 'create' ? 'Nouveau projet' : 'Modifier projet'" width="620px">
            <el-form label-position="top">
                <el-form-item label="Nom"><el-input v-model="projectForm.name" /></el-form-item>
                <el-form-item label="Slug"><el-input v-model="projectForm.slug" /></el-form-item>
                <el-form-item label="Description"><el-input v-model="projectForm.description" type="textarea" :rows="3" /></el-form-item>
                <el-form-item v-if="projectDialog.mode === 'create' && isAdmin" label="Racine filesystem"><el-input v-model="projectForm.rootPath" placeholder="/opt/1panel/projects/mon-projet" /></el-form-item>
                <el-form-item v-if="projectDialog.mode === 'edit'" label="Statut"><el-select v-model="projectForm.status"><el-option label="Actif" value="active" /><el-option label="Archivé" value="archived" /></el-select></el-form-item>
            </el-form>
            <template #footer><el-button @click="projectDialog.open = false">Annuler</el-button><el-button type="primary" @click="saveProject">Enregistrer</el-button></template>
        </el-dialog>

        <el-dialog v-model="resourceDialog.open" title="Ressources du projet" width="760px">
            <div class="toolbar"><span class="toolbar-note">Utilise les clés stables : <code>website:alias</code>, <code>mysql:instance:db</code>, <code>runtime:nom</code>, container/compose par nom.</span><el-button @click="addProjectResource">Ajouter</el-button></div>
            <el-table :data="resourceDialog.resources" border>
                <el-table-column label="Node ID" width="120"><template #default="scope"><el-input-number v-model="scope.row.nodeId" :min="0" controls-position="right" /></template></el-table-column>
                <el-table-column label="Type" width="180"><template #default="scope"><el-select v-model="scope.row.resourceType"><el-option v-for="type in resourceTypes" :key="type" :label="type" :value="type" /></el-select></template></el-table-column>
                <el-table-column label="Resource ID"><template #default="scope"><el-input v-model="scope.row.resourceId" /></template></el-table-column>
                <el-table-column width="70"><template #default="scope"><el-button link type="danger" @click="resourceDialog.resources.splice(scope.$index, 1)">Retirer</el-button></template></el-table-column>
            </el-table>
            <template #footer><el-button @click="resourceDialog.open = false">Annuler</el-button><el-button type="primary" @click="saveProjectResources">Enregistrer</el-button></template>
        </el-dialog>

        <el-dialog v-model="rootDialog.open" title="Frontière filesystem du projet" width="620px">
            <el-alert type="warning" :closable="false" show-icon title="Cette valeur borne File Manager, les bind mounts Docker et les chemins Runtime. Ne choisissez jamais une racine système large." />
            <el-form label-position="top" class="dialog-form"><el-form-item label="Root path"><el-input v-model="rootDialog.rootPath" placeholder="/opt/1panel/projects/mon-projet" /></el-form-item></el-form>
            <template #footer><el-button @click="rootDialog.open = false">Annuler</el-button><el-button type="primary" @click="saveRootPath">Enregistrer</el-button></template>
        </el-dialog>

        <el-dialog v-model="serviceDialog.open" :title="serviceDialog.mode === 'create' ? 'Nouveau compte de service' : 'Modifier compte de service'" width="760px">
            <el-form label-position="top">
                <el-form-item label="Nom"><el-input v-model="serviceForm.name" /></el-form-item>
                <el-form-item label="IP / CIDR autorisés"><el-input v-model="serviceForm.ipWhiteList" type="textarea" placeholder="10.0.0.0/24, 203.0.113.4" /></el-form-item>
                <el-form-item v-if="serviceDialog.mode === 'edit'" label="Statut"><el-select v-model="serviceForm.status"><el-option label="Actif" value="active" /><el-option label="Désactivé" value="disabled" /></el-select></el-form-item>
                <el-divider>Accès</el-divider>
                <BindingEditor v-model="serviceForm.bindings" :roles="serviceAccountRoles" :projects="projects" :nodes="nodes" />
            </el-form>
            <template #footer><el-button @click="serviceDialog.open = false">Annuler</el-button><el-button type="primary" @click="saveServiceAccount">Enregistrer</el-button></template>
        </el-dialog>

        <el-dialog v-model="nodeDialog.open" :title="nodeDialog.mode === 'create' ? 'Enregistrer un nœud' : 'Modifier le nœud'" width="560px">
            <el-form label-position="top"><el-form-item label="Nom"><el-input v-model="nodeForm.name" /></el-form-item><el-form-item label="External Key"><el-input v-model="nodeForm.externalKey" /></el-form-item><el-form-item v-if="nodeDialog.mode === 'edit'" label="Statut"><el-select v-model="nodeForm.status"><el-option label="Actif" value="active" /><el-option label="Désactivé" value="disabled" /></el-select></el-form-item></el-form>
            <template #footer><el-button @click="nodeDialog.open = false">Annuler</el-button><el-button type="primary" @click="saveNode">Enregistrer</el-button></template>
        </el-dialog>

        <el-dialog v-model="tokenDialog.open" title="Token du compte de service" width="680px" :close-on-click-modal="false">
            <el-alert type="warning" :closable="false" show-icon title="Ce token n’est affiché qu’une fois. Copiez-le maintenant et stockez-le dans un gestionnaire de secrets." />
            <el-input v-model="tokenDialog.token" readonly class="token-input"><template #append><el-button @click="copyToken">Copier</el-button></template></el-input>
        </el-dialog>

        <el-dialog v-model="roleDialog.open" :title="roleDialog.role?.name || 'Rôle'" width="760px">
            <el-table :data="roleDialog.role?.permissions || []" stripe><el-table-column prop="code" label="Permission" min-width="220" /><el-table-column prop="resourceType" label="Ressource" width="130" /><el-table-column prop="action" label="Action" width="130" /><el-table-column label="Risque" width="110"><template #default="scope"><el-tag :type="riskTag(scope.row.riskLevel)" size="small">{{ scope.row.riskLevel }}</el-tag></template></el-table-column><el-table-column prop="description" label="Description" min-width="260" /></el-table>
        </el-dialog>
    </div>
</template>

<script setup lang="ts">
import { computed, defineComponent, h, onMounted, reactive, ref } from 'vue';
import { ElButton, ElInput, ElInputNumber, ElMessage, ElMessageBox, ElOption, ElSelect } from 'element-plus';
import { Refresh, Delete } from '@element-plus/icons-vue';
import { GlobalStore } from '@/store';
import { hasPermission } from '@/utils/rbac';
import type { AccessControl } from '@/api/interface/access';
import {
    createAccessNode,
    createAccessProject,
    createAccessUser,
    createServiceAccount,
    listAccessNodes,
    listAccessProjects,
    listAccessRoles,
    listAccessUsers,
    listServiceAccounts,
    replaceAccessProjectResources,
    replaceAccessUserBindings,
    resetAccessUserPassword,
    rotateServiceAccount,
    searchAccessAudit,
    updateAccessNode,
    updateAccessProject,
    updateAccessProjectRoot,
    updateAccessUser,
    updateAccessUserStatus,
    updateServiceAccount,
} from '@/api/modules/access';

const globalStore = GlobalStore();
const isAdmin = computed(() => globalStore.isAdmin);
const can = (permission: string) => hasPermission(permission);
const activeTab = ref('users');
const users = ref<AccessControl.User[]>([]);
const roles = ref<AccessControl.Role[]>([]);
const projects = ref<AccessControl.Project[]>([]);
const nodes = ref<AccessControl.Node[]>([]);
const serviceAccounts = ref<AccessControl.ServiceAccount[]>([]);
const userFilter = ref('');
const loading = reactive({ users: false, roles: false, projects: false, nodes: false, serviceAccounts: false, audit: false });
const filteredUsers = computed(() => {
    const query = userFilter.value.trim().toLowerCase();
    if (!query) return users.value;
    return users.value.filter((u) => [u.username, u.displayName, u.email].some((v) => (v || '').toLowerCase().includes(query)));
});
const serviceAccountRoles = computed(() => roles.value.filter((role) => role.key !== 'administrator'));
const resourceTypes = ['website', 'database', 'runtime', 'container', 'compose'];

const emptyBinding = (): AccessControl.BindingInput => ({ roleKey: 'developer', scopeType: 'project', scopeId: projects.value[0]?.id ? String(projects.value[0].id) : '', nodeId: 0 });

const BindingEditor = defineComponent({
    name: 'BindingEditor',
    props: { modelValue: { type: Array, required: true }, roles: { type: Array, required: true }, projects: { type: Array, required: true }, nodes: { type: Array, required: true } },
    emits: ['update:modelValue'],
    setup(props, { emit }) {
        const update = (index: number, key: string, value: unknown) => {
            const next = (props.modelValue as AccessControl.BindingInput[]).map((item) => ({ ...item }));
            (next[index] as unknown as Record<string, unknown>)[key] = value;
            if (key === 'scopeType') {
                const scope = String(value);
                next[index].resourceType = '';
                next[index].nodeId = 0;
                if (scope === 'global') next[index].scopeId = '*';
                else if (scope === 'node') next[index].scopeId = '0';
                else if (scope === 'project') next[index].scopeId = String((props.projects as AccessControl.Project[])[0]?.id || '');
                else next[index].scopeId = '';
            }
            emit('update:modelValue', next);
        };
        const add = () => emit('update:modelValue', [...(props.modelValue as AccessControl.BindingInput[]), emptyBinding()]);
        const remove = (index: number) => emit('update:modelValue', (props.modelValue as AccessControl.BindingInput[]).filter((_, i) => i !== index));
        return () => h('div', { class: 'binding-editor' }, [
            ...(props.modelValue as AccessControl.BindingInput[]).map((binding, index) => h('div', { class: 'binding-row' }, [
                h(ElSelect, { modelValue: binding.roleKey, 'onUpdate:modelValue': (v: string) => update(index, 'roleKey', v), placeholder: 'Rôle' }, () => (props.roles as AccessControl.Role[]).map((role) => h(ElOption, { label: role.name, value: role.key }))),
                h(ElSelect, { modelValue: binding.scopeType, 'onUpdate:modelValue': (v: string) => update(index, 'scopeType', v), placeholder: 'Scope' }, () => ['global', 'node', 'project', 'resource'].map((scope) => h(ElOption, { label: scope, value: scope }))),
                binding.scopeType === 'project'
                    ? h(ElSelect, { modelValue: binding.scopeId, 'onUpdate:modelValue': (v: string) => update(index, 'scopeId', String(v)), placeholder: 'Projet' }, () => (props.projects as AccessControl.Project[]).map((project) => h(ElOption, { label: project.name, value: String(project.id) })))
                    : binding.scopeType === 'node'
                      ? h(ElSelect, { modelValue: binding.scopeId, 'onUpdate:modelValue': (v: string) => update(index, 'scopeId', String(v)), placeholder: 'Nœud' }, () => [h(ElOption, { label: 'Local / master', value: '0' }), ...(props.nodes as AccessControl.Node[]).map((node) => h(ElOption, { label: node.name, value: String(node.id) }))])
                      : binding.scopeType === 'resource'
                        ? h('div', { class: 'resource-scope-fields' }, [
                            h(ElSelect, { modelValue: binding.resourceType, 'onUpdate:modelValue': (v: string) => update(index, 'resourceType', v), placeholder: 'Type' }, () => resourceTypes.map((type) => h(ElOption, { label: type, value: type }))),
                            h(ElSelect, { modelValue: binding.nodeId ?? 0, 'onUpdate:modelValue': (v: number) => update(index, 'nodeId', Number(v)), placeholder: 'Nœud' }, () => [h(ElOption, { label: 'Local / master', value: 0 }), ...(props.nodes as AccessControl.Node[]).map((node) => h(ElOption, { label: node.name, value: node.id }))]),
                            h(ElInput, { modelValue: binding.scopeId, 'onUpdate:modelValue': (v: string) => update(index, 'scopeId', v), placeholder: 'Resource ID' }),
                        ])
                        : h(ElInput, { modelValue: '*', disabled: true }),
                h(ElButton, { circle: true, plain: true, type: 'danger', icon: Delete, disabled: (props.modelValue as unknown[]).length <= 1, onClick: () => remove(index) }),
            ])),
            h(ElButton, { plain: true, onClick: add }, () => 'Ajouter un accès'),
        ]);
    },
});

const userDialog = reactive({ open: false, mode: 'create' as 'create' | 'edit', id: 0 });
const userForm = reactive({ username: '', displayName: '', email: '', password: '', requireMFA: true, bindings: [] as AccessControl.BindingInput[] });
const bindingDialog = reactive({ open: false, userID: 0, bindings: [] as AccessControl.BindingInput[] });
const projectDialog = reactive({ open: false, mode: 'create' as 'create' | 'edit', id: 0 });
const projectForm = reactive({ name: '', slug: '', description: '', rootPath: '', status: 'active' as 'active' | 'archived' });
const resourceDialog = reactive({ open: false, projectID: 0, resources: [] as AccessControl.ProjectResource[] });
const rootDialog = reactive({ open: false, projectID: 0, rootPath: '' });
const serviceDialog = reactive({ open: false, mode: 'create' as 'create' | 'edit', id: 0 });
const serviceForm = reactive({ name: '', ipWhiteList: '', status: 'active' as 'active' | 'disabled', bindings: [] as AccessControl.BindingInput[] });
const nodeDialog = reactive({ open: false, mode: 'create' as 'create' | 'edit', id: 0 });
const nodeForm = reactive({ name: '', externalKey: '', status: 'active' as 'active' | 'disabled' });
const tokenDialog = reactive({ open: false, token: '' });
const roleDialog = reactive<{ open: boolean; role?: AccessControl.Role }>({ open: false, role: undefined });
const audit = reactive<{ total: number; items: AccessControl.AuditEvent[] }>({ total: 0, items: [] });
const auditFilters = reactive({ decision: '', action: '', info: '' });
const auditPage = ref(1);
const auditPageSize = 30;

const loadUsers = async () => { if (!can('access.user.view')) return; loading.users = true; try { users.value = (await listAccessUsers()).data || []; } finally { loading.users = false; } };
const loadRoles = async () => { if (!can('access.role.view')) return; loading.roles = true; try { roles.value = (await listAccessRoles()).data || []; } finally { loading.roles = false; } };
const loadProjects = async () => { if (!can('project.view')) return; loading.projects = true; try { projects.value = (await listAccessProjects()).data || []; } finally { loading.projects = false; } };
const loadNodes = async () => { if (!can('node.view')) return; loading.nodes = true; try { nodes.value = (await listAccessNodes()).data || []; } finally { loading.nodes = false; } };
const loadServiceAccounts = async () => { if (!can('access.user.view')) return; loading.serviceAccounts = true; try { serviceAccounts.value = (await listServiceAccounts()).data || []; } finally { loading.serviceAccounts = false; } };
const loadAudit = async () => { if (!can('audit.view')) return; loading.audit = true; try { const res = await searchAccessAudit({ page: auditPage.value, pageSize: auditPageSize, ...auditFilters }); audit.total = res.data?.total || 0; audit.items = res.data?.items || []; } finally { loading.audit = false; } };

const refreshCurrentTab = async () => {
    if (activeTab.value === 'users') await loadUsers();
    else if (activeTab.value === 'roles') await loadRoles();
    else if (activeTab.value === 'projects') await loadProjects();
    else if (activeTab.value === 'nodes') await loadNodes();
    else if (activeTab.value === 'service-accounts') await loadServiceAccounts();
    else if (activeTab.value === 'audit') await loadAudit();
};

const openCreateUser = () => { Object.assign(userForm, { username: '', displayName: '', email: '', password: '', requireMFA: true, bindings: [emptyBinding()] }); Object.assign(userDialog, { open: true, mode: 'create', id: 0 }); };
const openEditUser = (user: AccessControl.User) => { Object.assign(userForm, { username: user.username, displayName: user.displayName, email: user.email, password: '', requireMFA: user.requireMFA, bindings: [] }); Object.assign(userDialog, { open: true, mode: 'edit', id: user.id }); };
const saveUser = async () => { if (userDialog.mode === 'create') { await createAccessUser(userForm); } else { await updateAccessUser({ id: userDialog.id, displayName: userForm.displayName, email: userForm.email, requireMFA: userForm.requireMFA }); } userDialog.open = false; ElMessage.success('Utilisateur enregistré'); await loadUsers(); };
const openBindings = (user: AccessControl.User) => { bindingDialog.userID = user.id; bindingDialog.bindings = user.bindings.map(({ roleKey, scopeType, scopeId, resourceType, nodeId }) => ({ roleKey, scopeType, scopeId, resourceType, nodeId: nodeId ?? 0 })); bindingDialog.open = true; };
const saveBindings = async () => { await replaceAccessUserBindings({ id: bindingDialog.userID, bindings: bindingDialog.bindings }); bindingDialog.open = false; ElMessage.success('Accès mis à jour'); await loadUsers(); };
const toggleUser = async (user: AccessControl.User) => { await updateAccessUserStatus({ id: user.id, status: user.status === 'active' ? 'disabled' : 'active' }); await loadUsers(); };
const resetPassword = async (user: AccessControl.User) => { const result = await ElMessageBox.prompt(`Nouveau mot de passe pour ${user.username}`, 'Réinitialiser le mot de passe', { inputType: 'password', inputPattern: /^.{12,}$/, inputErrorMessage: '12 caractères minimum' }); await resetAccessUserPassword({ id: user.id, password: result.value }); ElMessage.success('Mot de passe réinitialisé'); };

const openCreateProject = () => { Object.assign(projectForm, { name: '', slug: '', description: '', rootPath: '', status: 'active' }); Object.assign(projectDialog, { open: true, mode: 'create', id: 0 }); };
const openEditProject = (project: AccessControl.Project) => { Object.assign(projectForm, { name: project.name, slug: project.slug, description: project.description, rootPath: project.rootPath, status: project.status }); Object.assign(projectDialog, { open: true, mode: 'edit', id: project.id }); };
const saveProject = async () => { if (projectDialog.mode === 'create') await createAccessProject({ name: projectForm.name, slug: projectForm.slug, description: projectForm.description, rootPath: projectForm.rootPath }); else await updateAccessProject({ id: projectDialog.id, name: projectForm.name, slug: projectForm.slug, description: projectForm.description, status: projectForm.status }); projectDialog.open = false; ElMessage.success('Projet enregistré'); await loadProjects(); };
const openProjectResources = (project: AccessControl.Project) => { resourceDialog.projectID = project.id; resourceDialog.resources = project.resources.map((item) => ({ ...item })); resourceDialog.open = true; };
const addProjectResource = () => resourceDialog.resources.push({ nodeId: 0, resourceType: 'website', resourceId: '' });
const saveProjectResources = async () => { await replaceAccessProjectResources({ id: resourceDialog.projectID, resources: resourceDialog.resources.filter((item) => item.resourceId.trim()) }); resourceDialog.open = false; ElMessage.success('Ressources mises à jour'); await loadProjects(); };
const openRootPath = (project: AccessControl.Project) => { rootDialog.projectID = project.id; rootDialog.rootPath = project.rootPath || ''; rootDialog.open = true; };
const saveRootPath = async () => { await updateAccessProjectRoot({ id: rootDialog.projectID, rootPath: rootDialog.rootPath }); rootDialog.open = false; ElMessage.success('Frontière filesystem mise à jour'); await loadProjects(); };

const openCreateServiceAccount = () => { Object.assign(serviceForm, { name: '', ipWhiteList: '', status: 'active', bindings: [emptyBinding()] }); Object.assign(serviceDialog, { open: true, mode: 'create', id: 0 }); };
const openEditServiceAccount = (account: AccessControl.ServiceAccount) => { Object.assign(serviceForm, { name: account.name, ipWhiteList: account.ipWhiteList, status: account.status, bindings: account.bindings.map(({ roleKey, scopeType, scopeId, resourceType, nodeId }) => ({ roleKey, scopeType, scopeId, resourceType, nodeId: nodeId ?? 0 })) }); Object.assign(serviceDialog, { open: true, mode: 'edit', id: account.id }); };
const saveServiceAccount = async () => { if (serviceDialog.mode === 'create') { const res = await createServiceAccount({ name: serviceForm.name, ipWhiteList: serviceForm.ipWhiteList, bindings: serviceForm.bindings }); showToken(res.data?.token || ''); } else { await updateServiceAccount({ id: serviceDialog.id, name: serviceForm.name, ipWhiteList: serviceForm.ipWhiteList, status: serviceForm.status, bindings: serviceForm.bindings }); } serviceDialog.open = false; ElMessage.success('Compte de service enregistré'); await loadServiceAccounts(); };
const rotateToken = async (account: AccessControl.ServiceAccount) => { await ElMessageBox.confirm('L’ancien token cessera immédiatement de fonctionner.', 'Rotation du token', { type: 'warning' }); const res = await rotateServiceAccount(account.id); showToken(res.data?.token || ''); await loadServiceAccounts(); };
const showToken = (token: string) => { tokenDialog.token = token; tokenDialog.open = true; };
const copyToken = async () => { await navigator.clipboard.writeText(tokenDialog.token); ElMessage.success('Token copié'); };

const openCreateNode = () => { Object.assign(nodeForm, { name: '', externalKey: '', status: 'active' }); Object.assign(nodeDialog, { open: true, mode: 'create', id: 0 }); };
const openEditNode = (node: AccessControl.Node) => { Object.assign(nodeForm, { name: node.name, externalKey: node.externalKey, status: node.status }); Object.assign(nodeDialog, { open: true, mode: 'edit', id: node.id }); };
const saveNode = async () => { if (nodeDialog.mode === 'create') await createAccessNode({ name: nodeForm.name, externalKey: nodeForm.externalKey }); else await updateAccessNode({ id: nodeDialog.id, name: nodeForm.name, externalKey: nodeForm.externalKey, status: nodeForm.status }); nodeDialog.open = false; ElMessage.success('Nœud enregistré'); await loadNodes(); };
const showRole = (role: AccessControl.Role) => { roleDialog.role = role; roleDialog.open = true; };

const bindingLabel = (binding: Pick<AccessControl.Binding, 'scopeType' | 'scopeId' | 'resourceType' | 'nodeId'>) => binding.scopeType === 'global' ? 'global' : binding.scopeType === 'project' ? `project #${binding.scopeId}` : binding.scopeType === 'node' ? `node #${binding.scopeId}` : `${binding.resourceType}:${binding.scopeId} @ node #${binding.nodeId ?? 0}`;
const riskTag = (risk: string): 'success' | 'warning' | 'danger' | 'info' => risk === 'critical' || risk === 'high' ? 'danger' : risk === 'medium' ? 'warning' : risk === 'low' ? 'success' : 'info';
const resourceKey = (resource: AccessControl.ProjectResource) => `${resource.nodeId}:${resource.resourceType}:${resource.resourceId}`;
const formatDate = (value?: string) => value ? new Date(value).toLocaleString() : '—';

onMounted(async () => {
    await Promise.all([loadRoles(), loadProjects(), loadNodes()]);
    const visibleTabs = [
        can('access.user.view') && 'users',
        can('access.role.view') && 'roles',
        can('project.view') && 'projects',
        can('node.view') && 'nodes',
        can('audit.view') && 'audit',
    ].filter(Boolean) as string[];
    activeTab.value = visibleTabs[0] || 'users';
    await refreshCurrentTab();
});
</script>

<style scoped>
.ac-page { padding: 20px; }
.ac-header, .toolbar, .card-title { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
.ac-header { margin-bottom: 12px; }
.ac-header h2 { margin: 0 0 4px; font-size: 24px; }
.ac-header p, .role-description, .toolbar-note, .form-help { margin: 0; color: var(--el-text-color-secondary); }
.toolbar { margin-bottom: 14px; min-height: 32px; }
.search { width: 340px; max-width: 55vw; }
.small-filter { width: 160px; }
.audit-toolbar { justify-content: flex-start; flex-wrap: wrap; }
.primary-cell { font-weight: 600; }
.secondary-cell { color: var(--el-text-color-secondary); font-size: 12px; }
.tag-gap { margin: 2px 4px 2px 0; }
.role-card { margin-bottom: 16px; min-height: 190px; }
.role-description { min-height: 42px; margin-bottom: 14px; }
.permission-list { line-height: 30px; }
.pagination { display: flex; justify-content: flex-end; margin-top: 16px; }
.dialog-form { margin-top: 18px; }
.token-input { margin-top: 18px; }
.binding-editor { display: flex; flex-direction: column; gap: 10px; }
:deep(.binding-row) { display: grid; grid-template-columns: 1.1fr 1fr 2.6fr auto; gap: 8px; align-items: center; }
:deep(.resource-scope-fields) { display: grid; grid-template-columns: 130px 160px 1fr; gap: 8px; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
@media (max-width: 900px) {
    .ac-page { padding: 12px; }
    .ac-header, .toolbar { align-items: stretch; flex-direction: column; }
    .search, .small-filter { width: 100%; max-width: none; }
    :deep(.binding-row) { grid-template-columns: 1fr; padding: 10px; border: 1px solid var(--el-border-color-lighter); border-radius: 8px; }
    :deep(.resource-scope-fields) { grid-template-columns: 1fr; }
}
</style>
