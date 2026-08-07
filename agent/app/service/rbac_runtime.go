package service

import (
	"context"
	"strconv"
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/dto/request"
	"github.com/1Panel-dev/1Panel/agent/app/dto/response"
	"github.com/1Panel-dev/1Panel/agent/app/repo"
	"github.com/1Panel-dev/1Panel/agent/constant"
	"github.com/subosito/gotenv"
)

func RuntimeResourceKey(name string) string {
	return "runtime:" + strings.TrimSpace(name)
}

func ParseRuntimeRBACKeys(keys []string) ([]uint, []string) {
	ids := make([]uint, 0)
	names := make([]string, 0)
	idSeen := map[uint]struct{}{}
	nameSeen := map[string]struct{}{}
	for _, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" { continue }
		if strings.HasPrefix(key, "runtime:") {
			name := strings.TrimSpace(strings.TrimPrefix(key, "runtime:"))
			if name != "" {
				if _, ok := nameSeen[name]; !ok { nameSeen[name] = struct{}{}; names = append(names, name) }
			}
			continue
		}
		if parsed, err := strconv.ParseUint(key, 10, 64); err == nil && parsed > 0 {
			id := uint(parsed)
			if _, ok := idSeen[id]; !ok { idSeen[id] = struct{}{}; ids = append(ids, id) }
		}
	}
	return ids, names
}

func RuntimeKeyForID(id uint) (string, error) {
	runtime, err := runtimeRepo.GetFirst(context.Background(), repo.WithByID(id))
	if err != nil { return "", err }
	return RuntimeResourceKey(runtime.Name), nil
}

func PageRuntimesForRBAC(req request.RuntimeSearch, allowedKeys []string) (int64, []response.RuntimeDTO, error) {
	ids, names := ParseRuntimeRBACKeys(allowedKeys)
	opts := []repo.DBOption{repo.WithByIDsOrNames(ids, names)}
	if req.Name != "" { opts = append(opts, repo.WithByLikeName(req.Name)) }
	if req.Status != "" {
		if req.Type == constant.TypePhp { opts = append(opts, runtimeRepo.WithNormalStatus(req.Status)) } else { opts = append(opts, runtimeRepo.WithStatus(req.Status)) }
	}
	if req.Type != "" { opts = append(opts, repo.WithByType(req.Type)) }
	total, runtimes, err := runtimeRepo.Page(req.Page, req.PageSize, opts...)
	if err != nil { return 0, nil, err }
	res := make([]response.RuntimeDTO, 0, len(runtimes))
	if len(runtimes) == 0 { return total, res, nil }
	if err = SyncRuntimesStatus(runtimes); err != nil { return 0, nil, err }
	for _, runtime := range runtimes {
		if runtime.Resource == constant.ResourceLocal { runtime.Status = constant.StatusNormal }
		item := response.NewRuntimeDTO(runtime)
		// Generic runtime listings are protected only by runtime.view. Never
		// expose environment values here; secret-bearing env data must be served
		// by a dedicated endpoint that can enforce runtime.env.secrets.view.
		item.Params = make(map[string]interface{})
		envs, err := gotenv.Unmarshal(runtime.Env)
		if err != nil { return 0, nil, err }
		detail, _ := appDetailRepo.GetFirst(repo.WithByID(runtime.AppDetailID))
		if detail.AppId == 0 {
			appID, appDetailID := handleRuntimeDetailID(runtime)
			item.AppDetailID = appDetailID
			item.AppID = appID
		} else {
			item.AppID = detail.AppId
		}
		item.ExposedPorts, _ = loadComposeExposedPortsFromEnv(envs, "", false)
		res = append(res, item)
	}
	return total, res, nil
}
