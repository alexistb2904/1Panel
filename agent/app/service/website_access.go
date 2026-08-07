package service

import (
	"context"

	"github.com/1Panel-dev/1Panel/agent/app/dto/request"
	"github.com/1Panel-dev/1Panel/agent/app/dto/response"
	"github.com/1Panel-dev/1Panel/agent/app/repo"
	"github.com/1Panel-dev/1Panel/agent/constant"
)

// PageWebsitesForRBAC is the access-aware equivalent of PageWebsite. The
// authorization IDs are applied as a SQL predicate before count/pagination so
// unauthorized websites cannot leak through totals or sparse pages.
func PageWebsitesForRBAC(req request.WebsiteSearch, allowedIDs []uint) (int64, []response.WebsiteRes, error) {
	if len(allowedIDs) == 0 {
		return 0, []response.WebsiteRes{}, nil
	}

	var (
		websiteDTOs []response.WebsiteRes
		opts        []repo.DBOption
	)
	opts = append(opts,
		repo.WithByIDs(allowedIDs),
		repo.WithOrderRuleBy(req.OrderBy, req.Order),
		repo.WithOrderRuleBy("created_at", "descending"),
		repo.WithOrderRuleBy("id", "descending"),
	)
	if req.Name != "" {
		domains, _ := websiteDomainRepo.GetBy(websiteDomainRepo.WithDomainLike(req.Name))
		var websiteIDs []uint
		for _, domain := range domains {
			websiteIDs = append(websiteIDs, domain.WebsiteID)
		}
		opts = append(opts, websiteRepo.WithSearchKeyword(req.Name, websiteIDs))
	}
	if req.WebsiteGroupID != 0 {
		opts = append(opts, websiteRepo.WithGroupID(req.WebsiteGroupID))
	}
	if req.Type != "" {
		opts = append(opts, websiteRepo.WithType(req.Type))
	}

	total, websites, err := websiteRepo.Page(req.Page, req.PageSize, opts...)
	if err != nil {
		return 0, nil, err
	}
	allowed := make(map[uint]struct{}, len(allowedIDs))
	for _, id := range allowedIDs {
		allowed[id] = struct{}{}
	}

	for _, web := range websites {
		var (
			appName      string
			runtimeName  string
			runtimeType  string
			appInstallID uint
		)
		switch web.Type {
		case constant.Deployment:
			appInstall, err := appInstallRepo.GetFirst(repo.WithByID(web.AppInstallID))
			if err == nil {
				appName = appInstall.Name
				appInstallID = appInstall.ID
			}
		case constant.Runtime:
			runtime, _ := runtimeRepo.GetFirst(context.Background(), repo.WithByID(web.RuntimeID))
			if runtime != nil {
				runtimeName = runtime.Name
				runtimeType = runtime.Type
			}
		}

		siteDTO := response.WebsiteRes{
			ID:            web.ID,
			CreatedAt:     web.CreatedAt,
			Protocol:      web.Protocol,
			PrimaryDomain: web.PrimaryDomain,
			Type:          web.Type,
			Remark:        web.Remark,
			Status:        web.Status,
			Alias:         web.Alias,
			AppName:       appName,
			ExpireDate:    web.ExpireDate,
			SSLExpireDate: web.WebsiteSSL.ExpireDate,
			SSLStatus:     checkSSLStatus(web.WebsiteSSL.ExpireDate),
			RuntimeName:   runtimeName,
			SitePath:      GetSitePath(web, SiteDir),
			AppInstallID:  appInstallID,
			RuntimeType:   runtimeType,
			Favorite:      web.Favorite,
			IPV6:          web.IPV6,
		}

		if siteDTO.Type == constant.Subsite && web.ParentWebsiteID != 0 {
			if _, ok := allowed[web.ParentWebsiteID]; ok {
				parentWeb, _ := websiteRepo.GetFirst(repo.WithByID(web.ParentWebsiteID))
				if parentWeb.ID != 0 {
					siteDTO.ParentSite = parentWeb.PrimaryDomain
				}
			}
		}

		children, _ := websiteRepo.List(websiteRepo.WithParentID(web.ID), repo.WithByIDs(allowedIDs))
		for _, child := range children {
			siteDTO.ChildSites = append(siteDTO.ChildSites, child.PrimaryDomain)
		}
		websiteDTOs = append(websiteDTOs, siteDTO)
	}
	return total, websiteDTOs, nil
}

func GetWebsitesForRBAC(allowedIDs []uint) ([]response.WebsiteDTO, error) {
	if len(allowedIDs) == 0 {
		return []response.WebsiteDTO{}, nil
	}
	var result []response.WebsiteDTO
	websites, err := websiteRepo.List(repo.WithByIDs(allowedIDs), repo.WithOrderRuleBy("primary_domain", "ascending"))
	if err != nil {
		return nil, err
	}
	for _, web := range websites {
		result = append(result, response.WebsiteDTO{Website: web})
	}
	return result, nil
}

func GetWebsiteOptionsForRBAC(req request.WebsiteOptionReq, allowedIDs []uint) ([]response.WebsiteOption, error) {
	if len(allowedIDs) == 0 {
		return []response.WebsiteOption{}, nil
	}
	options, err := NewIWebsiteService().GetWebsiteOptions(req)
	if err != nil {
		return nil, err
	}
	allowed := make(map[uint]struct{}, len(allowedIDs))
	for _, id := range allowedIDs {
		allowed[id] = struct{}{}
	}
	filtered := make([]response.WebsiteOption, 0, len(options))
	for _, option := range options {
		if _, ok := allowed[option.ID]; ok {
			filtered = append(filtered, option)
		}
	}
	return filtered, nil
}
