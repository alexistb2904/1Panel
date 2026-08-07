package dto

type AccessProjectRootUpdate struct {
	ID       uint  `json:"id" validate:"required"`
	NodeID   uint  `json:"nodeId"`
	RootPath string `json:"rootPath" validate:"max=2048"`
	Enabled  *bool `json:"enabled"`
}

type AccessProjectNodeInfo struct {
	NodeID   uint   `json:"nodeId"`
	RootPath string `json:"rootPath"`
}

type AccessProjectSecurityInfo struct {
	ID       uint                    `json:"id"`
	Name     string                  `json:"name"`
	Slug     string                  `json:"slug"`
	RootPath string                  `json:"rootPath"`
	Status   string                  `json:"status"`
	Nodes    []AccessProjectNodeInfo `json:"nodes"`
}
