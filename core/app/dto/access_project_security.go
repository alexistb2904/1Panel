package dto

type AccessProjectRootUpdate struct {
	ID       uint   `json:"id" validate:"required"`
	RootPath string `json:"rootPath" validate:"max=2048"`
}

type AccessProjectSecurityInfo struct {
	ID       uint   `json:"id"`
	Name     string `json:"name"`
	Slug     string `json:"slug"`
	RootPath string `json:"rootPath"`
	Status   string `json:"status"`
}
