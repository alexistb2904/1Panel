package router

func commonGroups() []CommonRouter {
	return []CommonRouter{
		&BaseRouter{},
		&AccessRouter{},
		&BackupRouter{},
		&LogRouter{},
		&SettingRouter{},
		&CommandRouter{},
		&GroupRouter{},
		&ScriptRouter{},
	}
}
