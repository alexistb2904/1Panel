package service

import (
	"strings"

	"github.com/1Panel-dev/1Panel/agent/app/dto"
	"github.com/1Panel-dev/1Panel/agent/app/model"
	"github.com/1Panel-dev/1Panel/agent/app/repo"
	"github.com/1Panel-dev/1Panel/agent/buserr"
	"github.com/jinzhu/copier"
)

// RBAC database resource keys are stable across database row re-imports and
// remote synchronisation. They intentionally include both the engine family
// and the configured database-server name.
func DatabaseResourceKey(kind, instance, name string) string {
	return strings.ToLower(strings.TrimSpace(kind)) + ":" + strings.TrimSpace(instance) + ":" + strings.TrimSpace(name)
}

func AllowedDatabaseNames(keys []string, kind, instance string) []string {
	prefix := strings.ToLower(strings.TrimSpace(kind)) + ":" + strings.TrimSpace(instance) + ":"
	seen := map[string]struct{}{}
	result := make([]string, 0)
	for _, key := range keys {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(key, prefix))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		result = append(result, name)
	}
	return result
}

func SearchMysqlForRBAC(search dto.MysqlDBSearch, allowedKeys []string) (int64, interface{}, error) {
	names := AllowedDatabaseNames(allowedKeys, "mysql", search.Database)
	if len(names) == 0 {
		return 0, []dto.MysqlDBInfo{}, nil
	}
	total, mysqls, err := mysqlRepo.Page(search.Page, search.PageSize,
		mysqlRepo.WithByMysqlName(search.Database),
		repo.WithByNames(names),
		repo.WithByLikeName(search.Info),
		repo.WithOrderRuleBy(search.OrderBy, search.Order),
	)
	if err != nil {
		return total, nil, err
	}
	items := make([]dto.MysqlDBInfo, 0, len(mysqls))
	for _, mysql := range mysqls {
		var item dto.MysqlDBInfo
		if err := copier.Copy(&item, &mysql); err != nil {
			return 0, nil, buserr.WithDetail("ErrStructTransform", err.Error(), nil)
		}
		item.Username = ""
		item.Password = ""
		item.Permission = ""
		items = append(items, item)
	}
	return total, items, nil
}

func SearchPostgresqlForRBAC(search dto.PostgresqlDBSearch, allowedKeys []string) (int64, interface{}, error) {
	names := AllowedDatabaseNames(allowedKeys, "postgresql", search.Database)
	if len(names) == 0 {
		return 0, []dto.PostgresqlDBInfo{}, nil
	}
	total, rows, err := postgresqlRepo.Page(search.Page, search.PageSize,
		postgresqlRepo.WithByPostgresqlName(search.Database),
		repo.WithByNames(names),
		repo.WithByLikeName(search.Info),
		repo.WithOrderRuleBy(search.OrderBy, search.Order),
	)
	if err != nil {
		return total, nil, err
	}
	items := make([]dto.PostgresqlDBInfo, 0, len(rows))
	for _, row := range rows {
		var item dto.PostgresqlDBInfo
		if err := copier.Copy(&item, &row); err != nil {
			return 0, nil, buserr.WithDetail("ErrStructTransform", err.Error(), nil)
		}
		item.Password = ""
		items = append(items, item)
	}
	return total, items, nil
}

func SearchMongodbForRBAC(search dto.MongodbDBSearch, allowedKeys []string) (int64, interface{}, error) {
	names := AllowedDatabaseNames(allowedKeys, "mongodb", search.Database)
	if len(names) == 0 {
		return 0, []dto.MongodbDBInfo{}, nil
	}
	total, rows, err := mongodbRepo.Page(search.Page, search.PageSize,
		mongodbRepo.WithByMongodbName(search.Database),
		repo.WithByNames(names),
		repo.WithByLikeName(search.Info),
		repo.WithOrderRuleBy(search.OrderBy, search.Order),
	)
	if err != nil {
		return total, nil, err
	}
	items := make([]dto.MongodbDBInfo, 0, len(rows))
	for _, row := range rows {
		var item dto.MongodbDBInfo
		if err := copier.Copy(&item, &row); err != nil {
			return 0, nil, buserr.WithDetail("ErrStructTransform", err.Error(), nil)
		}
		item.Password = ""
		items = append(items, item)
	}
	return total, items, nil
}

func ResolveDatabaseResourceKeyByID(kind string, id uint) (string, error) {
	switch strings.ToLower(kind) {
	case "mysql", "mariadb", "mysql-cluster":
		item, err := mysqlRepo.Get(repo.WithByID(id))
		if err != nil {
			return "", err
		}
		return DatabaseResourceKey("mysql", item.MysqlName, item.Name), nil
	case "postgresql", "postgresql-cluster":
		item, err := postgresqlRepo.Get(repo.WithByID(id))
		if err != nil {
			return "", err
		}
		return DatabaseResourceKey("postgresql", item.PostgresqlName, item.Name), nil
	case "mongodb":
		item, err := mongodbRepo.Get(repo.WithByID(id))
		if err != nil {
			return "", err
		}
		return DatabaseResourceKey("mongodb", item.MongodbName, item.Name), nil
	default:
		return "", buserr.New("ErrTypeOfDatabase")
	}
}

func DatabaseResourceKeyFromRecord(record any) string {
	switch item := record.(type) {
	case model.DatabaseMysql:
		return DatabaseResourceKey("mysql", item.MysqlName, item.Name)
	case model.DatabasePostgresql:
		return DatabaseResourceKey("postgresql", item.PostgresqlName, item.Name)
	case model.DatabaseMongodb:
		return DatabaseResourceKey("mongodb", item.MongodbName, item.Name)
	default:
		return ""
	}
}
