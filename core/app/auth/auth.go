package auth

import (
	"crypto/hmac"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/1Panel-dev/1Panel/core/app/dto"
	"github.com/1Panel-dev/1Panel/core/app/model"
	"github.com/1Panel-dev/1Panel/core/app/rbac"
	"github.com/1Panel-dev/1Panel/core/app/repo"
	"github.com/1Panel-dev/1Panel/core/buserr"
	"github.com/1Panel-dev/1Panel/core/constant"
	"github.com/1Panel-dev/1Panel/core/global"
	initauth "github.com/1Panel-dev/1Panel/core/init/auth"
	"github.com/1Panel-dev/1Panel/core/init/session/psession"
	"github.com/1Panel-dev/1Panel/core/utils/common"
	"github.com/1Panel-dev/1Panel/core/utils/encrypt"
	"github.com/1Panel-dev/1Panel/core/utils/mfa"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const communityAuthSource = "community"

func Login(c *gin.Context, info dto.Login, entrance string) (*dto.UserLoginInfo, string, error) {
	if err := CheckEntrance(entrance); err != nil {
		return nil, "ErrEntrance", err
	}
	settingRepo := repo.NewISettingRepo()
	priKey, err := settingRepo.Get(repo.WithByKey("PASSWORD_PRIVATE_KEY"))
	if err != nil {
		return nil, "", err
	}
	if err := settingRepo.Update("Language", info.Language); err != nil {
		return nil, "", err
	}

	var user model.AccessUser
	err = global.DB.Where("username = ?", info.Name).First(&user).Error
	if err == nil {
		return loginCommunityUser(c, user, info.Password, priKey.Value, entrance)
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, "", err
	}
	return legacyLogin(c, info, entrance, priKey.Value)
}

func loginCommunityUser(c *gin.Context, user model.AccessUser, encryptedPassword, privateKey, entrance string) (*dto.UserLoginInfo, string, error) {
	if user.Status != model.AccessUserStatusActive {
		return nil, "ErrAuth", buserr.New("ErrAuth")
	}
	password, err := DecryptLoginPassword(privateKey, encryptedPassword)
	if err != nil {
		return nil, "ErrAuth", err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, "ErrAuth", buserr.New("ErrAuth")
	}
	if user.MFAEnabled {
		ip := common.GetRealClientIP(c)
		mfaSession := initauth.GetMFASessionStore().SetWithAuthSource(user.Username, entrance, ip, communityAuthSource, user.ID, 0)
		return &dto.UserLoginInfo{Name: user.Username, Role: roleForUser(user.ID), MfaStatus: constant.StatusEnable, MfaSession: mfaSession}, "", nil
	}
	return finishCommunityLogin(c, user, entrance)
}

func legacyLogin(c *gin.Context, info dto.Login, entrance, privateKey string) (*dto.UserLoginInfo, string, error) {
	settingRepo := repo.NewISettingRepo()
	nameSetting, err := settingRepo.Get(repo.WithByKey("UserName"))
	if err != nil {
		return nil, "", buserr.New("ErrRecordNotFound")
	}
	if info.Name != nameSetting.Value {
		return nil, "ErrAuth", buserr.New("ErrAuth")
	}
	passwordSetting, err := settingRepo.Get(repo.WithByKey("Password"))
	if err != nil {
		return nil, "", err
	}
	if err = CheckPassword(privateKey, info.Password, passwordSetting.Value); err != nil {
		return nil, "ErrAuth", err
	}
	mfaSetting, err := settingRepo.Get(repo.WithByKey("MFAStatus"))
	if err != nil {
		return nil, "", err
	}
	if mfaSetting.Value == constant.StatusEnable {
		return BeginMFALogin(c, nameSetting.Value, entrance, mfaSetting.Value), "", nil
	}
	sessionUser := psession.SessionUser{ID: psession.SuperAdminSessionUserID, Name: nameSetting.Value, Role: "ADMIN"}
	res, err := GenerateSession(c, sessionUser)
	if err != nil {
		return nil, "", err
	}
	if entrance != "" {
		SetSecurityEntranceCookie(c, entrance)
	}
	return res, "", nil
}

func MFALogin(c *gin.Context, info dto.MFALogin, entrance string) (*dto.UserLoginInfo, string, error) {
	mfaSession, ok := initauth.GetMFASessionStore().Get(info.SessionID)
	if ok && mfaSession.AuthSource == communityAuthSource {
		user, errCode, err := verifyCommunityMFALogin(c, info.SessionID, info.Code, entrance)
		if errCode != "" || err != nil {
			return nil, errCode, err
		}
		return finishCommunityLogin(c, *user, entrance)
	}

	name, errCode, err := VerifyMFALogin(c, info.SessionID, info.Code, entrance)
	if errCode != "" {
		return nil, errCode, err
	}
	sessionUser := psession.SessionUser{ID: psession.SuperAdminSessionUserID, Name: name, Role: "ADMIN"}
	res, err := GenerateSession(c, sessionUser)
	if err != nil {
		return nil, "", err
	}
	if entrance != "" {
		SetSecurityEntranceCookie(c, entrance)
	}
	return res, "", nil
}

func finishCommunityLogin(c *gin.Context, user model.AccessUser, entrance string) (*dto.UserLoginInfo, string, error) {
	sessionUser := psession.SessionUser{ID: strconv.FormatUint(uint64(user.ID), 10), Name: user.Username, Role: roleForUser(user.ID)}
	res, err := GenerateSession(c, sessionUser)
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	_ = global.DB.Model(&model.AccessUser{}).Where("id = ?", user.ID).Update("last_login_at", &now).Error
	if entrance != "" {
		SetSecurityEntranceCookie(c, entrance)
	}
	return res, "", nil
}

func roleForUser(userID uint) string {
	type roleRow struct {
		Key  string
		Sort int
	}
	var roles []roleRow
	_ = global.DB.Table("rbac_roles AS r").
		Select("DISTINCT r.key, r.sort").
		Joins("JOIN rbac_role_bindings b ON b.role_id = r.id").
		Where("b.user_id = ?", userID).
		Order("r.sort ASC").
		Scan(&roles).Error
	for _, role := range roles {
		if role.Key == rbac.RoleAdministrator {
			return "ADMIN"
		}
	}
	if len(roles) == 0 {
		return "USER"
	}
	return strings.ToUpper(roles[0].Key)
}

func verifyCommunityMFALogin(c *gin.Context, sessionID, code, entrance string) (*model.AccessUser, string, error) {
	mfaSessions := initauth.GetMFASessionStore()
	session, ok := mfaSessions.Get(sessionID)
	if !ok || session.AuthSource != communityAuthSource {
		return nil, "ErrMFA", nil
	}
	if session.IP != common.GetRealClientIP(c) || session.Entrance != entrance {
		return nil, "ErrMFA", nil
	}
	var user model.AccessUser
	if err := global.DB.First(&user, session.AuthSourceID).Error; err != nil {
		return nil, "ErrAuth", err
	}
	if user.Status != model.AccessUserStatusActive || !user.MFAEnabled || user.MFASecret == "" {
		return nil, "ErrAuth", buserr.New("ErrAuth")
	}
	secret, err := encrypt.StringDecrypt(user.MFASecret)
	if err != nil {
		return nil, "", err
	}
	interval := user.MFAInterval
	if interval <= 0 {
		interval = 30
	}
	if !mfa.ValidCode(interval, code, secret) {
		return nil, "ErrMFA", nil
	}
	mfaSessions.Delete(sessionID)
	return &user, "", nil
}

func BeginMFALogin(c *gin.Context, name, entrance, mfaStatus string) *dto.UserLoginInfo {
	ip := common.GetRealClientIP(c)
	mfaSession := initauth.GetMFASessionStore().Set(name, entrance, ip)
	return &dto.UserLoginInfo{Name: name, MfaStatus: mfaStatus, MfaSession: mfaSession}
}

func BeginAuthSourceMFALogin(
	c *gin.Context,
	name, entrance, mfaStatus, authSource string,
	authSourceID uint,
	authSourceConfigVersion uint64,
) *dto.UserLoginInfo {
	ip := common.GetRealClientIP(c)
	mfaSession := initauth.GetMFASessionStore().SetWithAuthSource(name, entrance, ip, authSource, authSourceID, authSourceConfigVersion)
	return &dto.UserLoginInfo{Name: name, MfaStatus: mfaStatus, MfaSession: mfaSession}
}

func BeginAuthSourceMFALoginWithSession(
	c *gin.Context,
	name, entrance, mfaStatus, authSource string,
	authSourceID uint,
	authSourceConfigVersion uint64,
	externalIssuer, externalNameID, externalNameIDFormat, externalSessionIndex string,
	externalSessionExpiresAt time.Time,
	externalSessionRequired bool,
) *dto.UserLoginInfo {
	ip := common.GetRealClientIP(c)
	mfaSession := initauth.GetMFASessionStore().SetWithAuthSourceSession(
		name, entrance, ip, authSource, authSourceID, authSourceConfigVersion,
		externalIssuer, externalNameID, externalNameIDFormat, externalSessionIndex,
		externalSessionExpiresAt, externalSessionRequired,
	)
	return &dto.UserLoginInfo{Name: name, MfaStatus: mfaStatus, MfaSession: mfaSession}
}

func VerifyMFALogin(c *gin.Context, sessionID, code, entrance string) (string, string, error) {
	settingRepo := repo.NewISettingRepo()
	mfaSessions := initauth.GetMFASessionStore()
	session, ok := mfaSessions.Get(sessionID)
	if !ok {
		return "", "ErrMFA", nil
	}
	if session.IP != common.GetRealClientIP(c) {
		return "", "ErrMFA", nil
	}
	if session.Entrance != entrance {
		return "", "", buserr.New("ErrEntrance")
	}
	mfaSecret, err := settingRepo.GetValueByKey("MFASecret")
	if err != nil {
		return "", "", err
	}
	mfaInterval, err := settingRepo.GetValueByKey("MFAInterval")
	if err != nil {
		return "", "", err
	}
	interval, err := strconv.Atoi(mfaInterval)
	if err != nil {
		return "", "", err
	}
	if !mfa.ValidCode(interval, code, mfaSecret) {
		return "", "ErrMFA", nil
	}
	mfaSessions.Delete(sessionID)
	return session.Name, "", nil
}

func GenerateSession(c *gin.Context, sessionUser psession.SessionUser) (*dto.UserLoginInfo, error) {
	settingRepo := repo.NewISettingRepo()
	setting, err := settingRepo.Get(repo.WithByKey("SessionTimeout"))
	if err != nil {
		return nil, err
	}
	httpsSetting, err := settingRepo.Get(repo.WithByKey("SSL"))
	if err != nil {
		return nil, err
	}
	lifeTime, err := strconv.Atoi(setting.Value)
	if err != nil {
		return nil, err
	}
	if err := global.SESSION.SetFresh(c, sessionUser, httpsSetting.Value == constant.StatusEnable, lifeTime); err != nil {
		return nil, err
	}
	return &dto.UserLoginInfo{Name: sessionUser.Name, Role: sessionUser.Role}, nil
}

func SetSecurityEntranceCookie(c *gin.Context, entrance string) {
	settingRepo := repo.NewISettingRepo()
	entranceValue := base64.StdEncoding.EncodeToString([]byte(entrance))
	sslEnabled := false
	if setting, err := settingRepo.Get(repo.WithByKey("SSL")); err == nil {
		sslEnabled = setting.Value == constant.StatusEnable
	}
	c.SetCookie("SecurityEntrance", entranceValue, 0, "/", "", sslEnabled, true)
}

func CheckEntrance(entrance string) error {
	settingRepo := repo.NewISettingRepo()
	entranceSetting, err := settingRepo.Get(repo.WithByKey("SecurityEntrance"))
	if err != nil {
		return err
	}
	if len(entranceSetting.Value) != 0 && entranceSetting.Value != entrance {
		return buserr.New("ErrEntrance")
	}
	return nil
}

func CheckPassword(priKey, password, passwordFromDB string) error {
	loginPassword, err := DecryptLoginPassword(priKey, password)
	if err != nil {
		return err
	}
	existPassword, err := encrypt.StringDecrypt(passwordFromDB)
	if err != nil {
		return err
	}
	if !hmac.Equal([]byte(loginPassword), []byte(existPassword)) {
		return buserr.New("ErrAuth")
	}
	return nil
}

func DecryptLoginPassword(priKey, password string) (string, error) {
	privateKey, err := encrypt.ParseRSAPrivateKey(priKey)
	if err != nil {
		return "", err
	}
	loginPassword, err := encrypt.DecryptPassword(password, privateKey)
	if err != nil {
		return "", err
	}
	return loginPassword, nil
}

func currentAccessUser(c *gin.Context) (*model.AccessUser, error) {
	sessionUser, err := global.SESSION.Get(c)
	if err != nil {
		return nil, err
	}
	var user model.AccessUser
	if sessionUser.ID == psession.SuperAdminSessionUserID {
		err = global.DB.Where("username = ?", sessionUser.Name).First(&user).Error
		return &user, err
	}
	id, err := strconv.ParseUint(sessionUser.ID, 10, 64)
	if err != nil || id == 0 {
		return nil, gorm.ErrRecordNotFound
	}
	err = global.DB.First(&user, uint(id)).Error
	return &user, err
}

func LoadMFAForContext(c *gin.Context, req dto.MfaRequest) (mfa.Otp, error) {
	user, err := currentAccessUser(c)
	if err != nil {
		return LoadMFA(req)
	}
	return mfa.GetOtp(user.Username, req.Title, req.Interval)
}

func MFABindForContext(c *gin.Context, req dto.MfaCredential) error {
	if !mfa.ValidCode(req.Interval, req.Code, req.Secret) {
		return errors.New("code is not valid")
	}
	user, err := currentAccessUser(c)
	if err != nil {
		return MFABind(req)
	}
	secret, err := encrypt.StringEncrypt(req.Secret)
	if err != nil {
		return err
	}
	return global.DB.Model(user).Updates(map[string]any{"mfa_enabled": true, "mfa_secret": secret, "mfa_interval": req.Interval}).Error
}

func MFACloseForContext(c *gin.Context) error {
	user, err := currentAccessUser(c)
	if err != nil {
		return MFAClose()
	}
	if user.RequireMFA {
		return errors.New("MFA is required for this account")
	}
	return global.DB.Model(user).Updates(map[string]any{"mfa_enabled": false, "mfa_secret": ""}).Error
}

func LoadMFA(req dto.MfaRequest) (mfa.Otp, error) {
	settingRepo := repo.NewISettingRepo()
	username, err := settingRepo.GetValueByKey("UserName")
	if err != nil {
		return mfa.Otp{}, err
	}
	return mfa.GetOtp(username, req.Title, req.Interval)
}

func MFABind(req dto.MfaCredential) error {
	if !mfa.ValidCode(req.Interval, req.Code, req.Secret) {
		return errors.New("code is not valid")
	}
	settingRepo := repo.NewISettingRepo()
	if err := settingRepo.Update("MFAInterval", strconv.Itoa(req.Interval)); err != nil {
		return err
	}
	if err := settingRepo.Update("MFAStatus", constant.StatusEnable); err != nil {
		return err
	}
	if err := settingRepo.Update("MFASecret", req.Secret); err != nil {
		return err
	}
	return nil
}

func MFAClose() error {
	return repo.NewISettingRepo().Update("MFAStatus", constant.StatusDisable)
}

func GetCurrentUserInfoForContext(c *gin.Context) (*dto.CurrentUserInfo, error) {
	user, err := currentAccessUser(c)
	if err != nil {
		return GetCurrentUserInfo()
	}
	settings, err := repo.NewISettingRepo().List()
	if err != nil {
		return nil, err
	}
	settingMap := make(map[string]string, len(settings))
	for _, item := range settings {
		settingMap[item.Key] = item.Value
	}
	permissions, err := rbac.NewEvaluator(global.DB).PermissionCodes(user.ID)
	if err != nil {
		return nil, err
	}
	info := &dto.CurrentUserInfo{
		Name: user.Username, MFAStatus: constant.StatusDisable, MFAInterval: user.MFAInterval,
		Role: roleForUser(user.ID), Permissions: permissions, NodeRoles: []dto.CurrentUserNodeRole{},
		AuthSource: user.AuthSource, AuthSourceStatus: user.Status,
		RequireMFA: user.RequireMFA,
		ApiInterfaceStatus: settingMap["ApiInterfaceStatus"], ApiKey: settingMap["ApiKey"],
		IpWhiteList: settingMap["IpWhiteList"], ApiTrustedProxies: settingMap["ApiTrustedProxies"],
	}
	if user.MFAEnabled {
		info.MFAStatus = constant.StatusEnable
	}
	info.ApiKeyValidityTime, _ = strconv.Atoi(settingMap["ApiKeyValidityTime"])

	type nodeRoleRow struct {
		ScopeID string
		RoleID  uint
		RoleName string
	}
	var rows []nodeRoleRow
	_ = global.DB.Table("rbac_role_bindings AS b").
		Select("b.scope_id, r.id AS role_id, r.name AS role_name").
		Joins("JOIN rbac_roles r ON r.id = b.role_id").
		Where("b.user_id = ? AND b.scope_type = ?", user.ID, model.AccessScopeNode).
		Scan(&rows).Error
	for _, row := range rows {
		nodeID, _ := strconv.ParseUint(row.ScopeID, 10, 64)
		info.NodeRoles = append(info.NodeRoles, dto.CurrentUserNodeRole{NodeID: uint(nodeID), RoleID: row.RoleID, RoleName: row.RoleName})
	}
	return info, nil
}

func GetCurrentUserInfo() (*dto.CurrentUserInfo, error) {
	setting, err := repo.NewISettingRepo().List()
	if err != nil {
		return nil, buserr.New("ErrRecordNotFound")
	}
	settingMap := make(map[string]string)
	for _, set := range setting {
		settingMap[set.Key] = set.Value
	}
	var info dto.CurrentUserInfo
	stringSettingMap := make(map[string]string, len(settingMap))
	for key, value := range settingMap {
		stringSettingMap[key] = value
	}
	delete(stringSettingMap, "SessionTimeout")
	delete(stringSettingMap, "ExpirationDays")
	delete(stringSettingMap, "MFAInterval")
	delete(stringSettingMap, "ApiKeyValidityTime")
	arr, err := json.Marshal(stringSettingMap)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(arr, &info); err != nil {
		return nil, err
	}
	info.MFAInterval, _ = strconv.Atoi(settingMap["MFAInterval"])
	info.ApiKeyValidityTime, _ = strconv.Atoi(settingMap["ApiKeyValidityTime"])
	info.Name = settingMap["UserName"]
	info.AuthSource = "local"
	info.AuthSourceStatus = "active"
	info.Role = "ADMIN"
	info.Permissions = []string{}
	info.NodeRoles = []dto.CurrentUserNodeRole{}
	return &info, nil
}

func ShouldCheckPasswordExpiration(c *gin.Context) (bool, error) {
	_, err := currentAccessUser(c)
	if err == nil {
		return true, nil
	}
	return true, nil
}

func LoadPasswordExpirationTimeForContext(c *gin.Context) (string, error) {
	user, err := currentAccessUser(c)
	if err != nil {
		return LoadPasswordExpirationTime(c)
	}
	daysRaw, err := repo.NewISettingRepo().GetValueByKey("ExpirationDays")
	if err != nil {
		return "", err
	}
	days, _ := strconv.Atoi(daysRaw)
	if days <= 0 {
		return "", nil
	}
	changedAt := user.CreatedAt
	if user.PasswordChangedAt != nil {
		changedAt = *user.PasswordChangedAt
	}
	return changedAt.AddDate(0, 0, days).Format(constant.DateTimeLayout), nil
}

func LoadPasswordExpirationTime(_ *gin.Context) (string, error) {
	return repo.NewISettingRepo().GetValueByKey("ExpirationTime")
}

func SyncPasswordExpirationTime(expirationDays string) error {
	expiredDays, _ := strconv.Atoi(expirationDays)
	return repo.NewISettingRepo().Update("ExpirationTime", buildPasswordExpirationTime(expiredDays))
}

func UpdateCurrentUserInfoForContext(c *gin.Context, req dto.CurrentUserUpdate) error {
	user, err := currentAccessUser(c)
	if err != nil {
		return UpdateCurrentUserInfo(c, req)
	}
	updates := map[string]any{}
	if req.Name != "" && req.Name != user.Username {
		var count int64
		if err := global.DB.Model(&model.AccessUser{}).Where("username = ? AND id <> ?", req.Name, user.ID).Count(&count).Error; err != nil {
			return err
		}
		if count != 0 {
			return errors.New("username already exists")
		}
		updates["username"] = req.Name
	}
	if req.Password != "" {
		if req.OldPassword == "" {
			return buserr.New("ErrInitialPassword")
		}
		oldPassword, err := base64.StdEncoding.DecodeString(req.OldPassword)
		if err != nil {
			return err
		}
		newPassword, err := base64.StdEncoding.DecodeString(req.Password)
		if err != nil {
			return err
		}
		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), oldPassword); err != nil {
			return buserr.New("ErrInitialPassword")
		}
		hash, err := bcrypt.GenerateFromPassword(newPassword, bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		now := time.Now()
		updates["password_hash"] = string(hash)
		updates["password_changed_at"] = &now
	}
	if len(updates) == 0 {
		return nil
	}
	if err := global.DB.Model(user).Updates(updates).Error; err != nil {
		return err
	}
	deleteCurrentSession(c)
	return nil
}

func UpdateCurrentUserInfo(c *gin.Context, req dto.CurrentUserUpdate) error {
	settingRepo := repo.NewISettingRepo()
	currentName, err := settingRepo.GetValueByKey("UserName")
	if err != nil {
		return err
	}
	shouldDeleteSession := len(req.Password) != 0 || req.Name != currentName
	if len(req.Password) != 0 {
		if len(req.OldPassword) == 0 {
			return buserr.New("ErrInitialPassword")
		}
		oldPassword, err := base64.StdEncoding.DecodeString(req.OldPassword)
		if err != nil {
			return err
		}
		newPassword, err := base64.StdEncoding.DecodeString(req.Password)
		if err != nil {
			return err
		}
		if err := HandlePasswordExpired(c, string(oldPassword), string(newPassword)); err != nil {
			return err
		}
	}
	if err := settingRepo.Update("UserName", req.Name); err != nil {
		return err
	}
	if shouldDeleteSession {
		deleteCurrentSession(c)
	}
	return nil
}

func GenerateApiKey() (string, error) {
	apiKey := common.RandStr(32)
	if err := repo.NewISettingRepo().Update("ApiKey", apiKey); err != nil {
		return "", err
	}
	return apiKey, nil
}

func UpdateApiConfig(req dto.ApiInterfaceConfig) error {
	settingRepo := repo.NewISettingRepo()
	trustedProxies, err := NormalizeAPITrustedProxies(req.ApiTrustedProxies)
	if err != nil {
		return err
	}
	if err := settingRepo.UpdateOrCreate("ApiInterfaceStatus", req.ApiInterfaceStatus); err != nil {
		return err
	}
	if err := settingRepo.UpdateOrCreate("ApiKey", req.ApiKey); err != nil {
		return err
	}
	if err := settingRepo.UpdateOrCreate("IpWhiteList", req.IpWhiteList); err != nil {
		return err
	}
	if err := settingRepo.UpdateOrCreate("ApiTrustedProxies", trustedProxies); err != nil {
		return err
	}
	if err := settingRepo.UpdateOrCreate("ApiKeyValidityTime", strconv.Itoa(req.ApiKeyValidityTime)); err != nil {
		return err
	}
	return nil
}

func HandlePasswordExpiredForContext(c *gin.Context, old, new string) error {
	user, err := currentAccessUser(c)
	if err != nil {
		return HandlePasswordExpired(c, old, new)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(old)); err != nil {
		return buserr.New("ErrInitialPassword")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(new), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	now := time.Now()
	if err := global.DB.Model(user).Updates(map[string]any{"password_hash": string(hash), "password_changed_at": &now}).Error; err != nil {
		return err
	}
	deleteCurrentSession(c)
	return nil
}

func HandlePasswordExpired(c *gin.Context, old, new string) error {
	settingRepo := repo.NewISettingRepo()
	setting, err := settingRepo.Get(repo.WithByKey("Password"))
	if err != nil {
		return err
	}
	passwordFromDB, err := encrypt.StringDecrypt(setting.Value)
	if err != nil {
		return err
	}
	if passwordFromDB == old {
		newPassword, err := encrypt.StringEncrypt(new)
		if err != nil {
			return err
		}
		if err := settingRepo.Update("Password", newPassword); err != nil {
			return err
		}
		expiredSetting, err := settingRepo.Get(repo.WithByKey("ExpirationDays"))
		if err != nil {
			return err
		}
		timeout, _ := strconv.Atoi(expiredSetting.Value)
		if err := settingRepo.Update("ExpirationTime", buildPasswordExpirationTime(timeout)); err != nil {
			return err
		}
		return nil
	}
	return buserr.New("ErrInitialPassword")
}

func buildPasswordExpirationTime(expirationDays int) string {
	if expirationDays == 0 {
		return ""
	}
	return time.Now().AddDate(0, 0, expirationDays).Format(constant.DateTimeLayout)
}

func deleteCurrentSession(c *gin.Context) {
	if c == nil {
		return
	}
	sessionUser, err := global.SESSION.Get(c)
	if err != nil || sessionUser.ID == "" {
		return
	}
	_ = global.SESSION.DeleteByID(sessionUser.ID)
}
