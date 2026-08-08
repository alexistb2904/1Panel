package router

import (
	v2 "github.com/1Panel-dev/1Panel/agent/app/api/v2"
	"github.com/1Panel-dev/1Panel/agent/middleware"
	"github.com/gin-gonic/gin"
)

type FileRouter struct {
}

func (f *FileRouter) InitRouter(Router *gin.RouterGroup) {
	fileRouter := Router.Group("files")
	protected := fileRouter.Group("").Use(middleware.FileRBAC())
	baseApi := v2.ApiGroupApp.BaseApi
	{
		protected.POST("/search", baseApi.ListFiles)
		protected.POST("/ai-search", baseApi.FileAISearch)
		protected.POST("/upload/search", baseApi.SearchUploadWithPage)
		protected.POST("/tree", baseApi.GetFileTree)
		protected.POST("", baseApi.CreateFile)
		protected.POST("/del", baseApi.DeleteFile)
		protected.POST("/batch/del", baseApi.BatchDeleteFile)
		protected.POST("/mode", baseApi.ChangeFileMode)
		protected.POST("/owner", baseApi.ChangeFileOwner)
		protected.POST("/compress", baseApi.CompressFile)
		protected.POST("/compress/stop", baseApi.StopCompressFile)
		protected.POST("/decompress", baseApi.DeCompressFile)
		protected.POST("/decompress/stop", baseApi.StopDeCompressFile)
		protected.POST("/content", baseApi.GetContent)
		protected.POST("/preview", baseApi.PreviewContent)
		protected.POST("/save", baseApi.SaveContent)
		protected.POST("/history/search", baseApi.SearchFileHistory)
		protected.POST("/history/content", baseApi.GetFileHistoryContent)
		protected.POST("/history/del", baseApi.DeleteFileHistory)
		protected.POST("/history/restore", baseApi.RestoreFileHistory)
		protected.POST("/remarks", baseApi.BatchGetFileRemarks)
		protected.POST("/remark", baseApi.SetFileRemark)
		protected.POST("/check", baseApi.CheckFile)
		protected.POST("/batch/check", baseApi.BatchCheckFiles)
		protected.POST("/upload", baseApi.UploadFiles)
		protected.POST("/chunkupload", baseApi.UploadChunkFiles)
		protected.POST("/chunkupload/stop", baseApi.StopChunkUpload)
		protected.POST("/rename", baseApi.ChangeFileName)
		protected.POST("/wget", baseApi.WgetFile)
		protected.POST("/wget/stop", baseApi.StopWget)
		protected.POST("/move", baseApi.MoveFile)
		protected.GET("/download", baseApi.Download)
		protected.POST("/share/search", baseApi.SearchFileShare)
		protected.POST("/share/detail", baseApi.GetFileShareDetail)
		protected.POST("/share/create", baseApi.CreateFileShare)
		protected.POST("/share/del", baseApi.DeleteFileShare)
		protected.GET("/share/qrcode", baseApi.GetFileShareQRCode)
		protected.POST("/chunkdownload", baseApi.DownloadChunkFiles)
		protected.POST("/size", baseApi.Size)
		protected.POST("/depth/size", baseApi.DepthDirSize)
		protected.GET("/wget/process", baseApi.WgetProcess)
		protected.GET("/wget/process/keys", baseApi.ProcessKeys)
		protected.POST("/read/:type", baseApi.ReadFileByLine)
		protected.POST("/batch/role", baseApi.BatchChangeModeAndOwner)

		protected.POST("/recycle/search", baseApi.SearchRecycleBinFile)
		protected.POST("/recycle/reduce", baseApi.ReduceRecycleBinFile)
		protected.POST("/recycle/clear", baseApi.ClearRecycleBinFile)
		protected.GET("/recycle/status", baseApi.GetRecycleStatus)

		protected.POST("/favorite/search", baseApi.SearchFavorite)
		protected.POST("/favorite", baseApi.CreateFavorite)
		protected.POST("/favorite/del", baseApi.DeleteFavorite)

		protected.POST("/mount", baseApi.GetHostMount)
		protected.POST("/user/group", baseApi.GetUsersAndGroups)
		protected.POST("/convert", baseApi.ConvertFile)
		protected.POST("/convert/log", baseApi.ConvertLog)
	}

	publicShareRouter := fileRouter.Group("/share")
	publicShareRouter.Use(middleware.FileSharePublicAccess())
	{
		publicShareRouter.GET("/info", baseApi.GetPublicFileShareInfo)
		publicShareRouter.GET("/check", baseApi.CheckFileShare)
		publicShareRouter.GET("/download", baseApi.DownloadFileShare)
	}
}
