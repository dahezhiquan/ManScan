package redis

import (
	lib_redis "ManScan/pkg/js/libs/redis"

	"ManScan/pkg/js/gojs"
	"github.com/Mzack9999/goja"
)

var (
	module = gojs.NewGojaModule("nuclei/redis")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"Connect":           lib_redis.Connect,
			"GetServerInfo":     lib_redis.GetServerInfo,
			"GetServerInfoAuth": lib_redis.GetServerInfoAuth,
			"IsAuthenticated":   lib_redis.IsAuthenticated,
			"RunLuaScript":      lib_redis.RunLuaScript,

			// Var and consts

			// Objects / Classes

		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
