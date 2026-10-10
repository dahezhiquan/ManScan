package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	templateconfig "ManScan/pkg/catalog/config"

	fileutil "github.com/projectdiscovery/utils/file"
	"gopkg.in/yaml.v3"
)

const defaultServerAddress = ":8686"

type runtimeConfigFile struct {
	MySQL MySQLConfig `yaml:"mysql"`
	Auth  AuthConfig  `yaml:"auth"`
}

type Config struct {
	RootDir     string
	Address     string
	ConfigFile  string
	TemplateDir string
	MySQL       MySQLConfig
	Auth        AuthConfig
}

type MySQLConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Database string `yaml:"database"`
}

type AuthConfig struct {
	JWTSecret       string `yaml:"jwt_secret"`
	TokenTTLMinutes int    `yaml:"token_ttl_minutes"`
}

func Load() (*Config, error) {
	rootDir, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("获取工作目录失败: %w", err)
	}

	configFile := strings.TrimSpace(os.Getenv("MANSCAN_CONFIG_FILE"))
	if configFile == "" {
		configFile = filepath.Join(rootDir, "config.yaml")
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	var fileConfig runtimeConfigFile
	if err := yaml.Unmarshal(data, &fileConfig); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	if strings.TrimSpace(fileConfig.MySQL.Database) == "" {
		fileConfig.MySQL.Database = "manscan_scan"
	}
	if err := fileConfig.MySQL.Validate(); err != nil {
		return nil, err
	}
	fileConfig.Auth.ApplyEnv()
	if fileConfig.Auth.TokenTTLMinutes <= 0 {
		fileConfig.Auth.TokenTTLMinutes = 480
	}
	if err := fileConfig.Auth.Validate(); err != nil {
		return nil, err
	}

	templateDir := resolveTemplateDir(rootDir)
	if templateDir != "" {
		templateconfig.DefaultConfig.SetTemplatesDir(templateDir)
	}

	address := strings.TrimSpace(os.Getenv("MANSCAN_SERVER_ADDR"))
	if address == "" {
		address = defaultServerAddress
	}

	return &Config{
		RootDir:     rootDir,
		Address:     address,
		ConfigFile:  configFile,
		TemplateDir: templateDir,
		MySQL:       fileConfig.MySQL,
		Auth:        fileConfig.Auth,
	}, nil
}

func (c MySQLConfig) Validate() error {
	switch {
	case strings.TrimSpace(c.Username) == "":
		return fmt.Errorf("mysql.username 不能为空")
	case strings.TrimSpace(c.Host) == "":
		return fmt.Errorf("mysql.host 不能为空")
	case c.Port <= 0:
		return fmt.Errorf("mysql.port 必须大于 0")
	case strings.TrimSpace(c.Database) == "":
		return fmt.Errorf("mysql.database 不能为空")
	default:
		return nil
	}
}

func (c MySQLConfig) DSN() string {
	return fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=true&loc=Local",
		c.Username,
		c.Password,
		c.Host,
		c.Port,
		c.Database,
	)
}

func (c *AuthConfig) ApplyEnv() {
	if secret := strings.TrimSpace(os.Getenv("MANSCAN_JWT_SECRET")); secret != "" {
		c.JWTSecret = secret
	}
	if rawTTL := strings.TrimSpace(os.Getenv("MANSCAN_TOKEN_TTL_MINUTES")); rawTTL != "" {
		if ttl, err := strconv.Atoi(rawTTL); err == nil {
			c.TokenTTLMinutes = ttl
		}
	}
}

func (c AuthConfig) Validate() error {
	if len(strings.TrimSpace(c.JWTSecret)) < 32 {
		return fmt.Errorf("auth.jwt_secret 或 MANSCAN_JWT_SECRET 必须至少 32 个字符")
	}
	if c.TokenTTLMinutes <= 0 {
		return fmt.Errorf("auth.token_ttl_minutes 必须大于 0")
	}
	return nil
}

func (c AuthConfig) TokenTTL() time.Duration {
	return time.Duration(c.TokenTTLMinutes) * time.Minute
}

func resolveTemplateDir(rootDir string) string {
	type candidate struct {
		path string
	}

	configuredDir := strings.TrimSpace(templateconfig.DefaultConfig.GetTemplateDir())
	candidates := make([]candidate, 0, 5)

	if dir := strings.TrimSpace(os.Getenv("MANSCAN_TEMPLATES_DIR")); dir != "" {
		candidates = append(candidates, candidate{path: dir})
	}
	if dir := strings.TrimSpace(os.Getenv(templateconfig.NucleiTemplatesDirEnv)); dir != "" {
		candidates = append(candidates, candidate{path: dir})
	}
	if configuredDir != "" {
		candidates = append(candidates, candidate{path: configuredDir})
	}
	candidates = append(candidates,
		candidate{path: filepath.Join(rootDir, "manscan-templates")},
		candidate{path: filepath.Join(filepath.Dir(rootDir), "manscan-templates")},
	)

	for _, item := range candidates {
		if item.path == "" {
			continue
		}
		if fileutil.FolderExists(item.path) {
			return item.path
		}
	}

	return configuredDir
}
