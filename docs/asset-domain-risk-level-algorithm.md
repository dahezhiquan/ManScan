# 域名资产风险等级算法

## 目标

`risk_level` 用于表达一个域名资产当前整体风险，不只等于最高漏洞等级，而是综合以下因素：

- 有效漏洞数量与严重等级
- 资产区域与环境属性，例如外网高于内网，生产高于测试
- 当前存活组件数量，组件越多代表暴露面越大

## 数据口径

域名资产主表：

- 表：`manscan_asset_domain`
- 关联字段：`domain`
- 使用字段：`domain`、`region`、`is_alive`

漏洞表：

- 表：`manscan_vulnerabilities`
- 关联字段：`asset_endpoint = manscan_asset_domain.domain`
- 使用字段：`severity`、`status`

域名组件表：

- 表：`manscan_asset_domain_service_assets`
- 关联字段：`domain = manscan_asset_domain.domain`
- 使用字段：`is_alive`

## 有效漏洞过滤

计算风险时，漏洞数量需要排除以下状态：

```text
fixed
false_positive
ignored
```

也就是只统计仍然需要关注的漏洞，例如：

```text
unreviewed
confirmed
ticketed
空状态或未知状态
```

推荐 SQL 条件：

```sql
WHERE asset_endpoint = manscan_asset_domain.domain
  AND (
    status IS NULL
    OR status = ''
    OR status NOT IN ('fixed', 'false_positive', 'ignored')
  )
```

## 总分模型

推荐使用加法模型：

```text
risk_score = vulnerability_score + region_score + component_score
```

其中：

- `vulnerability_score` 体现漏洞严重程度和数量
- `region_score` 体现资产暴露面和环境重要性
- `component_score` 体现组件暴露面复杂度

最终 `risk_level` 由 `risk_score` 映射得到。

## 漏洞分

有效漏洞按严重等级加权：

| 漏洞等级 | 单个漏洞分值 |
| --- | ---: |
| critical | 40 |
| high | 20 |
| medium | 8 |
| low | 3 |

计算公式：

```text
vulnerability_score =
  critical_count * 40 +
  high_count * 20 +
  medium_count * 8 +
  low_count * 3
```

说明：

- 一个 `critical` 漏洞应足以让资产进入高风险以上。
- 多个 `high` 或多个 `medium` 可以把资产风险逐步推高。
- `low` 漏洞不会单独把资产推到高风险，但数量多时会体现累积风险。

## 区域与环境分

### 暴露区域分

| 区域关键词 | 分值 |
| --- | ---: |
| 外网 | 15 |
| 内网 | 5 |

### 环境分

| 环境关键词 | 分值 |
| --- | ---: |
| 生产 | 10 |
| 测试 | -8 |

计算方式：

```text
region_score = exposure_score + environment_score
```

示例：

```text
外网生产：15 + 10 = 25
外网测试：15 - 8 = 7
内网生产：5 + 10 = 15
内网测试：5 - 8 = -3
```

说明：

- 同样的漏洞，外网生产资产风险更高。
- 内网和测试环境不会清零漏洞风险，只降低环境加权。
- 如果当前 `region` 只有 `内网` / `外网`，则环境分按 `0` 处理。

## 组件暴露面分

组件数量只统计当前存活组件：

```sql
WHERE domain = manscan_asset_domain.domain
  AND is_alive = true
```

推荐分值：

| 存活组件数量 | 分值 |
| ---: | ---: |
| 0 | 0 |
| 1-2 | 2 |
| 3-5 | 5 |
| 6-10 | 8 |
| 11 及以上 | 12 |

说明：

- 组件数量只作为风险加权，不直接决定风险等级。
- 组件越多，代表资产技术栈更复杂、暴露面更大。
- 组件分最高限制为 `12`，避免纯组件数量压过真实漏洞风险。

## 风险等级映射

推荐阈值：

| risk_score | risk_level |
| ---: | --- |
| 80 及以上 | critical |
| 45-79 | high |
| 20-44 | medium |
| 1-19 | low |
| 0 及以下 | none |

推荐规则：

```text
if risk_score >= 80:
  risk_level = critical
elif risk_score >= 45:
  risk_level = high
elif risk_score >= 20:
  risk_level = medium
elif risk_score > 0:
  risk_level = low
else:
  risk_level = none
```

## 非存活资产处理

不要因为 `is_alive = false` 直接把风险清零。原因是：

- 资产可能只是本次探测不通，历史漏洞仍有安全价值。
- 域名可能短时不可访问，直接清零会导致风险波动过大。