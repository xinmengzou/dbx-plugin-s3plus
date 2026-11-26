package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/minio/minio-go/v7"
	dbxpluginsdk "github.com/t8y2/dbx/plugins/sdk/go/dbx-plugin-sdk"
)

// 桶能力探测状态:只读桶信息对每个能力单独探测,厂商对单个 API 的支持参差不齐,
// 状态必须逐项明示而不是整体失败。
const (
	bucketCapOK           = "ok"           // 拿到配置
	bucketCapUnconfigured = "unconfigured" // S3 明确返回"未配置"
	bucketCapUnsupported  = "unsupported"  // 厂商不支持该 API
	bucketCapError        = "error"        // 其它错误
)

type bucketCapability struct {
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// bucketInfo 只读桶管理信息:版本控制/策略/加密/生命周期/CORS。
// 只读边界:本方法不执行任何 SetBucket* 操作(商店审查认可的破坏面边界)。
// provider 权限检查由 main.go 分发表完成。
func (plugin *plugin) bucketInfo(values map[string]any) (any, *dbxpluginsdk.PluginError) {
	ctx, cancel := operationContext()
	defer cancel()
	connection, pluginError := plugin.connectionFor(values)
	if pluginError != nil {
		return nil, pluginError
	}
	path, pluginError := parseObjectPath(stringValue(values["uri"]), connection)
	if pluginError != nil {
		return nil, pluginError
	}
	if path.bucket == "" {
		return nil, invalidParams("Bucket name cannot be empty")
	}
	client := connection.client
	result := map[string]any{"bucket": path.bucket}

	if config, err := client.GetBucketVersioning(ctx, path.bucket); err != nil {
		result["versioning"] = classifyBucketCapability(err)
	} else {
		status := config.Status
		if status == "" {
			status = "Off"
		}
		detail := status
		if len(config.ExcludedPrefixes) > 0 {
			detail += fmt.Sprintf("; %d excluded prefixes", len(config.ExcludedPrefixes))
		}
		result["versioning"] = bucketCapability{Status: bucketCapOK, Detail: detail}
	}

	if policy, err := client.GetBucketPolicy(ctx, path.bucket); err != nil {
		result["policy"] = classifyBucketCapability(err)
	} else if strings.TrimSpace(policy) == "" {
		// minio-go 对 NoSuchBucketPolicy 返回 ("", nil)
		result["policy"] = bucketCapability{Status: bucketCapUnconfigured}
	} else {
		result["policy"] = bucketCapability{Status: bucketCapOK, Detail: summarizeBucketPolicy(policy)}
	}

	if config, err := client.GetBucketEncryption(ctx, path.bucket); err != nil {
		result["encryption"] = classifyBucketCapability(err)
	} else {
		detail := "configured"
		if len(config.Rules) > 0 && config.Rules[0].Apply.SSEAlgorithm != "" {
			detail = config.Rules[0].Apply.SSEAlgorithm
		}
		result["encryption"] = bucketCapability{Status: bucketCapOK, Detail: detail}
	}

	if config, err := client.GetBucketLifecycle(ctx, path.bucket); err != nil {
		result["lifecycle"] = classifyBucketCapability(err)
	} else {
		rules := make([]string, 0, len(config.Rules))
		for _, rule := range config.Rules {
			rules = append(rules, fmt.Sprintf("%s(%s)", rule.ID, strings.ToLower(rule.Status)))
		}
		result["lifecycle"] = bucketCapability{Status: bucketCapOK, Detail: fmt.Sprintf("%d rules: %s", len(config.Rules), strings.Join(rules, ", "))}
	}

	if config, err := client.GetBucketCors(ctx, path.bucket); err != nil {
		result["cors"] = classifyBucketCapability(err)
	} else if config == nil || len(config.CORSRules) == 0 {
		// minio-go 对 NoSuchCORSConfiguration 返回 (nil, nil)
		result["cors"] = bucketCapability{Status: bucketCapUnconfigured}
	} else {
		methods := map[string]bool{}
		for _, rule := range config.CORSRules {
			for _, method := range rule.AllowedMethod {
				methods[method] = true
			}
		}
		allowed := make([]string, 0, len(methods))
		for method := range methods {
			allowed = append(allowed, method)
		}
		sort.Strings(allowed)
		result["cors"] = bucketCapability{Status: bucketCapOK, Detail: fmt.Sprintf("%d rules; methods: %s", len(config.CORSRules), strings.Join(allowed, ", "))}
	}

	return result, nil
}

// classifyBucketCapability 把 S3 错误归类为能力状态:
// 已知的"未配置"错误码 → unconfigured;厂商未实现/不支持 → unsupported;其余 → error。
func classifyBucketCapability(err error) bucketCapability {
	response := minio.ToErrorResponse(err)
	switch {
	case response.Code == "NoSuchBucketPolicy",
		response.Code == "NoSuchBucketEncryption",
		response.Code == "NoSuchLifecycleConfiguration",
		response.Code == "NoSuchCORSConfiguration",
		response.Code == "NoSuchTagSet":
		return bucketCapability{Status: bucketCapUnconfigured}
	case response.Code == "NotImplemented", response.Code == "NotSupported",
		response.StatusCode == 501, response.StatusCode == 405,
		response.Code == "MethodNotAllowed":
		return bucketCapability{Status: bucketCapUnsupported, Detail: response.Code}
	case response.StatusCode == 404, response.Code == "NoSuchBucket":
		return bucketCapability{Status: bucketCapError, Detail: "bucket not found"}
	default:
		detail := strings.TrimSpace(response.Code + " " + response.Message)
		if detail == "" {
			detail = err.Error()
		}
		return bucketCapability{Status: bucketCapError, Detail: detail}
	}
}

// summarizeBucketPolicy 把策略 JSON 压成一行摘要,避免把整段策略塞进对话框。
func summarizeBucketPolicy(policy string) string {
	var parsed struct {
		Statement []struct {
			Effect string `json:"Effect"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(policy), &parsed); err != nil || len(parsed.Statement) == 0 {
		return fmt.Sprintf("%d bytes", len(policy))
	}
	allow, deny := 0, 0
	for _, statement := range parsed.Statement {
		if strings.EqualFold(statement.Effect, "Allow") {
			allow++
		} else {
			deny++
		}
	}
	return fmt.Sprintf("%d statements (%d allow / %d deny)", len(parsed.Statement), allow, deny)
}
