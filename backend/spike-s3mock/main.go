// spike-s3mock: 本地 spike 用的最小 S3 兼容服务(仅回环,仅测试用,不提交)。
// 覆盖连接/列举/单对象读写/multipart 上传/版本化,足够通过 repo 的 local_s3_test.go。
// 环境变量:SPIKE_S3_ADDR(默认 127.0.0.1:9000)、SPIKE_S3_DELAY_MS(每请求人工延迟,默认 0)
package main

import (
	"bufio"
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const s3XMLNS = "http://s3.amazonaws.com/doc/2006-03-01/"

type objVersion struct {
	data        []byte
	etag        string
	mtime       time.Time
	vid         string
	contentType string
}

// decodeAWSChunked 剥掉 minio-go 的 STREAMING-AWS4-HMAC-SHA256 分块框架,
// 只留载荷字节。头部行形如 "SIZE;chunk-signature=hex" 或 "SIZE",SIZE=0 结束,
// 之后是 trailer 头(读到空行为止)。
type chunkedReader struct {
	br        *bufio.Reader
	remaining int
	done      bool
	err       error
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	for c.remaining == 0 && !c.done && c.err == nil {
		line, err := c.br.ReadString('\n')
		if err != nil {
			c.done, c.err = true, err
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" { // 结束后的空行分隔
			continue
		}
		head := strings.SplitN(line, ";", 2)[0]
		n, err := strconv.ParseInt(head, 16, 64)
		if err != nil {
			c.done, c.err = true, fmt.Errorf("bad chunk header %q: %w", line, err)
			break
		}
		if n == 0 {
			c.done = true // 后续 trailer 忽略
		} else {
			c.remaining = int(n)
		}
	}
	if c.remaining > 0 && len(p) > 0 && c.err == nil {
		if int64(len(p)) > int64(c.remaining) {
			p = p[:c.remaining]
		}
		n, err := io.ReadFull(c.br, p)
		c.remaining -= n
		return n, err
	}
	if c.err != nil && c.err != io.EOF {
		return 0, c.err
	}
	return 0, io.EOF
}

func newBodyDecoder(r *http.Request) {
	if strings.HasPrefix(r.Header.Get("x-amz-content-sha256"), "STREAMING") {
		r.Body = io.NopCloser(&chunkedReader{br: bufio.NewReader(r.Body)})
		r.ContentLength = -1
	}
}

type mpUpload struct {
	key   string
	parts map[int][]byte
}

type bucket struct {
	versioning string // "" | "Enabled" | "Suspended"
	configs    map[string]string // policy/encryption/lifecycle/cors 的原始配置体
	objects    map[string][]objVersion
	uploads    map[string]*mpUpload
}

type store struct {
	mu      sync.Mutex
	buckets map[string]*bucket
	vidSeq  int
}

var st = &store{buckets: map[string]*bucket{}}

func newETag(b []byte) string {
	sum := md5.Sum(b)
	return hex.EncodeToString(sum[:])
}

func newVID() string {
	st.vidSeq++
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("spike-%04d-%s", st.vidSeq, hex.EncodeToString(b))
}

func xmlError(w http.ResponseWriter, code int, codeName, message string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(code)
	_ = xml.NewEncoder(w).Encode(struct {
		XMLName xml.Name `xml:"Error"`
		Code    string
		Message string
	}{Code: codeName, Message: message})
}

func bucketOf(name string) *bucket { return st.buckets[name] }

func main() {
	addr := os.Getenv("SPIKE_S3_ADDR")
	if addr == "" {
		addr = "127.0.0.1:9000"
	}
	delay := 0
	if v := os.Getenv("SPIKE_S3_DELAY_MS"); v != "" {
		delay, _ = strconv.Atoi(v)
	}

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		if delay > 0 {
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
		if !strings.HasPrefix(r.RemoteAddr, "127.0.0.1") && !strings.HasPrefix(r.RemoteAddr, "[::1]") {
			xmlError(w, 403, "AccessDenied", "loopback only")
			return
		}
		newBodyDecoder(r)
		st.mu.Lock()
		defer st.mu.Unlock()
		log.Printf("%s %s%s in=%d", r.Method, r.Host, r.URL.String(), r.ContentLength)

		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			handleService(w, r)
			return
		}
		parts := strings.SplitN(path, "/", 2)
		bname := parts[0]
		key := ""
		if len(parts) > 1 {
			key = parts[1]
		}
		q := r.URL.Query()

		b := bucketOf(bname)
		if key == "" {
			switch r.Method {
			case http.MethodPut:
				if q.Has("policy") || q.Has("encryption") || q.Has("lifecycle") || q.Has("cors") {
					if b == nil {
						xmlError(w, 404, "NoSuchBucket", "bucket not found")
						return
					}
					for _, capKind := range []string{"policy", "encryption", "lifecycle", "cors"} {
						if q.Has(capKind) {
							body, err := io.ReadAll(r.Body)
							if err != nil {
								xmlError(w, 400, "IncompleteBody", err.Error())
								return
							}
							b.configs[capKind] = string(body)
							w.WriteHeader(204)
							return
						}
					}
				}
				if q.Has("versioning") {
					if b == nil {
						xmlError(w, 404, "NoSuchBucket", "bucket not found")
						return
					}
					body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
					if strings.Contains(string(body), "Enabled") {
						b.versioning = "Enabled"
					} else if strings.Contains(string(body), "Suspended") {
						b.versioning = "Suspended"
					}
					w.WriteHeader(200)
					return
				}
				if b != nil {
					xmlError(w, 409, "BucketAlreadyOwnedByYou", "exists")
					return
				}
				st.buckets[bname] = &bucket{configs: map[string]string{}, objects: map[string][]objVersion{}, uploads: map[string]*mpUpload{}}
				w.Header().Set("Location", "/"+bname)
				w.WriteHeader(200)
			case http.MethodHead:
				if b == nil {
					w.WriteHeader(404)
					return
				}
				w.WriteHeader(200)
			case http.MethodDelete:
				if b == nil {
					xmlError(w, 404, "NoSuchBucket", "bucket not found")
					return
				}
				delete(st.buckets, bname)
				w.WriteHeader(204)
			case http.MethodGet:
				if b == nil {
					xmlError(w, 404, "NoSuchBucket", "bucket not found")
					return
				}
				for _, cap := range []struct{ param, missing string }{
					{"policy", "NoSuchBucketPolicy"},
					{"encryption", "NoSuchBucketEncryption"},
					{"lifecycle", "NoSuchLifecycleConfiguration"},
					{"cors", "NoSuchCORSConfiguration"},
				} {
					if q.Has(cap.param) {
						body, ok := b.configs[cap.param]
						if !ok {
							xmlError(w, 404, cap.missing, "not configured")
							return
						}
						w.Header().Set("Content-Type", "application/xml")
						w.WriteHeader(200)
						io.WriteString(w, body)
						return
					}
				}
				if q.Has("versions") {
					listVersions(w, bname, b, q.Get("prefix"))
					return
				}
				if q.Has("versioning") {
					out := xmlHeader + `<VersioningConfiguration xmlns="` + s3XMLNS + `"`
					if b.versioning != "" {
						out += `><Status>` + b.versioning + `</Status></VersioningConfiguration>`
					} else {
						out += `/>`
					}
					io.WriteString(w, out)
					return
				}
				if q.Has("uploads") {
					io.WriteString(w, xmlHeader+`<ListMultipartUploadsResult xmlns="`+s3XMLNS+`"><Bucket>`+bname+`</Bucket><KeyMarker></KeyMarker><UploadIdMarker></UploadIdMarker><MaxUploads>1000</MaxUploads><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>`)
					return
				}
				listObjectsV2(w, bname, b, q)
			default:
				xmlError(w, 405, "MethodNotAllowed", "unsupported")
			}
			return
		}

		// object-level
		if b == nil {
			xmlError(w, 404, "NoSuchBucket", "bucket not found")
			return
		}
		if r.Method == http.MethodPost && q.Has("uploads") {
			handleMultipart(w, r, b, key, "", q)
			return
		}
		if uid := q.Get("uploadId"); uid != "" {
			handleMultipart(w, r, b, key, uid, q)
			return
		}
		switch r.Method {
		case http.MethodPut:
			data, err := io.ReadAll(r.Body)
			if err != nil {
				xmlError(w, 400, "IncompleteBody", err.Error())
				return
			}
			etag := newETag(data)
			v := objVersion{data: data, etag: etag, mtime: time.Now().UTC(), vid: "", contentType: r.Header.Get("Content-Type")}
			if b.versioning == "Enabled" {
				v.vid = newVID()
			}
			b.objects[key] = append([]objVersion{v}, b.objects[key]...)
			w.Header().Set("ETag", `"`+etag+`"`)
			if v.vid != "" {
				w.Header().Set("x-amz-version-id", v.vid)
			}
			w.WriteHeader(200)
		case http.MethodHead:
			versions := b.objects[key]
			if len(versions) == 0 {
				w.WriteHeader(404)
				return
			}
			v := versions[0]
			w.Header().Set("Content-Length", strconv.Itoa(len(v.data)))
			w.Header().Set("ETag", `"`+v.etag+`"`)
			w.Header().Set("Last-Modified", v.mtime.Format(http.TimeFormat))
			w.Header().Set("Content-Type", v.contentType)
			if v.vid != "" {
				w.Header().Set("x-amz-version-id", v.vid)
			}
			w.WriteHeader(200)
		case http.MethodGet:
			versions := b.objects[key]
			if len(versions) == 0 {
				xmlError(w, 404, "NoSuchKey", "key not found")
				return
			}
			v := versions[0]
			if vid := q.Get("versionId"); vid != "" {
				found := false
				for _, cand := range versions {
					if cand.vid == vid {
						v = cand
						found = true
						break
					}
				}
				if !found {
					xmlError(w, 404, "NoSuchVersion", "version not found")
					return
				}
			}
			w.Header().Set("ETag", `"`+v.etag+`"`)
			w.Header().Set("Last-Modified", v.mtime.Format(http.TimeFormat))
			w.Header().Set("Content-Type", "application/octet-stream")
			if v.vid != "" {
				w.Header().Set("x-amz-version-id", v.vid)
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(v.data)))
			w.WriteHeader(200)
			_, _ = w.Write(v.data)
		case http.MethodDelete:
			if uid := q.Get("uploadId"); uid != "" {
				delete(b.uploads, uid)
			}
			delete(b.objects, key)
			w.WriteHeader(204)
		default:
			xmlError(w, 405, "MethodNotAllowed", "unsupported")
		}
		_ = start
	})
	log.Printf("spike-s3mock listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, h))
}

const xmlHeader = `<?xml version="1.0" encoding="UTF-8"?>`

func handleService(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		xmlError(w, 405, "MethodNotAllowed", "unsupported")
		return
	}
	names := make([]string, 0, len(st.buckets))
	for n := range st.buckets {
		names = append(names, n)
	}
	sort.Strings(names)
	io.WriteString(w, xmlHeader+`<ListAllMyBucketsResult xmlns="`+s3XMLNS+`"><Owner><ID>spike</ID><DisplayName>spike</DisplayName></Owner><Buckets>`)
	for _, n := range names {
		io.WriteString(w, `<Bucket><Name>`+n+`</Name><CreationDate>2026-01-01T00:00:00.000Z</CreationDate></Bucket>`)
	}
	io.WriteString(w, `</Buckets></ListAllMyBucketsResult>`)
}

func listObjectsV2(w http.ResponseWriter, bname string, b *bucket, q map[string][]string) {
	get := func(k string) string {
		if v, ok := q[k]; ok && len(v) > 0 {
			return v[0]
		}
		return ""
	}
	prefix, delim := get("prefix"), get("delimiter")
	maxKeys := 1000
	if mk := get("max-keys"); mk != "" {
		if n, err := strconv.Atoi(mk); err == nil && n > 0 {
			maxKeys = n
		}
	}
	keys := make([]string, 0, len(b.objects))
	for k := range b.objects {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	encKey := func(k string) string { return k }
	if get("encoding-type") == "url" {
		encKey = func(k string) string { return url.QueryEscape(k) }
	}
	var contents, prefixes []string
	seenPrefix := map[string]bool{}
	truncated := ""
	for _, k := range keys {
		rest := strings.TrimPrefix(k, prefix)
		if delim != "" {
			if idx := strings.Index(rest, delim); idx >= 0 {
				cp := prefix + rest[:idx+len(delim)]
				if !seenPrefix[cp] {
					seenPrefix[cp] = true
					if len(contents)+len(prefixes) >= maxKeys {
						truncated = cp
						break
					}
					prefixes = append(prefixes, cp)
				}
				continue
			}
		}
		if len(contents)+len(prefixes) >= maxKeys {
			truncated = k
			break
		}
		v := b.objects[k][0]
		contents = append(contents, `<Contents><Key>`+encKey(k)+`</Key><LastModified>`+v.mtime.Format("2006-01-02T15:04:05.000Z")+`</LastModified><ETag>&quot;`+v.etag+`&quot;</ETag><Size>`+strconv.Itoa(len(v.data))+`</Size><StorageClass>STANDARD</StorageClass></Contents>`)
	}
	out := xmlHeader + `<ListBucketResult xmlns="` + s3XMLNS + `"><Name>` + bname + `</Name><Prefix>` + encKey(prefix) + `</Prefix><Delimiter>` + encKey(delim) + `</Delimiter><MaxKeys>` + strconv.Itoa(maxKeys) + `</MaxKeys><IsTruncated>` + boolStr(truncated != "") + `</IsTruncated>`
	if len(contents)+len(prefixes) > 0 && truncated != "" {
		out += `<NextContinuationToken>` + newETag([]byte(truncated)) + `</NextContinuationToken><ContinuationToken></ContinuationToken>`
	}
	for _, c := range contents {
		out += c
	}
	if delim != "" {
		out += ``
		for _, p := range prefixes {
			out += `<CommonPrefixes><Prefix>` + encKey(p) + `</Prefix></CommonPrefixes>`
		}
	}
	out += `</ListBucketResult>`
	io.WriteString(w, out)
}

func listVersions(w http.ResponseWriter, bname string, b *bucket, prefix string) {
	type ventry struct {
		key string
		v   objVersion
	}
	var all []ventry
	for k, versions := range b.objects {
		if strings.HasPrefix(k, prefix) {
			for _, v := range versions {
				all = append(all, ventry{k, v})
			}
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].key != all[j].key {
			return all[i].key < all[j].key
		}
		return all[i].v.mtime.After(all[j].v.mtime)
	})
	out := xmlHeader + `<ListVersionsResult xmlns="` + s3XMLNS + `"><Name>` + bname + `</Name><Prefix>` + prefix + `</Prefix><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated>`
	for _, e := range all {
		isLatest := "true"
		if b.objects[e.key][0].vid != e.v.vid {
			isLatest = "false"
		}
		out += `<Version><Key>` + e.key + `</Key><VersionId>` + e.v.vid + `</VersionId><IsLatest>` + isLatest + `</IsLatest><LastModified>` + e.v.mtime.Format("2006-01-02T15:04:05.000Z") + `</LastModified><ETag>&quot;` + e.v.etag + `&quot;</ETag><Size>` + strconv.Itoa(len(e.v.data)) + `</Size><StorageClass>STANDARD</StorageClass></Version>`
	}
	out += `</ListVersionsResult>`
	io.WriteString(w, out)
}

func handleMultipart(w http.ResponseWriter, r *http.Request, b *bucket, key, uid string, q map[string][]string) {
	get := func(k string) string {
		if v, ok := q[k]; ok && len(v) > 0 {
			return v[0]
		}
		return ""
	}
	if r.Method == http.MethodGet && uid != "" {
		// ListParts
		up, ok := b.uploads[uid]
		if !ok {
			xmlError(w, 404, "NoSuchUpload", "upload not found")
			return
		}
		nums := make([]int, 0, len(up.parts))
		for n := range up.parts {
			nums = append(nums, n)
		}
		sort.Ints(nums)
		out := xmlHeader + `<ListPartsResult xmlns="` + s3XMLNS + `"><Bucket>` + bucketName(r) + `</Bucket><Key>` + key + `</Key><UploadId>` + uid + `</UploadId><StorageClass>STANDARD</StorageClass><IsTruncated>false</IsTruncated>`
		for _, n := range nums {
			out += `<Part><PartNumber>` + strconv.Itoa(n) + `</PartNumber><LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>&quot;` + newETag(up.parts[n]) + `&quot;</ETag><Size>` + strconv.Itoa(len(up.parts[n])) + `</Size></Part>`
		}
		out += `</ListPartsResult>`
		io.WriteString(w, out)
		return
	}
	switch r.Method {
	case http.MethodPost:
		if uid == "" {
			// initiate
			vid := newVID()
			b.uploads[vid] = &mpUpload{key: key, parts: map[int][]byte{}}
			io.WriteString(w, xmlHeader+`<InitiateMultipartUploadResult xmlns="`+s3XMLNS+`"><Bucket>`+bucketName(r)+`</Bucket><Key>`+key+`</Key><UploadId>`+vid+`</UploadId></InitiateMultipartUploadResult>`)
			return
		}
		// complete
		up, ok := b.uploads[uid]
		if !ok {
			xmlError(w, 404, "NoSuchUpload", "upload not found")
			return
		}
		nums := make([]int, 0, len(up.parts))
		for n := range up.parts {
			nums = append(nums, n)
		}
		sort.Ints(nums)
		var full []byte
		for _, n := range nums {
			full = append(full, up.parts[n]...)
		}
		etag := fmt.Sprintf("%s-%d", newETag(full), len(nums))
		v := objVersion{data: full, etag: etag, mtime: time.Now().UTC(), vid: "", contentType: r.Header.Get("Content-Type")}
		if b.versioning == "Enabled" {
			v.vid = newVID()
		}
		b.objects[key] = append([]objVersion{v}, b.objects[key]...)
		delete(b.uploads, uid)
		w.Header().Set("x-amz-version-id", v.vid)
		io.WriteString(w, xmlHeader+`<CompleteMultipartUploadResult xmlns="`+s3XMLNS+`"><Location>http://localhost/`+r.URL.Path+`</Location><Bucket>`+bucketName(r)+`</Bucket><Key>`+key+`</Key><ETag>&quot;`+etag+`&quot;</ETag></CompleteMultipartUploadResult>`)
	case http.MethodPut:
		up, ok := b.uploads[uid]
		if !ok {
			xmlError(w, 404, "NoSuchUpload", "upload not found")
			return
		}
		num, err := strconv.Atoi(get("partNumber"))
		if err != nil {
			xmlError(w, 400, "InvalidArgument", "bad partNumber")
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			xmlError(w, 400, "IncompleteBody", err.Error())
			return
		}
		up.parts[num] = data
		w.Header().Set("ETag", `"`+newETag(data)+`"`)
		w.WriteHeader(200)
	case http.MethodDelete:
		delete(b.uploads, uid)
		w.WriteHeader(204)
	default:
		xmlError(w, 405, "MethodNotAllowed", "unsupported")
	}
}

func bucketName(r *http.Request) string {
	p := strings.TrimPrefix(r.URL.Path, "/")
	if i := strings.Index(p, "/"); i >= 0 {
		return p[:i]
	}
	return p
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
