/*
Copyright The Helm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package registry // import "helm.sh/helm/v3/pkg/registry"

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/pkg/errors"

	"helm.sh/helm/v3/internal/version"
	"helm.sh/helm/v3/pkg/chart"
)

// See https://github.com/helm/helm/issues/10166
const registryUnderscoreMessage = `
OCI artifact references (e.g. tags) do not support the plus sign (+). To support
storing semantic versions, Helm adopts the convention of changing plus (+) to
an underscore (_) in chart version tags when pushing to a registry and back to
a plus (+) when pulling from a registry.`

type (
	// Client works with OCI-compliant registries
	Client struct {
		debug bool
		// path to repository config file e.g. ~/.docker/config.json
		credentialsFile string
		out             io.Writer
	}

	// ClientOption allows specifying various settings configurable by the user for overriding the defaults
	// used when creating a new default client
	ClientOption func(*Client)
)

// NewClient returns a new registry client with config
func NewClient(options ...ClientOption) (*Client, error) {
	client := &Client{
		out: ioutil.Discard,
	}
	for _, option := range options {
		option(client)
	}

	// TODO credentialsFile

	return client, nil
}

// ClientOptDebug returns a function that sets the debug setting on client options set
func ClientOptDebug(debug bool) ClientOption {
	return func(client *Client) {
		client.debug = debug
	}
}

// ClientOptWriter returns a function that sets the writer setting on client options set
func ClientOptWriter(out io.Writer) ClientOption {
	return func(client *Client) {
		client.out = out
	}
}

// ClientOptCredentialsFile returns a function that sets the credentialsFile setting on a client options set
func ClientOptCredentialsFile(credentialsFile string) ClientOption {
	return func(client *Client) {
		client.credentialsFile = credentialsFile
	}
}

type (
	// LoginOption allows specifying various settings on login
	LoginOption func(*loginOperation)

	loginOperation struct {
		username string
		password string
		insecure bool
	}
)

// Login logs into a registry
func (c *Client) Login(host string, options ...LoginOption) error {
	// TODO: login
	fmt.Fprintln(c.out, "Login Succeeded")
	return nil
}

// LoginOptBasicAuth returns a function that sets the username/password settings on login
func LoginOptBasicAuth(username string, password string) LoginOption {
	return func(operation *loginOperation) {
		operation.username = username
		operation.password = password
	}
}

// LoginOptInsecure returns a function that sets the insecure setting on login
func LoginOptInsecure(insecure bool) LoginOption {
	return func(operation *loginOperation) {
		operation.insecure = insecure
	}
}

type (
	// LogoutOption allows specifying various settings on logout
	LogoutOption func(*logoutOperation)

	logoutOperation struct{}
)

// Logout logs out of a registry
func (c *Client) Logout(host string, opts ...LogoutOption) error {
	// TODO: logout
	fmt.Fprintf(c.out, "Removing login credentials for %s\n", host)
	return nil
}

type (
	// PullOption allows specifying various settings on pull
	PullOption func(*pullOperation)

	// PullResult is the result returned upon successful pull.
	PullResult struct {
		Manifest *descriptorPullSummary         `json:"manifest"`
		Config   *descriptorPullSummary         `json:"config"`
		Chart    *descriptorPullSummaryWithMeta `json:"chart"`
		Prov     *descriptorPullSummary         `json:"prov"`
		Ref      string                         `json:"ref"`
	}

	descriptorPullSummary struct {
		Data   []byte `json:"-"`
		Digest string `json:"digest"`
		Size   int64  `json:"size"`
	}

	descriptorPullSummaryWithMeta struct {
		descriptorPullSummary
		Meta *chart.Metadata `json:"meta"`
	}

	pullOperation struct {
		withChart         bool
		withProv          bool
		ignoreMissingProv bool
	}
)

func readAll(l v1.Layer) ([]byte, error) {
	rc, err := l.Compressed()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return ioutil.ReadAll(rc)
}

// Pull downloads a chart from a registry
func (c *Client) Pull(ref string, options ...PullOption) (*PullResult, error) {
	parsedRef, err := parseReference(ref)
	if err != nil {
		return nil, err
	}

	operation := &pullOperation{
		withChart: true, // By default, always download the chart layer
	}
	for _, option := range options {
		option(operation)
	}

	kc := authn.NewMultiKeychain(
		// TODO: credentialsFile
		authn.DefaultKeychain,
	)
	img, err := remote.Image(parsedRef,
		remote.WithAuthFromKeychain(kc),
		remote.WithUserAgent(version.GetUserAgent()),
	)
	if err != nil {
		return nil, err
	}
	ls, err := img.Layers()
	if err != nil {
		return nil, err
	}

	result := &PullResult{
		Manifest: &descriptorPullSummary{},
		Config:   &descriptorPullSummary{},
		Chart:    &descriptorPullSummaryWithMeta{},
		Prov:     &descriptorPullSummary{},
		Ref:      parsedRef.String(),
	}

	dig, err := img.Digest()
	if err != nil {
		return nil, err
	}
	result.Manifest.Digest = dig.String()
	result.Manifest.Size, err = img.Size()
	if err != nil {
		return nil, err
	}

	dig, err = img.ConfigName()
	if err != nil {
		return nil, err
	}
	result.Config.Digest = dig.String()
	cfg, err := img.RawConfigFile()
	if err != nil {
		return nil, err
	}
	result.Config.Size = int64(len(cfg))

	for _, l := range ls {
		dig, err := l.Digest()
		if err != nil {
			return nil, err
		}
		mt, err := l.MediaType()
		if err != nil {
			return nil, err
		}
		switch string(mt) {
		case ConfigMediaType:
			result.Config.Digest = dig.String()
			result.Config.Size, err = l.Size()
			if err != nil {
				return nil, err
			}
			result.Config.Data, err = readAll(l)
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal(result.Config.Data, &result.Chart.Meta); err != nil {
				return nil, err
			}
		case LegacyChartLayerMediaType:
			fmt.Fprintf(c.out, "Warning: chart media type %s is deprecated\n", LegacyChartLayerMediaType)
			fallthrough
		case ChartLayerMediaType:
			result.Chart.Digest = dig.String()
			result.Chart.Size, err = l.Size()
			if err != nil {
				return nil, err
			}
			result.Chart.Data, err = readAll(l)
			if err != nil {
				return nil, err
			}
		case ProvLayerMediaType:
			result.Prov.Digest = dig.String()
			result.Prov.Size, err = l.Size()
			if err != nil {
				return nil, err
			}
			result.Prov.Data, err = readAll(l)
			if err != nil {
				return nil, err
			}
		}
	}
	if operation.withChart && result.Chart.Digest == "" {
		return nil, fmt.Errorf("manifest does not contain a layer with mediatype %s",
			ChartLayerMediaType)
	}
	if operation.withProv && result.Prov.Digest == "" && !operation.ignoreMissingProv {
		return nil, fmt.Errorf("manifest does not contain a layer with mediatype %s",
			ProvLayerMediaType)
	}

	fmt.Fprintf(c.out, "Pulled: %s\n", result.Ref)
	fmt.Fprintf(c.out, "Digest: %s\n", result.Manifest.Digest)

	if strings.Contains(result.Ref, "_") {
		fmt.Fprintf(c.out, "%s contains an underscore.\n", result.Ref)
		fmt.Fprint(c.out, registryUnderscoreMessage+"\n")
	}

	return result, nil
}

// PullOptWithChart returns a function that sets the withChart setting on pull
func PullOptWithChart(withChart bool) PullOption {
	return func(operation *pullOperation) {
		operation.withChart = withChart
	}
}

// PullOptWithProv returns a function that sets the withProv setting on pull
func PullOptWithProv(withProv bool) PullOption {
	return func(operation *pullOperation) {
		operation.withProv = withProv
	}
}

// PullOptIgnoreMissingProv returns a function that sets the ignoreMissingProv setting on pull
func PullOptIgnoreMissingProv(ignoreMissingProv bool) PullOption {
	return func(operation *pullOperation) {
		operation.ignoreMissingProv = ignoreMissingProv
	}
}

type (
	// PushOption allows specifying various settings on push
	PushOption func(*pushOperation)

	// PushResult is the result returned upon successful push.
	PushResult struct {
		Manifest *descriptorPushSummary         `json:"manifest"`
		Config   *descriptorPushSummary         `json:"config"`
		Chart    *descriptorPushSummaryWithMeta `json:"chart"`
		Prov     *descriptorPushSummary         `json:"prov"`
		Ref      string                         `json:"ref"`
	}

	descriptorPushSummary struct {
		Digest string `json:"digest"`
		Size   int64  `json:"size"`
	}

	descriptorPushSummaryWithMeta struct {
		descriptorPushSummary
		Meta *chart.Metadata `json:"meta"`
	}

	pushOperation struct {
		provData   []byte
		strictMode bool
	}
)

// Push uploads a chart to a registry.
func (c *Client) Push(data []byte, ref string, options ...PushOption) (*PushResult, error) {
	parsedRef, err := parseReference(ref)
	if err != nil {
		return nil, err
	}

	operation := &pushOperation{
		strictMode: true, // By default, enable strict mode
	}
	for _, option := range options {
		option(operation)
	}
	meta, err := extractChartMeta(data)
	if err != nil {
		return nil, err
	}
	if operation.strictMode {
		if !strings.HasSuffix(ref, fmt.Sprintf("/%s:%s", meta.Name, meta.Version)) {
			return nil, errors.New(
				"strict mode enabled, ref basename and tag must match the chart name and version")
		}
	}

	result := &PushResult{
		Manifest: &descriptorPushSummary{},
		Config:   &descriptorPushSummary{},
		Chart: &descriptorPushSummaryWithMeta{
			Meta: meta,
		},
		Prov: &descriptorPushSummary{}, // prevent nil references
		Ref:  parsedRef.String(),
	}

	chartLayer := static.NewLayer(data, types.MediaType(ChartLayerMediaType))
	layers := []v1.Layer{chartLayer}

	dig, err := chartLayer.Digest()
	if err != nil {
		return nil, err
	}
	result.Chart.Digest = dig.String()
	result.Chart.Size = int64(len(data))
	if operation.provData != nil {
		provLayer := static.NewLayer(operation.provData, types.MediaType(ProvLayerMediaType))
		dig, err := provLayer.Digest()
		if err != nil {
			return nil, err
		}
		result.Prov = &descriptorPushSummary{
			Digest: dig.String(),
			Size:   int64(len(operation.provData)),
		}
		layers = append(layers, provLayer)
	}

	img, err := mutate.AppendLayers(empty.Image, layers...)
	if err != nil {
		return nil, err
	}
	// mutate.MediaType(img) // TODO: set image media type correctly.
	// TODO: set config contents to the meta bytes
	/*
		configData, err := json.Marshal(meta)
		if err != nil {
			return nil, err
		}*/

	if err := remote.Write(parsedRef, img); err != nil {
		return nil, err
	}

	fmt.Fprintf(c.out, "Pushed: %s\n", result.Ref)
	fmt.Fprintf(c.out, "Digest: %s\n", result.Manifest.Digest)
	if strings.Contains(parsedRef.String(), "_") {
		fmt.Fprintf(c.out, "%s contains an underscore.\n", result.Ref)
		fmt.Fprint(c.out, registryUnderscoreMessage+"\n")
	}

	return result, err
}

// PushOptProvData returns a function that sets the prov bytes setting on push
func PushOptProvData(provData []byte) PushOption {
	return func(operation *pushOperation) {
		operation.provData = provData
	}
}

// PushOptStrictMode returns a function that sets the strictMode setting on push
func PushOptStrictMode(strictMode bool) PushOption {
	return func(operation *pushOperation) {
		operation.strictMode = strictMode
	}
}

// Tags provides a sorted list all semver compliant tags for a given repository
func (c *Client) Tags(ref string) ([]string, error) {
	repo, err := name.NewRepository(ref)
	if err != nil {
		return nil, err
	}

	kc := authn.NewMultiKeychain(
		// TODO: credentialsFile
		authn.DefaultKeychain,
	)
	registryTags, err := remote.List(repo,
		remote.WithAuthFromKeychain(kc),
		remote.WithUserAgent(version.GetUserAgent()),
	)
	if err != nil {
		return nil, err
	}

	var tagVersions []*semver.Version
	for _, tag := range registryTags {
		// Change underscore (_) back to plus (+) for Helm
		// See https://github.com/helm/helm/issues/10166
		tagVersion, err := semver.StrictNewVersion(strings.ReplaceAll(tag, "_", "+"))
		if err == nil {
			tagVersions = append(tagVersions, tagVersion)
		}
	}

	// Sort the collection
	sort.Sort(sort.Reverse(semver.Collection(tagVersions)))

	tags := make([]string, len(tagVersions))
	for iTv, tv := range tagVersions {
		tags[iTv] = tv.String()
	}
	return tags, nil
}
