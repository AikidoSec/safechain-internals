package utils

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/google/go-github/v82/github"
)

const (
	safeChainGitHubOwner = "AikidoSec"
	safeChainGitHubRepo  = "safe-chain"
)

func lookupSafeChainReleaseAssetDigest(ctx context.Context, releaseTag string, assetName string) (string, bool) {
	originalTag := strings.TrimSpace(releaseTag)
	assetName = strings.TrimSpace(assetName)
	if originalTag == "" || assetName == "" {
		return "", false
	}

	// tags might have a "v" prefix, but GitHub API requires the tag without the "v"
	normalizedTag := strings.TrimPrefix(originalTag, "v")

	client := github.NewClient(http.DefaultClient)

	release, _, err := client.Repositories.GetReleaseByTag(ctx, safeChainGitHubOwner, safeChainGitHubRepo, normalizedTag)
	if err != nil {
		var apiErr *github.ErrorResponse
		if errors.As(err, &apiErr) && apiErr.Response != nil && apiErr.Response.StatusCode == http.StatusNotFound {
			log.Printf("Unable to find digest for asset %q in release %q (release tag %q not found)", assetName, originalTag, normalizedTag)
			return "", false
		}
		log.Printf("Unable to find digest for asset %q in release %q (failed to fetch GitHub release metadata for tag %q): %v", assetName, originalTag, normalizedTag, err)
		return "", false
	}

	for _, asset := range release.Assets {
		if asset.GetName() != assetName {
			continue
		}
		digest := strings.TrimSpace(asset.GetDigest())
		if digest == "" {
			log.Printf("Unable to find digest for asset %q in release %q (digest missing in release metadata for tag %q)", assetName, originalTag, normalizedTag)
			return "", false
		}
		return digest, true
	}

	log.Printf("Unable to find digest for asset %q in release %q (asset not present in release tag %q)", assetName, originalTag, normalizedTag)
	return "", false
}
