package utils

import (
	"context"
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
	client := github.NewClient(http.DefaultClient)

	release, _, err := client.Repositories.GetReleaseByTag(ctx, safeChainGitHubOwner, safeChainGitHubRepo, originalTag)
	if err != nil {
		log.Printf("Failed to fetch release %q from GitHub: %v", originalTag, err)
		return "", false
	}

	for _, asset := range release.Assets {
		if asset.GetName() != assetName {
			continue
		}
		digest := strings.TrimSpace(asset.GetDigest())
		if digest != "" {
			return digest, true
		}
	}
	log.Printf("Asset %q not found in release %q or missing digest", assetName, originalTag)
	return "", false
}
