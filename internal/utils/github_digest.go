package utils

import (
	"context"
	"log"
	"strings"

	"github.com/google/go-github/v82/github"
)

const (
	safeChainGitHubOwner = "AikidoSec"
	safeChainGitHubRepo  = "safe-chain"
)

func lookupSafeChainReleaseAssetDigest(ctx context.Context, releaseTag string, assetName string) (string, bool) {
	releaseTag = strings.TrimSpace(releaseTag)
	assetName = strings.TrimSpace(assetName)
	if releaseTag == "" || assetName == "" {
		return "", false
	}
	if !strings.HasPrefix(releaseTag, "v") {
		releaseTag = "v" + releaseTag
	}

	client := github.NewClient(httpClient)

	release, _, err := client.Repositories.GetReleaseByTag(ctx, safeChainGitHubOwner, safeChainGitHubRepo, releaseTag)
	if err != nil {
		log.Printf("Unable to find digest for asset %q in release %q (failed to fetch GitHub release metadata): %v", assetName, releaseTag, err)
		return "", false
	}

	for _, asset := range release.Assets {
		if asset.GetName() == assetName {
			digest := strings.TrimSpace(asset.GetDigest())
			if digest == "" {
				log.Printf("Unable to find digest for asset %q in release %q (digest missing in release metadata)", assetName, releaseTag)
				return "", false
			}
			return digest, true
		}
	}

	log.Printf("Unable to find digest for asset %q in release %q (asset not present in release)", assetName, releaseTag)
	return "", false
}
