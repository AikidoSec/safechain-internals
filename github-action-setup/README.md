# Aikido Device Protection for GitHub Actions

Installs Aikido Device Protection on a Linux job, so the package downloads in every later step of that job are checked. It automates the setup from [Device Protection in GitHub Actions](https://help.aikido.dev/aikido-device-protection/deploying-aikido-endpoint/device-protection-mdm-guides/linux/device-protection-in-github-actions): you add one step and your token, and no longer need to source `/etc/profile.d/aikido-*.sh` in each step.

## Usage

Store your Device Protection token as a repository secret (for example `AIKIDO_TOKEN`) and add the action as the first step of each job:

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: AikidoSec/safechain-internals/github-action-setup@action-v1
        with:
          token: ${{ secrets.AIKIDO_TOKEN }}
      - uses: actions/checkout@v7
      - run: npm ci
      - run: npm test
```

Each job runs on its own machine, so add the step to every job that installs packages. Only steps after it are covered.

### Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `token` | yes | | Device Protection token. Pass it from a secret. |
| `self-check` | no | `false` | When `true`, the step fails unless a known test package is blocked afterwards. |

## How it works

1. Installs the agent with the [Linux installer](https://github.com/AikidoSec/safe-chain/blob/main/install-scripts/install-endpoint-linux.sh) in container mode (the CI flavour: no reboot, nothing persisted).
2. Starts it and waits until setup has finished.
3. Exports the proxy and CA-trust variables the agent writes to `/etc/profile.d/aikido-*.sh` (`HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, `PIP_CERT`, ...) through `GITHUB_ENV`, so every later step gets them.

The installer always installs the latest agent release.

## Supported

- GitHub-hosted Linux runners (`ubuntu-*`, x64 and arm64). Uses passwordless `sudo`.
- `container:` jobs on Debian/Ubuntu or Enterprise Linux 9/10 images (runs as root; the image needs `bash` and `curl`).
