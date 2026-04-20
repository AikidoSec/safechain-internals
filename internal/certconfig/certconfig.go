package certconfig

import (
	"context"
	"log"
)

type Configurator interface {
	Name() string
	Install(context.Context) error
	Uninstall(context.Context) error
}

type CertConfig struct {
	configurators []Configurator
}

func New() *CertConfig {
	return &CertConfig{
		configurators: []Configurator{
			newNodeConfigurator(),
			newPipConfigurator(),
			newFirefoxConfigurator(),
			newMavenConfigurator(),
			newHomebrewConfigurator(),
			newGradleConfigurator(),
			newGitConfigurator(),
		},
	}
}

func Install(ctx context.Context) error {
	return New().Install(ctx)
}

func Teardown(ctx context.Context) error {
	return New().Teardown(ctx)
}

func (c *CertConfig) Install(ctx context.Context) error {
	for _, cfg := range c.configurators {
		log.Printf("Configuring certificate trust for %s", cfg.Name())
		if err := cfg.Install(ctx); err != nil {
			log.Printf("Warning: %s trust configuration failed: %v", cfg.Name(), err)
		}
	}
	return nil
}

func (c *CertConfig) Teardown(ctx context.Context) error {
	for _, cfg := range c.configurators {
		log.Printf("Removing certificate trust configuration for %s", cfg.Name())
		if err := cfg.Uninstall(ctx); err != nil {
			log.Printf("Warning: %s trust cleanup failed: %v", cfg.Name(), err)
		}
	}
	return nil
}
