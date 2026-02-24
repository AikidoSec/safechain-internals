package sbom

func (r *Registry) List() []string {
	names := make([]string, 0, len(r.managers))
	for name := range r.managers {
		names = append(names, name)
	}
	return names
}
